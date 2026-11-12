package burp.curl;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.List;
import org.junit.jupiter.api.Test;

/** Command selection and option walking of {@link Curl#parse}. */
class CurlParseTest {
    private static List<BuiltRequest> build(String text) throws Exception {
        return Curl.parse(text).build(FileAccess.DENY);
    }

    private static String raw(BuiltRequest r) {
        return new String(r.raw(), StandardCharsets.ISO_8859_1);
    }

    private static boolean warned(ParsedCurl p, Warning.Severity sev, String needle) {
        return p.warnings().stream().anyMatch(w -> w.severity() == sev && w.message().contains(needle));
    }

    // ---- command selection ----

    @Test
    void skipsAssignmentsAndWrappers() throws Exception {
        for (String c : new String[] {"FOO=1 BAR=2 curl http://h/x", "sudo /usr/bin/curl http://h/x",
                "env X=1 curl.exe http://h/x", "time nohup CURL http://h/x",
                "$ curl http://h/x"}) {
            List<BuiltRequest> r = build(c);
            assertEquals(1, r.size(), c);
            assertEquals("http://h/x", r.get(0).url(), c);
        }
    }

    @Test
    void ignoresCommandsWithoutCurlAndParsesEveryCurl() throws Exception {
        List<BuiltRequest> r = build("echo hi; curl http://h/1 && curl -X PUT http://h/2\ncurl http://h/3");
        assertEquals(List.of("http://h/1", "http://h/2", "http://h/3"), r.stream().map(BuiltRequest::url).toList());
        assertEquals("PUT", r.get(1).method());
    }

    @Test
    void bareArgumentsWithoutTheCurlWord() throws Exception {
        assertEquals("POST", build("-X POST http://h/x").get(0).method());
        assertEquals("http://h/x", build("http://h/x -H 'A: b'").get(0).url());
        assertEquals("http://example.com/x", build("example.com/x").get(0).url());
        assertEquals("http://localhost:3000/", build("localhost:3000").get(0).url());
        assertTrue(Curl.parse("-X POST http://h/x").warnings().stream()
                .anyMatch(w -> w.severity() == Warning.Severity.NOTE));
    }

    @Test
    void nothingUsableIsAnError() {
        CurlParseException e = assertThrows(CurlParseException.class, () -> Curl.parse("echo hello world"));
        assertTrue(e.getMessage().toLowerCase().contains("curl"));
        assertThrows(CurlParseException.class, () -> Curl.parse(""));
        assertThrows(CurlParseException.class, () -> Curl.parse("   \n"));
        assertThrows(CurlParseException.class, () -> Curl.parse(null));
        CurlParseException u = assertThrows(CurlParseException.class, () -> Curl.parse("curl -X POST -s"));
        assertTrue(u.getMessage().contains("URL"));
        assertThrows(CurlParseException.class, () -> Curl.parse("curl"));
    }

    @Test
    void windowsPathOfCurlExe() throws Exception {
        String cmd = "C:\\tools\\curl.exe ^\"http://h/x^\" ^\n  -X PUT";
        assertEquals("PUT", build(cmd).get(0).method());
    }

    @Test
    void cmdDialect() throws Exception {
        String cmd = "curl ^\"http://h/x^\" ^\n  -H ^\"Accept: a/b^\" ^\n  --data-raw ^\"^^{\\^\"a\\^\":1}^\"";
        BuiltRequest r = build(cmd).get(0);
        assertTrue(raw(r).startsWith("POST /x HTTP/1.1\r\n"), raw(r));
        assertTrue(raw(r).contains("Accept: a/b\r\n"));
    }

    // ---- option walking ----

    @Test
    void attachedAndClusteredShortOptions() throws Exception {
        BuiltRequest r = build("curl -XPUT -sSLk -Hx:y -dabc -m5 -o out http://h/x").get(0);
        assertEquals("PUT", r.method());
        String w = raw(r);
        assertTrue(w.contains("\r\nx:y\r\n"), w);
        assertTrue(w.endsWith("\r\n\r\nabc"), w);
        assertEquals(1, build("curl -sSLk http://h/x").size());
        assertEquals("HEAD", build("curl -sI http://h/x").get(0).method());
        assertEquals("POST", build("curl -sd a http://h/x").get(0).method());
    }

    @Test
    void longOptionForms() throws Exception {
        assertEquals("PUT", build("curl --request PUT http://h/x").get(0).method());
        assertEquals("PUT", build("curl --request=PUT http://h/x").get(0).method());
        assertEquals("http://h/x", build("curl --url http://h/x").get(0).url());
        assertEquals("POST", build("curl --dat a http://h/x").get(0).method());
        assertTrue(raw(build("curl --compr http://h/x").get(0)).contains("Accept-Encoding: deflate, gzip"));
        assertFalse(raw(build("curl --compressed --no-compressed http://h/x").get(0)).contains("Accept-Encoding"));
    }

    @Test
    void doubleDashEndsOptions() throws Exception {
        List<BuiltRequest> r = build("curl -X POST -- -weird http://h/x");
        assertEquals(2, r.size());
    }

    @Test
    void missingArgumentIsAnError() {
        assertThrows(CurlParseException.class, () -> Curl.parse("curl http://h/x -H"));
        assertThrows(CurlParseException.class, () -> Curl.parse("curl http://h/x --request"));
        assertThrows(CurlParseException.class, () -> Curl.parse("curl http://h/x -sX"));
    }

    @Test
    void unknownOptionWarnsAndTakesNoArgument() throws Exception {
        ParsedCurl p = Curl.parse("curl --frobnicate http://h/x");
        assertTrue(warned(p, Warning.Severity.LOSSY, "--frobnicate"));
        assertEquals(1, p.build(FileAccess.DENY).size());
        assertTrue(warned(Curl.parse("curl -!9 http://h/x"), Warning.Severity.LOSSY, "-!"));
    }

    @Test
    void everyOptionTakesItsArgumentAndNeverBecomesAUrl() throws Exception {
        int checked = 0;
        for (OptionSpec s : CurlOptionTable.get().all()) {
            if (s.longName().equals("url") || s.longName().equals("next")) {
                continue;
            }
            String arg = s.takesArg() ? " 'v-" + s.longName() + "'" : "";
            if (s.longName().equals("variable")) {
                arg = " 'n=v'";
            }
            List<BuiltRequest> r = Curl.parse("curl --" + s.longName() + arg + " http://h/x").build(FileAccess.DENY);
            assertEquals(1, r.size(), "--" + s.longName());
            if (s.shortName() != 0) {
                String cmd = "curl -" + s.shortName() + (s.takesArg() ? "v" : "") + " http://h/x";
                assertEquals(1, Curl.parse(cmd).build(FileAccess.DENY).size(), cmd);
            }
            checked++;
        }
        assertTrue(checked > 250);
    }

    // ---- warnings ----

    @Test
    void groupWarnings() throws Exception {
        ParsedCurl b = Curl.parse("curl --digest -u a:b --resolve h:80:1.2.3.4 http://h/x");
        assertTrue(warned(b, Warning.Severity.LOSSY, "--digest"));
        assertTrue(warned(b, Warning.Severity.LOSSY, "--resolve"));
        assertTrue(b.warnings().stream().allMatch(w -> w.message().contains("differ")));
        // groups C and D are silent
        assertEquals(List.of(), Curl.parse("curl -skL --max-time 5 -o /dev/null -v --ftp-pasv --socks5 p:1 http://h/x")
                .warnings());
        for (String o : new String[] {"-F a=b", "--form-string a=b", "--form-escape", "-T f", "--url-query a=b",
                "--variable a=b", "--expand-data x", "-z 1", "--tr-encoding", "--request-target /", "--proto-default http",
                "--crlf", "-b jar.txt", "-H @hdrs.txt", "--disallow-username-in-url"}) {
            ParsedCurl p = Curl.parse("curl " + o + " http://h/x");
            assertFalse(warned(p, Warning.Severity.LOSSY, "not supported yet"), o);
            assertEquals(1, p.build(FileAccess.DENY).size(), o);
        }
    }

    @Test
    void tokenizerWarningsAreForwarded() throws Exception {
        ParsedCurl p = Curl.parse("curl http://h/$HOST");
        assertFalse(p.warnings().isEmpty());
    }
}
