package burp.curl;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * Behaviour of the wave-3 options that the differential corpus cannot pin (it has no fixtures for them, or the
 * real curl refuses the combination). Expected bytes were measured with the real curl 8.7.1 where noted.
 */
class CurlExtendedBuilderTest {
    private static FileAccess files(Map<String, String> m) {
        return p -> {
            String c = m.get(p);
            if (c == null) {
                throw new IOException("no such file " + p);
            }
            return c.getBytes(StandardCharsets.ISO_8859_1);
        };
    }

    private static BuiltRequest one(String cmd, FileAccess f) throws Exception {
        List<BuiltRequest> r = Curl.parse(cmd).build(f);
        assertEquals(1, r.size(), cmd);
        return r.get(0);
    }

    private static String raw(BuiltRequest b) {
        return new String(b.raw(), StandardCharsets.ISO_8859_1);
    }

    private static boolean lossy(BuiltRequest b, String needle) {
        return b.warnings().stream().anyMatch(w -> w.severity() == Warning.Severity.LOSSY
                && w.message().contains(needle));
    }

    @Test
    void unreadableFilesBecomePlaceholdersWithAWarning() throws Exception {
        for (String c : new String[] {"curl -T nofile http://h/x", "curl -F f=@nofile http://h/x",
                "curl -F f='<nofile' http://h/x", "curl --url-query @nofile http://h/x",
                "curl -d @nofile http://h/x", "curl -b nofile http://h/x", "curl -H @nofile http://h/x",
                "curl --variable v@nofile --expand-data '{{v}}' http://h/x"}) {
            BuiltRequest b = one(c, FileAccess.DENY);
            assertTrue(raw(b).contains("<<FILE: nofile>>") || raw(b).contains("<<FILE:%20nofile>>")
                    || raw(b).contains("%3C%3CFILE%3A+nofile%3E%3E"), c + "\n" + raw(b));
            assertTrue(lossy(b, "nofile"), c + b.warnings());
        }
    }

    @Test
    void everyFileReadingOptionIsListedInFileRefs() throws Exception {
        ParsedCurl p = Curl.parse("curl -T up.txt -F 'a=@f1;headers=@h1' -F 'b=<f2' -F 'c=@f3,f4' --url-query @q1 "
                + "--url-query n@q2 -b jar.txt -H @hdrs.txt --variable v@var.txt -d @d1 --data-urlencode e@d2 "
                + "http://h/x/ --next -T - http://h/y < stdin.txt");
        List<String> refs = p.fileRefs();
        for (String f : new String[] {"up.txt", "f1", "h1", "f2", "f3", "f4", "q1", "q2", "jar.txt", "hdrs.txt",
                "var.txt", "d1", "d2", "stdin.txt"}) {
            assertTrue(refs.contains(f), f + " in " + refs);
        }
    }

    @Test
    void refusedCombinationsKeepTheMostUsefulRequest() throws Exception {
        FileAccess f = files(Map.of("a.txt", "hello\n"));
        BuiltRequest b = one("curl -d x=1 -F a=b http://h/x", f);
        assertEquals("POST", b.method());
        assertTrue(raw(b).contains("multipart/form-data"));
        assertTrue(lossy(b, "refuses"), b.warnings().toString());

        b = one("curl -T a.txt -F a=b http://h/x", f);
        assertTrue(raw(b).contains("multipart/form-data"));
        assertTrue(lossy(b, "refuses"));

        b = one("curl -T a.txt -d x=1 http://h/x", f);
        assertEquals("PUT", b.method());
        assertTrue(lossy(b, "refuses"));

        b = one("curl -I -T a.txt http://h/x", f);
        assertEquals("HEAD", b.method());
        assertTrue(lossy(b, "refuses"));

        b = one("curl -I -F a=b http://h/x", f);
        assertEquals("HEAD", b.method());
        assertFalse(raw(b).contains("multipart"));
        assertTrue(lossy(b, "refuses"));
    }

    @Test
    void crlfConvertsEveryLfAndLosesTheTailAfterTheLastLf() throws Exception {
        // measured: --data-binary $'a\nb\nc' sends the chunk "a\r\nb\r\n"
        BuiltRequest b = one("curl --crlf --data-binary 'a\nb\nc' http://h/x", FileAccess.DENY);
        assertTrue(raw(b).endsWith("\r\n\r\n6\r\na\r\nb\r\n\r\n0\r\n\r\n"), raw(b));
        assertTrue(raw(b).contains("Transfer-Encoding: chunked\r\nContent-Type"), raw(b));
        assertFalse(raw(b).contains("Content-Length"));
        // measured: a CR in front of an LF is not recognised
        b = one("curl --crlf --data-binary $'a\\r\\nb\\n' http://h/x", FileAccess.DENY);
        assertTrue(raw(b).contains("\r\n\r\n"));
    }

    @Test
    void largeBodiesAskForExpect100Continue() throws Exception {
        String big = "a".repeat(1_048_577);
        FileAccess f = files(Map.of("big", big));
        // measured on 8.7.1: Content-Length, Content-Type, Expect for data; Content-Length, Expect for uploads
        String d = raw(one("curl -d @big http://h/x", f));
        assertTrue(d.contains("Content-Length: 1048577\r\nContent-Type: application/x-www-form-urlencoded\r\n"
                + "Expect: 100-continue\r\n\r\n"), d.substring(0, 300));
        String u = raw(one("curl -T big http://h/x", f));
        assertTrue(u.contains("Content-Length: 1048577\r\nExpect: 100-continue\r\n\r\n"), u.substring(0, 300));
        String small = raw(one("curl -d @big http://h/x", files(Map.of("big", "a".repeat(1_048_576)))));
        assertFalse(small.contains("Expect"));
        String http10 = raw(one("curl --http1.0 -T big http://h/x", f));
        assertFalse(http10.contains("Expect"));
    }

    @Test
    void stdinUploadsAreChunkedInPiecesOf65524() throws Exception {
        String body = "z".repeat(70_000);
        BuiltRequest b = one("curl -T - http://h/x <<'EOF'\n" + body + "\nEOF", FileAccess.DENY);
        String r = raw(b);
        assertTrue(r.contains("Transfer-Encoding: chunked\r\nExpect: 100-continue\r\n\r\nfff4\r\n"), r.substring(0, 250));
        assertTrue(r.endsWith("\r\n0\r\n\r\n"));
    }

    @Test
    void customTransferEncodingChunkedChunksAnyBody() throws Exception {
        // measured on 8.7.1
        assertEquals("GET /x HTTP/1.1\r\nHost: h\r\nUser-Agent: curl/8.7.1\r\nAccept: */*\r\n"
                        + "Transfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
                raw(one("curl -H 'Transfer-Encoding: chunked' http://h/x", FileAccess.DENY)));
        assertTrue(raw(one("curl -H 'Transfer-Encoding: gzip' -d abc http://h/x", FileAccess.DENY))
                .contains("Transfer-Encoding: gzip\r\nContent-Length: 3\r\n"));
    }

    @Test
    void variablesNeedNoShellAndFollowCurlsRules() throws Exception {
        FileAccess f = files(Map.of("v.txt", "  file value \n"));
        String body = new String(one("curl --variable 'a=1' --variable 'b@v.txt' --expand-data "
                + "'{{a}}|{{b:trim}}|{{b:trim:url}}|{{b:b64}}|{{none}}|\\{{a}}' http://h/x", f).raw(),
                StandardCharsets.ISO_8859_1);
        assertTrue(body.endsWith("\r\n\r\n1|file value|file%20value|ICBmaWxlIHZhbHVlIAo=||{{a}}"), body);
    }

    @Test
    void brokenVariableExpressionsKeepTheArgumentAndWarn() throws Exception {
        BuiltRequest b = one("curl --variable v=1 --expand-data '{{ v }}' http://h/x", FileAccess.DENY);
        assertTrue(raw(b).endsWith("\r\n\r\n{{ v }}"), raw(b));
        assertTrue(lossy(b, "refuses"));
        b = one("curl --variable v=1 --expand-data '{{v:nope}}' http://h/x", FileAccess.DENY);
        assertTrue(raw(b).endsWith("\r\n\r\n{{v:nope}}"));
        assertTrue(lossy(b, "unknown variable function"));
        b = one("curl --variable v=1 --expand-data '[{{v' http://h/x", FileAccess.DENY);
        assertTrue(raw(b).endsWith("\r\n\r\n[{{v"));
    }

    @Test
    void environmentImportsUseTheDefaultOrWarn() throws Exception {
        BuiltRequest b = one("curl --variable '%SOME_ENV=dflt' --expand-data '{{SOME_ENV}}' http://h/x",
                FileAccess.DENY);
        assertTrue(raw(b).endsWith("\r\n\r\ndflt"));
        assertTrue(lossy(b, "SOME_ENV"));
        b = one("curl --variable '%SOME_ENV' --expand-data '[{{SOME_ENV}}]' http://h/x", FileAccess.DENY);
        assertTrue(raw(b).endsWith("\r\n\r\n[]"));
        assertTrue(lossy(b, "SOME_ENV"));
        b = one("curl --variable '%SOME_ENV@d.txt' --expand-data '{{SOME_ENV}}' http://h/x",
                files(Map.of("d.txt", "from file")));
        assertTrue(raw(b).endsWith("\r\n\r\nfrom file"));
    }

    @Test
    void timeConditionWithAFileNameCannotBeResolved() throws Exception {
        BuiltRequest b = one("curl -z some-file.txt http://h/x", FileAccess.DENY);
        assertFalse(raw(b).contains("If-Modified-Since"));
        assertTrue(lossy(b, "-z"));
    }

    @Test
    void protocolVersionOptionsAreLeftToBurp() throws Exception {
        for (String o : new String[] {"--http2", "--http2-prior-knowledge", "--http3", "--http3-only", "--http1.1"}) {
            ParsedCurl p = Curl.parse("curl " + o + " http://h/x");
            assertTrue(p.warnings().stream().anyMatch(w -> w.severity() == Warning.Severity.NOTE
                    && w.message().contains("left to Burp")), o + p.warnings());
            assertTrue(raw(p.build(FileAccess.DENY).get(0)).startsWith("GET /x HTTP/1.1\r\n"), o);
        }
    }

    @Test
    void uploadPairsOneFilePerUrl() throws Exception {
        FileAccess f = files(Map.of("a", "AAA", "b", "BBB"));
        List<BuiltRequest> r = Curl.parse("curl -T a -T b http://h/1/ http://h/2 http://h/3").build(f);
        assertEquals(3, r.size());
        assertTrue(raw(r.get(0)).startsWith("PUT /1/a HTTP/1.1"));
        assertTrue(raw(r.get(1)).startsWith("PUT /2 HTTP/1.1") && raw(r.get(1)).endsWith("BBB"));
        assertTrue(raw(r.get(2)).startsWith("GET /3 HTTP/1.1"));
    }
}
