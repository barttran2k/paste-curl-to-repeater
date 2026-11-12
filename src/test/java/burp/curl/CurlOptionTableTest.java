package burp.curl;

import static org.junit.jupiter.api.Assertions.*;

import burp.curl.CurlOptionTable.LongMatch;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.jupiter.api.Test;

class CurlOptionTableTest {
    private static final CurlOptionTable T = CurlOptionTable.get();

    private static List<String> resource(String name) throws IOException {
        try (InputStream in = CurlOptionTableTest.class.getResourceAsStream("/" + name)) {
            assertNotNull(in, name);
            return List.of(new String(in.readAllBytes(), StandardCharsets.UTF_8).split("\n"));
        }
    }

    private static OptionSpec spec(String n) {
        return T.byLong(n).orElseThrow(() -> new AssertionError("missing " + n));
    }

    private static void check(String name, char sh, ArgKind kind, boolean neg, Handling h) {
        assertEquals(new OptionSpec(name, sh, kind, neg, h), spec(name));
        if (sh != 0) {
            assertSame(spec(name), T.byShort(sh).orElseThrow());
        }
    }

    @Test
    void helpAllOptionsResolveWithMatchingArity() throws IOException {
        Pattern p = Pattern.compile("^ (?:-(\\S), |    )--(\\S+)( [<\\[])?");
        int n = 0;
        for (String line : resource("curl-help-all-8.7.1.txt").subList(1, 259)) {
            if (line.isBlank()) {
                continue;
            }
            Matcher m = p.matcher(line);
            assertTrue(m.find(), line);
            n++;
            LongMatch lm = T.resolveLong(m.group(2)).orElseThrow(() -> new AssertionError(line));
            assertEquals(m.group(3) != null, lm.spec().takesArg(), line);
            if (m.group(1) != null) {
                OptionSpec byShort = T.byShort(m.group(1).charAt(0)).orElseThrow();
                if (lm.spec() != byShort) {
                    // legacy alias: curl master keeps "include" without a letter; -i belongs to "show-headers"
                    assertEquals("include", lm.spec().longName(), line);
                    assertEquals("show-headers", byShort.longName(), line);
                }
            }
        }
        assertTrue(n > 250, "parsed help lines: " + n);
    }

    @Test
    void masterOptionsAllResolveAndTableIsUnique() throws IOException {
        List<String> names = resource("curl-master-options.txt");
        assertTrue(names.size() >= 287);
        for (String n : names) {
            assertSame(spec(n), T.resolveLong(n).orElseThrow().spec(), n);
        }
        assertTrue(T.all().size() >= 287);
        Set<String> longs = new HashSet<>();
        Set<Character> shorts = new HashSet<>();
        for (OptionSpec s : T.all()) {
            assertTrue(longs.add(s.longName()), "dup " + s.longName());
            if (s.shortName() != 0) {
                assertTrue(shorts.add(s.shortName()), "dup short " + s.shortName());
            }
        }
    }

    @Test
    void spotChecks() {
        check("data-raw", (char) 0, ArgKind.STRING, false, Handling.A);
        check("data", 'd', ArgKind.STRING, false, Handling.A);
        check("header", 'H', ArgKind.STRING, false, Handling.A);
        check("request", 'X', ArgKind.STRING, false, Handling.A);
        check("cookie", 'b', ArgKind.STRING, false, Handling.A);
        check("form", 'F', ArgKind.STRING, false, Handling.A);
        check("user", 'u', ArgKind.STRING, false, Handling.A);
        check("get", 'G', ArgKind.BOOL, true, Handling.A);
        check("head", 'I', ArgKind.BOOL, true, Handling.A);
        check("next", ':', ArgKind.NONE, false, Handling.A);
        check("json", (char) 0, ArgKind.STRING, false, Handling.A);
        check("url-query", (char) 0, ArgKind.STRING, false, Handling.A);
        check("variable", (char) 0, ArgKind.STRING, false, Handling.A);
        check("http1.0", '0', ArgKind.NONE, false, Handling.A);
        check("compressed", (char) 0, ArgKind.BOOL, true, Handling.A);
        check("path-as-is", (char) 0, ArgKind.BOOL, true, Handling.A);
        check("request-target", (char) 0, ArgKind.STRING, false, Handling.A);
        check("oauth2-bearer", (char) 0, ArgKind.STRING, false, Handling.A);
        check("proxy", 'x', ArgKind.STRING, false, Handling.B);
        check("resolve", (char) 0, ArgKind.STRING, false, Handling.B);
        check("output", 'o', ArgKind.FILE, false, Handling.C);
        check("max-time", 'm', ArgKind.NUM, false, Handling.C);
        check("retry", (char) 0, ArgKind.NUM, false, Handling.C);
        check("ftp-port", 'P', ArgKind.STRING, false, Handling.D);
    }

    @Test
    void groupA() {
        String a = "url url-query request-target path-as-is proto-default globoff disallow-username-in-url "
                + "request head get upload-file header user-agent referer cookie range time-cond compressed "
                + "tr-encoding user basic oauth2-bearer data data-ascii data-raw data-binary data-urlencode "
                + "json form form-string form-escape crlf http1.0 http1.1 http2 http2-prior-knowledge http3 "
                + "http3-only next variable";
        List<String> names = List.of(a.split(" "));
        for (String n : names) {
            assertEquals(Handling.A, spec(n).handling(), n);
        }
        List<String> actual = new ArrayList<>();
        T.all().stream().filter(s -> s.handling() == Handling.A).forEach(s -> actual.add(s.longName()));
        assertEquals(new HashSet<>(names), new HashSet<>(actual));
    }

    @Test
    void groupsBCDSamples() {
        for (String n : List.of("digest", "ntlm", "negotiate", "aws-sigv4", "netrc", "config", "continue-at",
                "connect-to", "unix-socket", "cert", "key", "upload-flags", "haproxy-protocol")) {
            assertEquals(Handling.B, spec(n).handling(), n);
        }
        for (String n : List.of("insecure", "cacert", "verbose", "silent", "location", "dump-header",
                "cookie-jar", "noproxy", "proxy-user", "socks5", "tlsv1.2", "retry-delay", "limit-rate",
                "write-out", "fail", "max-redirs", "doh-url", "ipv4", "parallel")) {
            assertEquals(Handling.C, spec(n).handling(), n);
        }
        for (String n : List.of("ftp-pasv", "quote", "list-only", "mail-from", "mail-rcpt", "pubkey",
                "telnet-option", "tftp-blksize", "krb", "sasl-ir", "knownhosts")) {
            assertEquals(Handling.D, spec(n).handling(), n);
        }
    }

    @Test
    void resolveExactAndNegation() {
        LongMatch m = T.resolveLong("data-raw").orElseThrow();
        assertEquals(new LongMatch(spec("data-raw"), false, false, null), m);

        m = T.resolveLong("no-compressed").orElseThrow();
        assertSame(spec("compressed"), m.spec());
        assertTrue(m.negated());

        m = T.resolveLong("no-keepalive").orElseThrow();
        assertSame(spec("keepalive"), m.spec());
        assertTrue(m.negated());

        m = T.resolveLong("no-buffer").orElseThrow();
        assertSame(spec("buffer"), m.spec());
        assertTrue(m.negated());

        m = T.resolveLong("no-alpn").orElseThrow();
        assertSame(spec("alpn"), m.spec());
        assertTrue(m.negated());

        m = T.resolveLong("noproxy").orElseThrow();
        assertSame(spec("noproxy"), m.spec());
        assertFalse(m.negated());

        assertTrue(T.resolveLong("no-data").isEmpty(), "data is not negatable");
        assertTrue(T.resolveLong("no-").isEmpty());
    }

    @Test
    void resolveExpand() {
        LongMatch m = T.resolveLong("expand-data").orElseThrow();
        assertSame(spec("data"), m.spec());
        assertTrue(m.expand());
        assertFalse(m.negated());
        m = T.resolveLong("expand-url").orElseThrow();
        assertSame(spec("url"), m.spec());
        assertTrue(m.expand());
        assertTrue(T.resolveLong("expand-compressed").isEmpty(), "takes no argument");
    }

    @Test
    void resolveAbbreviation() {
        LongMatch m = T.resolveLong("compr").orElseThrow();
        assertSame(spec("compressed"), m.spec());
        // "head" is an exact name even though "header" shares the prefix
        assertSame(spec("head"), T.resolveLong("head").orElseThrow().spec());
        assertSame(spec("header"), T.resolveLong("heade").orElseThrow().spec());
        // ambiguous: data-ascii, data-binary, data-raw, data-urlencode all start with "data-"
        assertTrue(T.resolveLong("data-").isEmpty());
        assertTrue(T.resolveLong("proxy-t").isEmpty());
        assertTrue(T.resolveLong("zzz-unknown").isEmpty());
    }

    @Test
    void resolveInlineValue() {
        LongMatch m = T.resolveLong("header=X: y").orElseThrow();
        assertSame(spec("header"), m.spec());
        assertEquals("X: y", m.inlineValue());
        m = T.resolveLong("data=a=b").orElseThrow();
        assertSame(spec("data"), m.spec());
        assertEquals("a=b", m.inlineValue());
        m = T.resolveLong("expand-data={{x}}").orElseThrow();
        assertTrue(m.expand());
        assertEquals("{{x}}", m.inlineValue());
        assertTrue(T.resolveLong("compressed=1").isEmpty(), "option takes no argument");
        assertTrue(T.resolveLong("nope=1").isEmpty());
        assertTrue(T.resolveLong("=x").isEmpty());
        assertEquals(Optional.empty(), T.resolveLong(""));
    }

    @Test
    void byShortUnknown() {
        assertTrue(T.byShort('!').isEmpty());
        assertTrue(T.byShort((char) 0).isEmpty());
        assertEquals("next", T.byShort(':').orElseThrow().longName());
    }
}
