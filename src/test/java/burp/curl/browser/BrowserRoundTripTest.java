package burp.curl.browser;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import burp.curl.BuiltRequest;
import burp.curl.Curl;
import burp.curl.DialectDetector;
import burp.curl.DialectDetector.Dialect;
import burp.curl.FileAccess;
import burp.curl.browser.BrowserGenerators.Flavor;
import burp.curl.browser.BrowserGenerators.Gen;
import burp.curl.browser.BrowserGenerators.Hdr;
import burp.curl.browser.BrowserGenerators.Req;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import java.util.stream.Stream;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

/**
 * What a browser puts on the clipboard parses back into the request it describes: for every browser x dialect a
 * logical request goes through the (node-validated) generator port, {@code Curl.parse(text).build(DENY)} must give
 * exactly one request whose method, request target, headers and body equal what the generator's arguments mean
 * after the generator's own, exactly modelled information loss ({@link Expectation#loss}).
 */
class BrowserRoundTripTest {
    static final int RANDOM_PER_FLAVOR = 3000;

    /** @return null when the round trip holds, else the failure description */
    static String roundTrip(Flavor f, Req logical) {
        Req r = Samples.avoidCoreBug(f, Samples.clean(logical));
        Gen g = f.gen(r);
        Expectation e = Expectation.of(f, g);
        List<BuiltRequest> built;
        try {
            built = Curl.parse(g.text()).build(FileAccess.DENY);
        } catch (Exception ex) {
            return ex + "\n" + g.text();
        }
        if (built.size() != 1) {
            return "expected exactly one request, got " + built.size() + "\n" + g.text();
        }
        String bad = e.check(built.get(0).raw());
        return bad == null ? null : bad + "\n----- clipboard text -----\n" + g.text() + "\n----- our request -----\n"
                + new String(built.get(0).raw(), StandardCharsets.ISO_8859_1).replace("\r", "\\r");
    }

    @TestFactory
    Stream<DynamicTest> handWrittenNastyRequests() {
        List<Samples.Named> all = Samples.nasty();
        assertTrue(all.size() >= 60, "need at least 60 hand-written requests, have " + all.size());
        List<DynamicTest> tests = new ArrayList<>();
        for (Flavor f : Flavor.values()) {
            for (Samples.Named s : all) {
                Req r = Samples.avoidCoreBug(f, Samples.clean(s.req()));
                if (Samples.notApplicable(f, r) != null) {
                    continue;
                }
                tests.add(DynamicTest.dynamicTest(f + " " + s.name(), () -> {
                    Gen g = f.gen(r);
                    Assumptions.assumeTrue(Samples.generatorOutputUnusable(f, g) == null, "generator output unusable");
                    if (!f.cmd() && DialectDetector.detect(g.text()) == Dialect.CMD) {
                        assertDocumentedResidualMisdetection(g.text());
                        return;
                    }
                    assertNull(roundTrip(f, r));
                }));
            }
        }
        return tests.stream();
    }

    /** The only POSIX text we may read as cmd: documented in DialectDetectorTest#residualMisdetectionIsDocumented. */
    static void assertDocumentedResidualMisdetection(String text) {
        assertTrue(!text.contains("\\\n") && text.matches("(?s).*\\s\\^\".*"),
                "POSIX text read as CMD outside the documented residual class:\n" + text);
    }

    private static void randomRoundTrip(Flavor f, long seed) {
        Random rnd = new Random(seed);
        int done = 0;
        int residual = 0;
        int lossless = 0;
        int unusable = 0;
        List<String> failures = new ArrayList<>();
        while (done < RANDOM_PER_FLAVOR) {
            Req r = Samples.avoidCoreBug(f, Samples.clean(Samples.random(rnd)));
            if (Samples.notApplicable(f, r) != null) {
                continue;
            }
            Gen g = f.gen(r);
            if (Samples.generatorOutputUnusable(f, g) != null) {
                unusable++;
                continue;
            }
            if (!f.cmd() && DialectDetector.detect(g.text()) == Dialect.CMD) {
                assertDocumentedResidualMisdetection(g.text());
                residual++;
                continue;
            }
            if (f.cmd()) {
                assertEquals(Dialect.CMD, DialectDetector.detect(g.text()), "cmd text must be detected as cmd:\n" + g.text());
            }
            done++;
            if (allLossless(f, g)) {
                lossless++;
            }
            String bad = roundTrip(f, r);
            if (bad != null && failures.size() < 5) {
                failures.add("seed " + seed + " case " + done + ": " + bad);
            }
        }
        System.out.println("random round trip " + f + ": " + done + " requests, " + lossless
                + " carried losslessly; skipped: " + residual + " documented dialect misdetection, " + unusable
                + " generator output curl refuses");
        assertTrue(failures.isEmpty(), String.join("\n=====\n", failures));
        assertTrue(lossless > RANDOM_PER_FLAVOR / 10, "too few lossless cases: " + lossless);
    }

    static boolean allLossless(Flavor f, Gen g) {
        for (String a : g.argv()) {
            if (!Expectation.lossless(f, a)) {
                return false;
            }
        }
        return true;
    }

    @Test
    void chromeBashRandom() {
        randomRoundTrip(Flavor.CHROME_BASH, 11L);
    }

    @Test
    void chromeCmdRandom() {
        randomRoundTrip(Flavor.CHROME_CMD, 12L);
    }

    @Test
    void firefoxBashRandom() {
        randomRoundTrip(Flavor.FIREFOX_BASH, 13L);
    }

    @Test
    void firefoxCmdRandom() {
        randomRoundTrip(Flavor.FIREFOX_CMD, 14L);
    }

    @Test
    void safariBashRandom() {
        randomRoundTrip(Flavor.SAFARI_BASH, 15L);
    }

    // ------------------------------------------------------------------------------------ loss classes

    private static Req post(String body, Hdr... h) {
        return new Req("POST", "https://x.test/p", List.of(h), body, false, false, null).withBody(body);
    }

    private static String bodyOf(Flavor f, Req r) throws Exception {
        List<BuiltRequest> b = Curl.parse(f.gen(r).text()).build(FileAccess.DENY);
        byte[] raw = b.get(0).raw();
        int at = new String(raw, StandardCharsets.ISO_8859_1).indexOf("\r\n\r\n") + 4;
        return new String(raw, at, raw.length - at, StandardCharsets.ISO_8859_1);
    }

    /**
     * Each class below is a loss of the generator itself: two different logical inputs give the same clipboard text
     * (proved on the generator port, independent of our parser), and our parse yields exactly the modelled result.
     */
    @Test
    void lossClassesOfTheCmdGenerators() throws Exception {
        for (Flavor f : new Flavor[] {Flavor.CHROME_CMD, Flavor.FIREFOX_CMD}) {
            // TAB is not representable: the clipboard text of a TAB equals that of a space
            assertEquals("a b", headerValue(f, "a\tb"), f + ": TAB becomes a space");
            assertEquals(f.gen(hdr("a b")).text(), f.gen(hdr("a\tb")).text(), f + ": a TAB and a space give the same text");
            assertEquals(f.gen(hdr("a b")).text(), f.gen(hdr("a\u00a0b")).text(), f + ": an NBSP and a space give the same text");
            // CR and CRLF become LF; the clipboard text is the same as for a plain LF
            assertEquals("a\nb", headerValue(f, "a\r\nb"), f + ": CRLF becomes LF");
            assertEquals("a\nb", headerValue(f, "a\rb"), f + ": CR becomes LF");
            assertEquals(f.gen(hdr("a\r\nb")).text(), f.gen(hdr("a\nb")).text(), f + ": CRLF and LF give the same text");
            assertEquals(f.gen(hdr("a\rb")).text(), f.gen(hdr("a\nb")).text(), f + ": CR and LF give the same text");
            // NBSP and other JS white space become a space
            assertEquals("a b", headerValue(f, "a\u00a0b"), f + ": NBSP becomes a space");
            assertEquals("a b", headerValue(f, "a\u2028b"), f + ": U+2028 becomes a space");
            assertEquals("a b", headerValue(f, "a\u3000b"), f + ": ideographic space becomes a space");
        }
        // Chrome only: every non-ASCII UTF-16 unit and every control character becomes a space
        assertEquals("a b", headerValue(Flavor.CHROME_CMD, "a\u00e9b"));
        assertEquals("a  b", headerValue(Flavor.CHROME_CMD, "a\uD83D\uDE00b"), "emoji = two UTF-16 units = two spaces");
        assertEquals("a b", headerValue(Flavor.CHROME_CMD, "a\u0001b"));
        assertEquals("a b", headerValue(Flavor.CHROME_CMD, "a\u007fb"));
        // Firefox keeps non-ASCII text and control characters
        assertEquals("a\u00e9b\u65e5\uD83D\uDE00\u0001", utf8(headerValue(Flavor.FIREFOX_CMD, "a\u00e9b\u65e5\uD83D\uDE00\u0001")));
    }

    private static Req hdr(String v) {
        return Req.of("GET", "https://x.test/", Samples.h("X-V", v));
    }

    /** The bytes (as Latin-1 chars) of the X-V header value we send for the flavour's clipboard text. */
    private static String headerValue(Flavor f, String v) throws Exception {
        String raw = new String(Curl.parse(f.gen(hdr(v)).text()).build(FileAccess.DENY).get(0).raw(), StandardCharsets.ISO_8859_1);
        int at = raw.indexOf("\r\nX-V: ") + 7;
        return raw.substring(at, raw.indexOf("\r\n\r\n", at));
    }

    private static String utf8(String latin1) {
        return new String(latin1.getBytes(StandardCharsets.ISO_8859_1), StandardCharsets.UTF_8);
    }

    @Test
    void lossClassesOfTheBashGenerators() throws Exception {
        // Firefox and Safari write U+0080..U+00FF as \xHH: bash then yields the single Latin-1 byte, not UTF-8
        for (Flavor f : new Flavor[] {Flavor.FIREFOX_BASH, Flavor.SAFARI_BASH}) {
            assertEquals("é", bodyOf(f, post("é", Samples.h("Content-Type", "text/plain"))),
                    f + ": e-acute is sent as the single byte E9");
            assertEquals("â\u0082¬", bodyOf(f, post("€", Samples.h("Content-Type", "text/plain"))),
                    f + ": U+20AC (>= U+0100) goes through \\u and is UTF-8");
            // a surrogate pair is written as two \\u escapes: bash encodes each half separately (CESU-8, 6 bytes)
            assertEquals(6, bodyOf(f, post("😀", Samples.h("Content-Type", "text/plain"))).length());
        }
        // Chrome bash keeps UTF-8 intact
        assertEquals("Ã©ð\u009f\u0098\u0080",
                bodyOf(Flavor.CHROME_BASH, post("é😀")));
    }

    @Test
    void firefoxDropsHeadersWithEmptyValueAndChromeDoesNot() throws Exception {
        Req r = Req.of("GET", "https://x.test/", Samples.h("X-Empty", ""), Samples.h("X-Keep", "v"));
        String chrome = new String(Curl.parse(Flavor.CHROME_BASH.gen(r).text()).build(FileAccess.DENY).get(0).raw(),
                StandardCharsets.ISO_8859_1);
        assertTrue(chrome.contains("\r\nX-Empty:\r\n"), "Chrome writes `-H 'X-Empty;'`, curl sends an empty header");
        for (Flavor f : new Flavor[] {Flavor.FIREFOX_BASH, Flavor.FIREFOX_CMD, Flavor.SAFARI_BASH}) {
            String s = new String(Curl.parse(f.gen(r).text()).build(FileAccess.DENY).get(0).raw(), StandardCharsets.ISO_8859_1);
            assertTrue(!s.contains("X-Empty"), f + " writes `-H 'X-Empty: '`, which tells curl to drop the header: " + s);
            assertTrue(s.contains("\r\nX-Keep: v\r\n"));
        }
    }

    @Test
    void firefoxOnlySendsTheLastLineOfACrlfBody() throws Exception {
        Req r = post("a=1\r\nb=2\r\nlast", Samples.h("Content-Type", "text/plain"));
        assertEquals("last", bodyOf(Flavor.FIREFOX_BASH, r));
        assertEquals("last", bodyOf(Flavor.FIREFOX_CMD, r));
        assertEquals("a=1\r\nb=2\r\nlast", bodyOf(Flavor.CHROME_BASH, r));
        assertEquals("a=1\r\nb=2\r\nlast", bodyOf(Flavor.SAFARI_BASH, r));
    }

    @Test
    void safariDataAtSignIsAFileReference() throws Exception {
        Req r = post("@secret.txt", Samples.h("Content-Type", Samples.FORM_CT));
        assertTrue(Curl.parse(Flavor.SAFARI_BASH.gen(r).text()).fileRefs().contains("secret.txt"));
        assertTrue(Curl.parse(Flavor.CHROME_BASH.gen(r).text()).fileRefs().isEmpty(), "--data-raw never reads files");
        assertTrue(Curl.parse(Flavor.FIREFOX_BASH.gen(r).text()).fileRefs().isEmpty(), "--data-raw never reads files");
    }

    /** The oracle must be able to fail: tampered requests are rejected. */
    @Test
    void expectationDetectsTampering() throws Exception {
        Req r = post("body", Samples.h("X-A", "v"), Samples.h("Content-Type", "text/plain"));
        Gen g = Flavor.CHROME_BASH.gen(r);
        byte[] raw = Curl.parse(g.text()).build(FileAccess.DENY).get(0).raw();
        Expectation e = Expectation.of(Flavor.CHROME_BASH, g);
        assertNull(e.check(raw));
        String w = new String(raw, StandardCharsets.ISO_8859_1);
        assertTrue(e.check(w.replace("POST /p", "PUT /p").getBytes(StandardCharsets.ISO_8859_1)) != null, "method");
        assertTrue(e.check(w.replace("POST /p", "POST /q").getBytes(StandardCharsets.ISO_8859_1)) != null, "target");
        assertTrue(e.check(w.replace("X-A: v", "X-A: w").getBytes(StandardCharsets.ISO_8859_1)) != null, "header value");
        assertTrue(e.check(w.replace("X-A:", "X-B:").getBytes(StandardCharsets.ISO_8859_1)) != null, "header name");
        assertTrue(e.check(w.replace("body", "bodz").getBytes(StandardCharsets.ISO_8859_1)) != null, "body");
        assertTrue(e.check((w + "x").getBytes(StandardCharsets.ISO_8859_1)) != null, "trailing byte");
    }

    @Test
    void residualDialectMisdetectionOfShortBashCommands() {
        // A bash command of fewer than 3 parts is one line; ' ^"' inside single quotes is then read as cmd (documented).
        String text = Flavor.CHROME_BASH.gen(Req.of("GET", "https://x.test/", Samples.h("X-A", "v ^\"w"))).text();
        assertEquals(Dialect.CMD, DialectDetector.detect(text), text);
        // with a third part the generator joins with backslash-newline and the veto applies
        String longer = Flavor.CHROME_BASH.gen(Req.of("GET", "https://x.test/", Samples.h("X-A", "v ^\"w"), Samples.h("X-B", "b"))).text();
        assertEquals(Dialect.POSIX, DialectDetector.detect(longer), longer);
    }
}
