package burp.curl.browser;

import static org.junit.jupiter.api.Assertions.assertEquals;

import burp.curl.Curl;
import burp.curl.FileAccess;
import burp.curl.testsupport.DiffPrinter;
import java.nio.charset.StandardCharsets;
import java.util.List;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

/**
 * Bugs found in the core (not in a tokenizer) while testing browser output. They are NOT fixed here and NOT hidden:
 * these tests fail until the owner of the request builder fixes them. Minimal inputs only; each compares with the
 * bytes the real curl sends.
 */
class CoreBugsTest {
    private static void sameAsRealCurl(String commandWithPortPlaceholder) throws Exception {
        Assumptions.assumeTrue(RealCurlBatch.available(), "curl, bash >= 4.2 or a UTF-8 locale is missing");
        RealCurlBatch.Outcome o = RealCurlBatch.run(port -> List.of(commandWithPortPlaceholder.replace("PORT", Integer.toString(port))));
        String text = o.commands().get(0);
        byte[] ours = Curl.parse(text).build(FileAccess.DENY).get(0).raw();
        String report = DiffPrinter.compare(text, List.of(o.requests().get(0)), List.of(ours));
        assertEquals(null, report, report);
    }

    /**
     * Real curl 8.7.1 sends the header bytes exactly as bash produced them: $'\xe9' is the single byte E9.
     * Firefox's and Safari's "Copy as cURL" for bash write U+0080..U+00FF this way, so any such header value is
     * corrupted: CurlCommandParser decodes -H arguments as UTF-8 text (Operation.headers is a List of String) and
     * U+FFFD is sent.
     */
    @Test
    void headerWithNonUtf8BytesKeepsItsBytes() throws Exception {
        sameAsRealCurl("curl http://127.0.0.1:PORT/ -H $'X-L: caf\\xe9'");
    }

    /** Same for the cookie argument: -b $'a=\xe9'. */
    @Test
    void cookieWithNonUtf8BytesKeepsItsBytes() throws Exception {
        sameAsRealCurl("curl http://127.0.0.1:PORT/ -b $'a=caf\\xe9'");
    }

    /**
     * Real curl 8.7.1 does not send a -H argument whose header name is empty, such as the HTTP/2 pseudo header
     * ':authority: example.test' that Firefox and Safari list among the request headers. We send it.
     */
    @Test
    void headerWithEmptyNameIsDroppedLikeCurl() throws Exception {
        sameAsRealCurl("curl http://127.0.0.1:PORT/ -H ':authority: example.test' -H 'X-Keep: v'");
    }

    /** Makes sure the minimal inputs above really are accepted by the parser (no exception). */
    @Test
    void minimalInputsParse() throws Exception {
        for (String c : List.of("curl http://h.test/ -H $'X-L: caf\\xe9'", "curl http://h.test/ -b $'a=\\xe9'",
                "curl http://h.test/ -H ':a: b'")) {
            Curl.parse(c).build(FileAccess.DENY);
        }
        assertEquals(1, new String(Curl.parse("curl http://h.test/ -H 'X: y'").build(FileAccess.DENY).get(0).raw(),
                StandardCharsets.ISO_8859_1).split("X: y").length - 1);
    }
}
