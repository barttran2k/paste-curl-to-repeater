package burp.curl;

import static burp.curl.DialectDetector.Dialect.CMD;
import static burp.curl.DialectDetector.Dialect.POSIX;
import static burp.curl.DialectDetector.detect;
import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

class DialectDetectorTest {
    @Test
    void emptyAndNullArePosix() {
        assertEquals(POSIX, detect(null));
        assertEquals(POSIX, detect(""));
        assertEquals(POSIX, detect("curl http://x"));
    }

    @Test
    void caretQuoteAtWordStartIsCmd() {
        assertEquals(CMD, detect("curl ^\"http://x^\""));
        assertEquals(CMD, detect("curl.exe ^\"http://x^\""));
        assertEquals(CMD, detect("^\"x^\""));
        assertEquals(CMD, detect("curl -H\t^\"a: b^\""));
    }

    @Test
    void trailingCaretContinuationIsCmd() {
        assertEquals(CMD, detect("curl http://x ^\n  -H a"));
        assertEquals(CMD, detect("curl http://x ^  \r\n  -H a"));
        assertEquals(CMD, detect("curl \"http://x\"^\n-H a"));
        assertEquals(CMD, detect("curl a ^\t\n b"));
    }

    @Test
    void singleTrailingCaretWithoutFollowingLineIsNotEnough() {
        assertEquals(POSIX, detect("curl http://x ^"));
        assertEquals(POSIX, detect("curl http://x ^\n\n  "));
    }

    @Test
    void ordinaryBashIsPosix() {
        assertEquals(POSIX, detect("curl -X POST 'http://x' \\\n  -H 'a: b' \\\n  -d '{\"a\":\"^\"}'"));
        assertEquals(POSIX, detect("curl 'http://x?re=^abc$' -d '{\"re\":\"^foo\"}'"));
        assertEquals(POSIX, detect("curl -d 'x' http://a/b^c"));
        assertEquals(POSIX, detect("curl -H \"X: a^b\" http://x"));
    }

    @Test
    void caretQuoteGluedToSingleQuoteIsPosix() {
        assertEquals(POSIX, detect("grep '^\"foo' f | curl -d @- http://x"));
        assertEquals(POSIX, detect("curl -d '^\"foo' http://x"));
        assertEquals(POSIX, detect("curl -d 'a^\"b' http://x"));
        assertEquals(POSIX, detect("curl -d '{\"re\":\"^\"}' http://x"));
    }

    @Test
    void posixContinuationVetoesCaretQuoteInsideBody() {
        assertEquals(POSIX, detect("curl http://x \\\n  -d ' ^\"foo'"));
    }

    @Test
    void residualMisdetectionIsDocumented() {
        // Whitespace + ^" inside a single-quoted bash string without any backslash continuation.
        assertEquals(CMD, detect("curl -d ' ^\"foo' http://x"));
    }

    @Test
    void bomAndCrlfAreIgnored() {
        assertEquals(CMD, detect("\uFEFFcurl ^\r\n -H a"));
        assertEquals(POSIX, detect("\uFEFFcurl \\\r\n -H a"));
    }
}
