package burp.curl;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.List;
import org.junit.jupiter.api.Test;

/** {@code Curl.parse} tries the other shell dialect when the detected one cannot read the text. */
class DialectFallbackTest {
    private static String raw(String text) throws CurlParseException {
        return new String(Curl.parse(text).build(FileAccess.DENY).get(0).raw(), StandardCharsets.ISO_8859_1);
    }

    private static List<String> notes(String text) throws CurlParseException {
        return Curl.parse(text).warnings().stream().map(Warning::message).toList();
    }

    @Test
    void bashHeaderWithSpaceCaretQuoteParsesAsBash() throws Exception {
        String text = "curl --url 'https://x.test/' -H 'X-A: v ^\"w'";
        assertEquals(DialectDetector.Dialect.CMD, DialectDetector.detect(text));
        assertTrue(raw(text).contains("\r\nX-A: v ^\"w\r\n"), raw(text));
        Warning w = Curl.parse(text).warnings().stream().filter(x -> x.message().contains("POSIX")).findFirst().get();
        assertEquals(Warning.Severity.NOTE, w.severity());
    }

    @Test
    void bashDataWithSpaceCaretQuoteParsesAsBash() throws Exception {
        String text = "curl -d ' ^\"foo' http://x";
        assertEquals(DialectDetector.Dialect.CMD, DialectDetector.detect(text));
        String w = raw(text);
        assertTrue(w.endsWith("\r\n\r\n ^\"foo"), w);
        assertTrue(notes(text).stream().anyMatch(m -> m.contains("POSIX")), notes(text).toString());
    }

    @Test
    void genuineCmdIsStillCmd() throws Exception {
        String text = "curl ^\"http://x.test/^\" -H ^\"A: b^\"";
        assertTrue(raw(text).contains("\r\nA: b\r\n"));
        assertFalse(notes(text).stream().anyMatch(m -> m.contains("POSIX") || m.contains("cmd")), notes(text).toString());
    }

    @Test
    void genuineCmdWithSyntaxErrorReportsTheCmdError() {
        String text = "curl ^\"http://x.test/^\" -H ^\"A: b^\" ^\"unterminated";
        CurlParseException e = assertThrows(CurlParseException.class, () -> Curl.parse(text));
        assertEquals("Unterminated double quote", e.getMessage());
        assertEquals(37, e.position());
    }

    @Test
    void bashWithUnterminatedQuoteReportsTheBashError() {
        CurlParseException e = assertThrows(CurlParseException.class, () -> Curl.parse("curl 'http://x"));
        assertEquals("Unterminated single quote", e.getMessage());
        assertEquals(5, e.position());
        e = assertThrows(CurlParseException.class, () -> Curl.parse("curl http://x -H 'A: b"));
        assertEquals("Unterminated single quote", e.getMessage());
        assertEquals(17, e.position());
    }

    @Test
    void bashDetectedAsCmdWithUnterminatedQuoteReportsTheCmdError() {
        // both dialects fail: the error of the detected dialect (cmd) is reported
        String text = "curl -d ' ^\"foo http://x";
        assertEquals(DialectDetector.Dialect.CMD, DialectDetector.detect(text));
        CurlParseException e = assertThrows(CurlParseException.class, () -> Curl.parse(text));
        assertEquals("Unterminated double quote", e.getMessage());
    }

    @Test
    void noCurlCommandInTheDetectedDialectTriesTheOther() throws Exception {
        // cmd reads the whole text as one word without a curl command; bash finds the command
        String text = "echo ^\"x ^\" ; curl 'http://x.test/' -H 'A: b'";
        assertEquals(DialectDetector.Dialect.CMD, DialectDetector.detect(text));
        assertTrue(raw(text).contains("\r\nA: b\r\n"), raw(text));
    }
}
