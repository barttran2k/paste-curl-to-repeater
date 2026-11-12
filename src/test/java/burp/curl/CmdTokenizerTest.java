package burp.curl;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

class CmdTokenizerTest {
    private static TokenizeResult tok(String s) throws CurlParseException {
        return new CmdTokenizer().tokenize(s);
    }

    private static List<String> words(CommandLine c) {
        List<String> o = new ArrayList<>();
        c.argv().forEach(t -> o.add(t.text()));
        return o;
    }

    private static List<String> one(String s) throws CurlParseException {
        TokenizeResult r = tok(s);
        assertEquals(1, r.commands().size(), s);
        return words(r.commands().get(0));
    }

    @Test
    void emptyInputGivesNoCommands() throws Exception {
        assertEquals(0, tok("").commands().size());
        assertEquals(0, tok("  \n \r\n").commands().size());
        assertEquals(0, tok(null).commands().size());
    }

    @Test
    void plainWords() throws Exception {
        assertEquals(List.of("curl", "-X", "POST", "http://x/"), one("curl -X POST http://x/"));
        assertEquals(List.of("curl", "a", "b"), one("curl\ta   b"));
    }

    @Test
    void handWrittenQuotes() throws Exception {
        assertEquals(List.of("curl", "-H", "A: b c", "u"), one("curl -H \"A: b c\" u"));
        assertEquals(List.of("curl", "-d", "{\"a\":1}"), one("curl -d \"{\\\"a\\\":1}\""));
        assertEquals(List.of("curl", ""), one("curl \"\""));
        assertEquals(List.of("curl", "a\"b"), one("curl \"a\"\"b\""));
        assertEquals(List.of("curl", "ab"), one("curl a\"\"b"));
    }

    @Test
    void caretEscapesOutsideQuotes() throws Exception {
        assertEquals(List.of("curl", "a&b"), one("curl a^&b"));
        assertEquals(List.of("curl", "a^b"), one("curl a^^b"));
        assertEquals(List.of("curl", "a", "b"), one("curl a^ b")); // escaped space still separates args for the CRT
    }

    @Test
    void caretIsLiteralInsideCmdQuotes() throws Exception {
        assertEquals(List.of("curl", "a^b"), one("curl \"a^b\""));
        assertEquals(List.of("curl", "a&b|c"), one("curl \"a&b|c\""));
    }

    @Test
    void escapedQuoteDoesNotToggleCmdQuoteState() throws Exception {
        // ^" is a plain quote for the argument layer but cmd stays unquoted, so & still ends the command.
        TokenizeResult r = tok("curl ^\"a b^\" & echo hi");
        assertEquals(2, r.commands().size());
        assertEquals(List.of("curl", "a b"), words(r.commands().get(0)));
        assertEquals(List.of("echo", "hi"), words(r.commands().get(1)));
    }

    @Test
    void lineContinuation() throws Exception {
        assertEquals(List.of("curl", "-H", "a", "u"), one("curl ^\n  -H ^\"a^\" ^\r\n  u"));
        assertEquals(List.of("curl", "ab"), one("curl a^\nb"));
    }

    @Test
    void literalNewlineIsCaretNewlineNewline() throws Exception {
        assertEquals(List.of("curl", "a\nb"), one("curl ^\"a^\n\nb^\""));
        assertEquals(List.of("curl", "a\n\nb"), one("curl ^\"a^\n\n^\n\nb^\""));
    }

    @Test
    void commandSeparators() throws Exception {
        assertEquals(2, tok("curl a & curl b").commands().size());
        assertEquals(2, tok("curl a && curl b").commands().size());
        assertEquals(2, tok("curl a | jq .").commands().size());
        assertEquals(2, tok("curl a || echo x").commands().size());
        assertEquals(2, tok("curl a\ncurl b").commands().size());
        assertEquals(2, tok("curl a\r\ncurl b").commands().size());
        assertEquals(1, tok("curl a &").commands().size());
        assertEquals(1, tok("& & curl a").commands().size());
    }

    @Test
    void redirectionsAreRemoved() throws Exception {
        assertEquals(List.of("curl", "a", "b"), one("curl a > out.txt b"));
        assertEquals(List.of("curl", "a"), one("curl a >> out.txt"));
        assertEquals(List.of("curl", "a"), one("curl a 2> err.txt"));
        assertEquals(List.of("curl", "a"), one("curl a 2>&1"));
        assertEquals(List.of("curl", "a"), one("curl a >out.txt 2>&1"));
        assertEquals(List.of("curl", "a"), one("curl a > \"my out.txt\""));
        assertEquals(List.of("curl", "a2"), one("curl a2 > o"));
    }

    @Test
    void stdinRedirect() throws Exception {
        TokenizeResult r = tok("curl -d @- http://x < body.json");
        CommandLine c = r.commands().get(0);
        assertEquals(List.of("curl", "-d", "@-", "http://x"), words(c));
        assertEquals("body.json", c.stdinFile());
        assertEquals("C:\\a b\\x.json", tok("curl x <\"C:\\a b\\x.json\"").commands().get(0).stdinFile());
        assertNull(tok("curl x").commands().get(0).stdinFile());
    }

    @Test
    void percentVariablesWarnOncePerDistinctName() throws Exception {
        TokenizeResult r = tok("curl -H \"Authorization: %TOKEN%\" %HOST%/a %TOKEN%");
        assertEquals(List.of("curl", "-H", "Authorization: %TOKEN%", "%HOST%/a", "%TOKEN%"),
                words(r.commands().get(0)));
        assertEquals(2, r.warnings().size());
        assertTrue(r.warnings().stream().allMatch(w -> w.severity() == Warning.Severity.LOSSY));
        assertTrue(r.warnings().get(0).message().contains("%TOKEN%"));
        assertTrue(r.warnings().get(1).message().contains("%HOST%"));
    }

    @Test
    void generatorPercentEscapingDecodesToPlainPercentWithoutWarning() throws Exception {
        TokenizeResult r = tok("curl ^\"^%^PATH^%^\" ^\"a^%20b^%^c^\"");
        assertEquals(List.of("curl", "%PATH%", "a%20b%c"), words(r.commands().get(0)));
        assertTrue(r.warnings().isEmpty());
    }

    @Test
    void urlEncodedPercentsDoNotWarn() throws Exception {
        TokenizeResult r = tok("curl \"http://x/a%20b%20c?q=%E3%81%82&r=100%\"");
        assertTrue(r.warnings().isEmpty(), r.warnings().toString());
    }

    @Test
    void preprocessing() throws Exception {
        assertEquals(List.of("curl", "a"), one("\uFEFFcurl a"));
        assertEquals(List.of("curl", "a"), one("C:\\Users\\me\\proj>curl a"));
        assertEquals(List.of("curl", "a"), one("  C:\\>  curl a"));
        assertEquals(List.of("curl", "a"), one("curl a\r\n"));
        assertEquals(List.of("curl", "a"), one("curl a\r"));
    }

    @Test
    void backslashRulesInsideQuotes() throws Exception {
        assertEquals(List.of("curl", "C:\\Users\\me"), one("curl \"C:\\Users\\me\""));
        assertEquals(List.of("curl", "a\\\\b"), one("curl \"a\\\\b\""));    // bare quote: the CRT keeps both
        assertEquals(List.of("curl", "a\\"), one("curl \"a\\\\\""));
        assertEquals(List.of("curl", "a\"b"), one("curl \"a\\\"b\""));
        assertEquals(List.of("curl", "a\\\"b"), one("curl \"a\\\\\\\"b\""));
    }

    @Test
    void backslashRulesOutsideQuotes() throws Exception {
        assertEquals(List.of("curl", "\\\\srv\\share"), one("curl \\\\srv\\share"));
        assertEquals(List.of("curl", "a\"b"), one("curl a\\\"b"));
        assertEquals(List.of("curl", "a\\b c"), one("curl a\\\\\"b c\""));
    }

    @Test
    void quotedFlag() throws Exception {
        List<Token> t = tok("curl a \"b\" c^&d \"\" x\\\"y").commands().get(0).argv();
        assertFalse(t.get(0).quoted());
        assertFalse(t.get(1).quoted());
        assertTrue(t.get(2).quoted());
        assertTrue(t.get(3).quoted());
        assertTrue(t.get(4).quoted());
        assertTrue(t.get(5).quoted());
    }

    @Test
    void tokensAreUtf8Bytes() throws Exception {
        Token t = tok("curl \"é😀\"").commands().get(0).argv().get(1);
        assertEquals("é😀", new String(t.bytes(), StandardCharsets.UTF_8));
        assertEquals(6, t.bytes().length);
    }

    @Test
    void unterminatedQuoteReportsPositionInOriginalInput() {
        CurlParseException e = assertThrows(CurlParseException.class, () -> tok("curl \"abc"));
        assertEquals(5, e.position());
        e = assertThrows(CurlParseException.class, () -> tok("\uFEFFcurl a\r\n  \"abc\r\nx"));
        assertEquals(11, e.position());
        e = assertThrows(CurlParseException.class, () -> tok("curl ^\"abc"));
        assertTrue(e.position() >= 0);
        e = assertThrows(CurlParseException.class, () -> tok("curl a > \"x"));
        assertEquals(9, e.position());
    }

    @Test
    void completeChromeCommand() throws Exception {
        String cmd = "curl ^\"https://api.example.com/v1/items^?a=1^&b=^%^20x^\" ^\n"
                + "  -H ^\"accept: application/json^\" ^\n"
                + "  -H ^\"content-type: application/json^\" ^\n"
                + "  -b ^\"sid=abc^%^20def; t=1^\" ^\n"
                + "  --data-raw ^\"^{^\"^\"name^\"^\":^\"^\"a ^\\^\\^\"^\"q^\\^\\^\"^\" C:^\\^\\^\\^\\x^\"^\"^}^\" ^\n"
                + "  --insecure";
        TokenizeResult r = tok(cmd);
        assertTrue(r.warnings().isEmpty());
        assertEquals(List.of("curl", "https://api.example.com/v1/items?a=1&b=%20x",
                "-H", "accept: application/json",
                "-H", "content-type: application/json",
                "-b", "sid=abc%20def; t=1",
                "--data-raw", "{\"name\":\"a \\\"q\\\" C:\\\\x\"}",
                "--insecure"), words(r.commands().get(0)));
    }

    @Test
    void completeChromeCommandWithWindowsLineEndings() throws Exception {
        String cmd = "curl ^\"https://x.example/^\" ^\r\n  -H ^\"a: b^\" ^\r\n  --data-raw ^\"l1^\r\n\r\nl2^\"";
        assertEquals(List.of("curl", "https://x.example/", "-H", "a: b", "--data-raw", "l1\nl2"), one(cmd));
    }

    @Test
    void completeFirefoxCommand() throws Exception {
        String cmd = "curl.exe ^\"https://api.example.com/v1/items?a=1^&b=^%^20x^\" ^\n"
                + "  -X POST ^\n"
                + "  -H ^\"Accept: */*^\" ^\n"
                + "  -H ^\"Content-Type: application/json^\" ^\n"
                + "  --data-raw ^\"^{\\^\"name\\^\":\\^\"a ^\\^\\\\^\"q^\\^\\\\^\" C:^\\^\\^\\^\\x\\^\"^}^\"";
        assertEquals(List.of("curl.exe", "https://api.example.com/v1/items?a=1&b=%20x",
                "-X", "POST",
                "-H", "Accept: */*",
                "-H", "Content-Type: application/json",
                "--data-raw", "{\"name\":\"a \\\"q\\\" C:\\\\x\"}"), one(cmd));
    }

    @Test
    void urlWithEncodedSpaceAndAmpersandUnquotedInsideCmdQuotes() throws Exception {
        assertEquals(List.of("curl", "http://x/a%20b?x=1&y=2"), one("curl \"http://x/a%20b?x=1&y=2\""));
    }
}
