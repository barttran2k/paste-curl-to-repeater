package burp.curl;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * Hand-written cmd commands (bare quotes) follow the Microsoft C runtime rules: backslashes are literal unless they
 * precede a quote. Only arguments opened with a caret-escaped quote (browser generators) double backslashes.
 */
class CmdTokenizerHandwrittenTest {
    private static List<String> one(String s) throws CurlParseException {
        TokenizeResult r = new CmdTokenizer().tokenize(s);
        assertEquals(1, r.commands().size(), s);
        List<String> o = new ArrayList<>();
        r.commands().get(0).argv().forEach(t -> o.add(t.text()));
        return o;
    }

    @Test
    void jsonBodyWithWindowsPathKeepsDoubledBackslashes() throws Exception {
        assertEquals(List.of("curl", "-d", "{\"p\":\"C:\\\\dir\"}", "http://x/"),
                one("curl -d \"{\\\"p\\\":\\\"C:\\\\dir\\\"}\" http://x/"));
    }

    @Test
    void backslashPairsInsideQuotesStayLiteral() throws Exception {
        assertEquals(List.of("curl", "-o", "C:\\\\tmp\\\\x"), one("curl -o \"C:\\\\tmp\\\\x\""));
        assertEquals(List.of("curl", "-o", "C:\\tmp\\x"), one("curl -o \"C:\\tmp\\x\""));
    }

    @Test
    void uncPathKeepsItsLeadingBackslashes() throws Exception {
        assertEquals(List.of("curl", "-T", "\\\\server\\share\\f.txt"), one("curl -T \"\\\\server\\share\\f.txt\""));
        assertEquals(List.of("curl", "-T", "\\\\server\\share\\f.txt"), one("curl -T \\\\server\\share\\f.txt"));
    }

    @Test
    void trailingBackslashesBeforeTheClosingQuote() throws Exception {
        // 2n backslashes + quote: n backslashes, the quote closes
        assertEquals(List.of("curl", "-o", "C:\\dir\\", "http://x/"), one("curl -o \"C:\\dir\\\\\" http://x/"));
        // 2n+1 backslashes + quote: n backslashes and a literal quote
        assertEquals(List.of("curl", "-o", "C:\\dir\" http://x/"), one("curl -o \"C:\\dir\\\" http://x/\""));
        assertEquals(List.of("curl", "-o", "a\\\\\\\\b"), one("curl -o \"a\\\\\\\\b\""));
    }

    @Test
    void doubledQuoteInsideQuotesIsOneQuote() throws Exception {
        assertEquals(List.of("curl", "-d", "say \"hi\"", "http://x/"), one("curl -d \"say \"\"hi\"\"\" http://x/"));
    }

    @Test
    void mixedArgumentsInOneCommand() throws Exception {
        // a hand-written argument next to the argument of a browser generator
        String cmd = "curl.exe -o \"C:\\\\tmp\\\\x\" -d ^\"{\\^\"p\\^\":\\^\"C:\\\\dir\\^\"}^\" -T \\\\srv\\s\\f "
                + "-H \"A: b\\\\c\" ^\"http://x/^\"";
        assertEquals(List.of("curl.exe", "-o", "C:\\\\tmp\\\\x", "-d", "{\"p\":\"C:\\dir\"}", "-T", "\\\\srv\\s\\f",
                "-H", "A: b\\\\c", "http://x/"), one(cmd));
    }

    @Test
    void generatorArgumentsStillDoubleBackslashes() throws Exception {
        assertEquals(List.of("curl", "-d", "C:\\dir\\file"), one("curl -d ^\"C:\\\\dir\\\\file^\""));
        assertEquals(List.of("curl", "-d", "a\"b"), one("curl -d ^\"a\\^\"b^\""));
    }

    @Test
    void handwrittenCommandThroughCurlParse() throws Exception {
        String text = "curl.exe -X POST -d \"{\\\"p\\\":\\\"C:\\\\dir\\\"}\" ^\n  http://127.0.0.1:1/";
        BuiltRequest r = Curl.parse(text).build(FileAccess.DENY).get(0);
        String raw = new String(r.raw(), java.nio.charset.StandardCharsets.ISO_8859_1);
        assertEquals("{\"p\":\"C:\\\\dir\"}", raw.substring(raw.indexOf("\r\n\r\n") + 4));
    }
}
