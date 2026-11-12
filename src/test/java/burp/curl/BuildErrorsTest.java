package burp.curl;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import org.junit.jupiter.api.Test;

/** Build-time URL errors skip the offending request only, and error positions point into the pasted text. */
class BuildErrorsTest {

    private static boolean skippedNote(List<Warning> ws, String reason) {
        return ws.stream().anyMatch(w -> w.severity() == Warning.Severity.LOSSY && w.message().contains("skipped")
                && w.message().contains(reason));
    }

    @Test
    void badUrlInSecondCommandKeepsTheFirstRequest() throws Exception {
        List<BuiltRequest> r = Curl.parse("curl http://ok.example/ ; curl ftp://x.example/f").build(FileAccess.DENY);
        assertEquals(1, r.size());
        assertEquals("http://ok.example/", r.get(0).url());
        assertTrue(skippedNote(r.get(0).warnings(), "unsupported protocol"), r.get(0).warnings().toString());
        for (Warning w : r.get(0).warnings()) {
            assertFalse(w.message().contains("x.example"), w.message());
        }
    }

    @Test
    void badUrlAmongSeveralInOneCommandIsSkipped() throws Exception {
        List<BuiltRequest> r = Curl.parse("curl http://a.example/ ftp://x.example/f http://b.example/ 'http://[bad/'")
                .build(FileAccess.DENY);
        assertEquals(List.of("http://a.example/", "http://b.example/"), r.stream().map(BuiltRequest::url).toList());
        assertTrue(skippedNote(r.get(0).warnings(), "unsupported protocol"));
        assertTrue(r.get(1).warnings().stream().filter(w -> w.message().contains("skipped")).count() == 2,
                r.get(1).warnings().toString());
    }

    @Test
    void badUrlInANextGroupIsSkipped() throws Exception {
        List<BuiltRequest> r = Curl.parse("curl ftp://x.example/ --next http://ok.example/").build(FileAccess.DENY);
        assertEquals(1, r.size());
        assertEquals("http://ok.example/", r.get(0).url());
    }

    @Test
    void throwsOnlyWhenNothingCanBeBuilt() {
        CurlParseException e = assertThrows(CurlParseException.class,
                () -> Curl.parse("curl ftp://x.example/f ; curl gopher://y.example/").build(FileAccess.DENY));
        assertTrue(e.getMessage().contains("unsupported protocol"), e.getMessage());
        assertFalse(e.getMessage().contains("example"), e.getMessage());
        assertEquals(-1, e.position());
    }

    @Test
    void controlCharacterInAUrlHasNoOffsetIntoTheUrl() {
        CurlParseException e = assertThrows(CurlParseException.class,
                () -> Curl.parse("curl 'http://ok.example/a\u0001b'").build(FileAccess.DENY));
        assertEquals(-1, e.position());
        assertFalse(e.getMessage().contains("ok.example"));
    }

    // ---- positions: either an offset into the pasted text or -1 ----

    private static void assertPointsAt(String pasted, int position, char expected) {
        assertTrue(position >= 0 && position < pasted.length(), "position " + position);
        assertEquals(expected, pasted.charAt(position), "position " + position + " in " + pasted);
    }

    @Test
    void posixTokenizerErrorPointsIntoThePastedText() {
        String text = "\uFEFFcurl -H a\r\n  --data 'oops";
        CurlParseException e = assertThrows(CurlParseException.class, () -> Curl.parse(text));
        assertPointsAt(text, e.position(), '\'');
    }

    @Test
    void cmdTokenizerErrorPointsIntoThePastedText() {
        String text = "C:\\Users\\me>curl.exe ^\r\n  -d \"oops";
        CurlParseException e = assertThrows(CurlParseException.class, () -> Curl.parse(text));
        assertPointsAt(text, e.position(), '"');
        String bom = "\uFEFFcurl.exe \"a b\" ^\n\"x";
        CurlParseException e2 = assertThrows(CurlParseException.class, () -> new CmdTokenizer().tokenize(bom));
        assertPointsAt(bom, e2.position(), '"');
        assertEquals(bom.lastIndexOf('"'), e2.position());
    }

    @Test
    void commandParserAndBuilderErrorsHaveNoPosition() {
        for (String text : new String[] {"curl -d", "curl --header", "curl -X POST", "curl -F"}) {
            CurlParseException e = assertThrows(CurlParseException.class, () -> Curl.parse(text).build(FileAccess.DENY),
                    text);
            assertEquals(-1, e.position(), text);
        }
        CurlParseException e = assertThrows(CurlParseException.class, () -> Curl.parse("   "));
        assertEquals(-1, e.position());
        CurlParseException e2 = assertThrows(CurlParseException.class, () -> Curl.parse("echo hello"));
        assertEquals(-1, e2.position());
    }
}
