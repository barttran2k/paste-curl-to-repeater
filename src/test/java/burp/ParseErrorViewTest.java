package burp;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class ParseErrorViewTest {
    static final String D = "·";

    @Test
    void lineAndColumnAreOneBased() {
        assertEquals("line 1, column 1", ParseErrorView.lineAndColumn("abc", 0));
        assertEquals("line 1, column 3", ParseErrorView.lineAndColumn("abc", 2));
        assertEquals("line 2, column 1", ParseErrorView.lineAndColumn("ab\ncd", 3));
        assertEquals("line 3, column 2", ParseErrorView.lineAndColumn("a\r\nb\r\ncd", 7));
        assertEquals("line 1, column 4", ParseErrorView.lineAndColumn("abc", 99));
        assertEquals("line 1, column 1", ParseErrorView.lineAndColumn("abc", -4));
    }

    @Test
    void everythingButStructureAndOptionsIsHidden() {
        // whitespace is kept, so word lengths stay visible
        String m = ParseErrorView.mask("curl -H 'Authorization: Bearer SECRET' --data-raw=abc \"x\\\"y$HOME\" \\\n  url");
        assertEquals(D.repeat(4) + " -H '" + D.repeat(14) + " " + D.repeat(6) + " " + D.repeat(6)
                + "' --data-raw=" + D.repeat(3) + " \"" + D + "\\\"" + D + "$" + D.repeat(4) + "\" \\\n  " + D.repeat(3), m);
    }

    @Test
    void optionWordsAreKeptOnlyWhenTheyAreCurlOptions() {
        assertEquals("-s", ParseErrorView.mask("-s"));
        assertEquals("-sSL", ParseErrorView.mask("-sSL"));
        assertEquals("-H" + D.repeat(6), ParseErrorView.mask("-HSECRET"));
        assertEquals("-u" + D.repeat(9), ParseErrorView.mask("-uuser:pass"));
        assertEquals(D.repeat(8), ParseErrorView.mask("+SECRETX"));
        assertEquals("--header", ParseErrorView.mask("--header"));
        assertEquals("--header=" + D + D + " " + D, ParseErrorView.mask("--header=a: b"));
        assertEquals(D.repeat(11), ParseErrorView.mask("--SECRET-xx"));
    }

    @Test
    void optionLookingWordsInsideQuotesAreHidden() {
        String m = ParseErrorView.mask("-H '--header x' --compressed");
        assertEquals("-H '" + D.repeat(8) + " " + D + "' --compressed", m);
    }

    @Test
    void excerptMarksPositionAndShowsNewlinesAsASymbol() {
        String text = "a".repeat(50) + "\nBAD\n" + "b".repeat(50);
        String ex = ParseErrorView.maskedExcerpt(text, 51);
        assertTrue(ex.startsWith("..."));
        assertTrue(ex.endsWith("..."));
        assertTrue(ex.contains(D.repeat(5) + "\u21b5 >>HERE<< " + D.repeat(3) + "\u21b5" + D.repeat(5)), ex);
        assertFalse(ex.contains("\n"));
        assertFalse(ex.contains("a"));
        assertFalse(ex.contains("B"));
        assertEquals(D + " >>HERE<< ", ParseErrorView.maskedExcerpt("x", 99));
        assertEquals(" >>HERE<< " + D + D, ParseErrorView.maskedExcerpt("xy", -5));
    }

    @Test
    void theExampleShape() {
        String text = "curl -H 'Auth: Bearer SECRET";
        assertEquals(D.repeat(4) + " -H '" + D.repeat(5) + " " + D.repeat(6) + " " + D.repeat(6) + " >>HERE<< ",
                ParseErrorView.maskedExcerpt(text, text.length()));
    }
}
