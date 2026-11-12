package burp.curl;

import static org.junit.jupiter.api.Assertions.*;

import java.util.List;
import org.junit.jupiter.api.Test;

class PosixTokenizerCurlyQuoteTest {
    private static final String LD = "“", RD = "”", LS = "‘", RS = "’";

    @Test
    void apostropheInsideCurlySingleAndCurlyInsideRegularQuotes() throws Exception {
        TokenizeResult r = PosixTokenizerTest.tok("curl " + LD + "https://x/a b" + RD + " -H " + LS + "A: it" + RS + "s" + RS
                + " -d \"say " + LD + "hi" + RD + "\"");
        assertEquals(List.of("curl", "https://x/a b", "-H", "A: it" + RS + "s", "-d", "say " + LD + "hi" + RD),
                PosixTokenizerTest.argv(r.commands().get(0)));
        assertEquals(1, PosixTokenizerTest.notes(r));
    }

    @Test
    void jsonWithApostrophe() throws Exception {
        TokenizeResult r = PosixTokenizerTest.tok("curl -d " + LS + "{\"msg\":\"it" + RS + "s fine\"}" + RS);
        assertEquals(List.of("curl", "-d", "{\"msg\":\"it" + RS + "s fine\"}"), PosixTokenizerTest.argv(r.commands().get(0)));
    }

    @Test
    void plainAndTwoArguments() throws Exception {
        assertEquals(List.of("plain"), PosixTokenizerTest.argv(PosixTokenizerTest.tok(LS + "plain" + RS).commands().get(0)));
        assertEquals(List.of("a", "b"),
                PosixTokenizerTest.argv(PosixTokenizerTest.tok(LS + "a" + RS + " " + LS + "b" + RS).commands().get(0)));
        assertEquals(List.of("a", "b"),
                PosixTokenizerTest.argv(PosixTokenizerTest.tok(LD + "a" + RD + " " + LD + "b" + RD).commands().get(0)));
    }

    @Test
    void curlyDoubleContainingCurlyDoubleBeforeLetter() throws Exception {
        TokenizeResult r = PosixTokenizerTest.tok("x " + LD + "say " + LD + "hi" + RD + "there" + RD + " y");
        assertEquals(List.of("x", "say " + LD + "hi" + RD + "there", "y"), PosixTokenizerTest.argv(r.commands().get(0)));
    }

    @Test
    void terminatorCharsAfterClosingQuote() throws Exception {
        TokenizeResult r = PosixTokenizerTest.tok("a " + LS + "b" + RS + "; c " + LS + "d" + RS + "| e");
        assertEquals(3, r.commands().size());
        assertEquals(List.of("a", "b"), PosixTokenizerTest.argv(r.commands().get(0)));
    }

    @Test
    void stillUnterminated() {
        assertThrows(CurlParseException.class, () -> PosixTokenizerTest.tok("curl " + LS + "it" + RS + "s"));
        assertThrows(CurlParseException.class, () -> PosixTokenizerTest.tok("curl " + LD + "it" + RD + "s"));
    }
}
