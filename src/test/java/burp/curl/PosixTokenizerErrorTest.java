package burp.curl;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;

class PosixTokenizerErrorTest {
    private static CurlParseException err(String in) {
        return assertThrows(CurlParseException.class, () -> new PosixTokenizer().tokenize(in));
    }

    @Test
    void unterminatedSingleQuote() {
        CurlParseException e = err("curl 'abc");
        assertEquals(5, e.position());
        assertTrue(e.getMessage().toLowerCase().contains("quote"));
    }

    @Test
    void unterminatedDoubleQuote() {
        assertEquals(7, err("curl a \"abc \\\" def").position());
    }

    @Test
    void unterminatedAnsiC() {
        assertEquals(5, err("curl $'abc\\'").position());
    }

    @Test
    void unterminatedCommandSubstitution() {
        CurlParseException e = err("curl $(echo a");
        assertEquals(5, e.position());
        assertTrue(e.getMessage().contains("$("));
        assertEquals(6, err("curl \"$(echo a").position());
    }

    @Test
    void unterminatedBraceAndBacktick() {
        assertEquals(5, err("curl ${A").position());
        assertEquals(5, err("curl `date").position());
    }

    @Test
    void unterminatedHeredoc() {
        CurlParseException e = err("curl -d @- <<EOF\nbody\n");
        assertEquals(11, e.position());
        assertTrue(e.getMessage().toLowerCase().contains("heredoc"));
    }

    @Test
    void unterminatedCurlyQuote() {
        assertEquals(5, err("curl \u2018abc").position());
    }

    @Test
    void positionMapsBackToOriginalAfterCrlfAndBom() {
        assertEquals(7, err("\uFEFFcurl\r\n'x").position());
    }

    @Test
    void positionAfterPromptStrip() {
        assertEquals(7, err("$ curl 'x").position());
    }
}
