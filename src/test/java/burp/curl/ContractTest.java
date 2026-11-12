package burp.curl;

import static org.junit.jupiter.api.Assertions.*;

import java.io.IOException;
import org.junit.jupiter.api.Test;

class ContractTest {
    @Test
    void tokenRoundTripsUtf8() {
        String s = "héllo-世界-😀";
        Token t = Token.of(s);
        assertEquals(s, t.text());
        assertFalse(t.quoted());
        assertEquals(s, t.toString());
        assertEquals(Token.of(s), t);
    }

    @Test
    void tokenBytesAreDefensiveCopies() {
        byte[] in = {1, 2, 3};
        Token t = Token.of(in, true);
        in[0] = 9;
        byte[] out = t.bytes();
        assertEquals(1, out[0]);
        out[1] = 9;
        assertEquals(2, t.bytes()[1]);
        assertTrue(t.quoted());
        assertNotEquals(t, Token.of(new byte[] {1, 2, 3}, false));
    }

    @Test
    void takesArgPerKind() {
        for (ArgKind k : ArgKind.values()) {
            OptionSpec s = new OptionSpec("x", (char) 0, k, false, Handling.A);
            boolean expected = k == ArgKind.STRING || k == ArgKind.FILE || k == ArgKind.NUM;
            assertEquals(expected, s.takesArg(), k.name());
        }
    }

    @Test
    void denyThrows() {
        assertThrows(IOException.class, () -> FileAccess.DENY.read("/etc/passwd"));
    }

    @Test
    void warningSeverity() {
        assertEquals(Warning.Severity.NOTE, Warning.note("a").severity());
        assertEquals(Warning.Severity.LOSSY, Warning.lossy("b").severity());
        assertEquals("b", Warning.lossy("b").message());
    }
}
