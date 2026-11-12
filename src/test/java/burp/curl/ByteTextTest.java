package burp.curl;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.nio.charset.StandardCharsets;
import java.util.Random;
import org.junit.jupiter.api.Test;

class ByteTextTest {
    @Test
    void validUtf8DecodesToOrdinaryText() {
        assertEquals("café ễ 😀", ByteText.decode("café ễ 😀".getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void invalidBytesBecomeEscapesAndComeBackUnchanged() {
        byte[] b = {'a', (byte) 0xe9, 'b', (byte) 0xff, (byte) 0xfe, (byte) 0xc3, (byte) 0xed, (byte) 0xa0, (byte) 0x80};
        String s = ByteText.decode(b);
        assertEquals('a', s.charAt(0));
        assertEquals('\udce9', s.charAt(1));
        assertArrayEquals(b, ByteText.encode(s));
    }

    @Test
    void everyByteSequenceRoundTrips() {
        Random rnd = new Random(7);
        for (int n = 0; n < 5000; n++) {
            byte[] b = new byte[rnd.nextInt(40)];
            for (int i = 0; i < b.length; i++) {
                b[i] = rnd.nextBoolean() ? (byte) rnd.nextInt(256) : (byte) (0x80 + rnd.nextInt(0x80));
            }
            assertArrayEquals(b, ByteText.encode(ByteText.decode(b)));
        }
        byte[] all = new byte[256];
        for (int i = 0; i < 256; i++) {
            all[i] = (byte) i;
        }
        assertArrayEquals(all, ByteText.encode(ByteText.decode(all)));
    }

    @Test
    void displayReplacesEscapesAndKeepsText() {
        assertEquals("caf� é", ByteText.display(ByteText.decode(new byte[] {'c', 'a', 'f', (byte) 0xe9, ' ', (byte) 0xc3, (byte) 0xa9})));
    }

    @Test
    void unrelatedLoneSurrogateEncodesAsReplacementCharacter() {
        assertArrayEquals(new byte[] {(byte) 0xef, (byte) 0xbf, (byte) 0xbd}, ByteText.encode("\ud800"));
    }
}
