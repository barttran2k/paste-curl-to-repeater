package burp.curl;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

/** {@link CurlDate} against the values the real curl 8.7.1 sent for {@code -z} (measured, see the resource). */
class CurlDateTest {
    @Test
    void matchesMeasuredCurlBehaviour() throws Exception {
        int n = 0;
        try (InputStream in = CurlDateTest.class.getResourceAsStream("/curl-dates.tsv");
             BufferedReader r = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8))) {
            String line;
            while ((line = r.readLine()) != null) {
                if (line.startsWith("#") || line.isEmpty()) {
                    continue;
                }
                int tab = line.lastIndexOf('\t');
                String input = line.substring(0, tab);
                String expected = line.substring(tab + 1);
                Long t = CurlDate.parse(input);
                String actual = t == null ? "(none)" : CurlDate.format(t);
                assertEquals(expected, actual, "input: '" + input + "'");
                n++;
            }
        }
        assertTrue(n > 90, "rows: " + n);
    }

    @Test
    void formatsRfc1123() {
        assertEquals("Thu, 01 Jan 1970 00:00:00 GMT", CurlDate.format(0));
        assertEquals("Sun, 06 Nov 1994 08:49:37 GMT", CurlDate.format(784111777L));
    }

    @Test
    void neverThrowsOnGarbage() {
        for (String s : new String[] {"", " ", "::", "99999999999999999999", "1 Jan 999999999", "Jan 1 -5",
                "äö", "+", "12:", ":12", "1:2:3:4:5:6:7", "31 Dec 999999999 23:59:60"}) {
            CurlDate.parse(s);
        }
    }
}
