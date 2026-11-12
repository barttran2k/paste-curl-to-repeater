package burp.curl;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.List;
import org.junit.jupiter.api.Test;

/** Argument bytes that are not UTF-8 reach the wire unchanged (no real curl needed; the corpus compares with curl). */
class WireBytesTest {
    private static RequestDetails one(String command) throws CurlParseException {
        return Curl.parseAndBuild(command, null).get(0);
    }

    private static String wire(RequestDetails d) {
        return new String(d.request().raw(), StandardCharsets.ISO_8859_1);
    }

    @Test
    void headerValueKeepsItsByte() throws Exception {
        String w = wire(one("curl http://h.test/ -H $'X-L: caf\\xe9'"));
        assertTrue(w.contains("\r\nX-L: café\r\n"), w);
        assertFalse(w.contains("ï¿½"), w);
    }

    @Test
    void typedHeadersAreReadableText() throws Exception {
        RequestDetails d = one("curl http://h.test/ -H $'X-L: caf\\xe9' -H 'X-U: é'");
        assertEquals(List.of("X-L: caf�", "X-U: é"), d.typedHeaders());
        assertTrue(wire(d).contains("\r\nX-U: Ã©\r\n"));
    }

    @Test
    void everyWireArgumentKeepsItsBytes() throws Exception {
        String w = wire(one("curl http://h.test/p$'\\xe9'?q=$'\\xe9' -b $'a=\\xe9' -A $'\\xe9' -e $'\\xe9' "
                + "-u $'\\xe9:\\xe9' -r $'1\\xe9' -X $'M\\xe9'"));
        assertTrue(w.startsWith("Mé /p%e9?q=é HTTP/1.1\r\n"), w);
        assertTrue(w.contains("\r\nCookie: a=é\r\n"), w);
        assertTrue(w.contains("\r\nUser-Agent: é\r\n"), w);
        assertTrue(w.contains("\r\nReferer: é\r\n"), w);
        assertTrue(w.contains("\r\nRange: bytes=1é\r\n"), w);
        String b64 = java.util.Base64.getEncoder().encodeToString(new byte[] {(byte) 0xe9, ':', (byte) 0xe9});
        assertTrue(w.contains("\r\nAuthorization: Basic " + b64 + "\r\n"), w);
    }

    @Test
    void formFieldsKeepTheirBytes() throws Exception {
        String w = wire(one("curl http://h.test/ -F $'n\\xe9=v\\xe9'"));
        assertTrue(w.contains("name=\"né\""), w);
        assertTrue(w.contains("\r\n\r\nvé\r\n"), w);
    }

    @Test
    void warningsStayReadable() throws Exception {
        RequestDetails d = one("curl http://h.test/ -u $'us\\xe9r'");
        for (Warning x : d.request().warnings()) {
            assertFalse(x.message().chars().anyMatch(c -> c >= 0xdc00 && c <= 0xdfff), x.message());
        }
        assertTrue(d.request().warnings().stream().anyMatch(x -> x.message().contains("-u")));
    }
}
