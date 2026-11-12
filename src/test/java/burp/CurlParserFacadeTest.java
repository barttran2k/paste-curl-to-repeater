package burp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

import burp.api.montoya.http.message.HttpHeader;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.util.List;
import org.junit.jupiter.api.Test;

/** Behaviour of the legacy facade that CurlParserTest does not pin. */
class CurlParserFacadeTest {

    @Test
    void returnsNullWhenNothingParses() {
        assertNull(CurlParser.parseCurlCommand("echo hello"));
        assertNull(CurlParser.parseCurlCommand(""));
        assertNull(CurlParser.parseCurlCommand("curl -X POST"));
    }

    @Test
    void portIsOmittedOnlyForTheSchemeDefault() {
        assertEquals("https://h:80/a", CurlParser.parseCurlCommand("curl https://h:80/a").getBaseUrl());
        assertEquals("http://h:443/a", CurlParser.parseCurlCommand("curl http://h:443/a").getBaseUrl());
        assertEquals("https://h/a", CurlParser.parseCurlCommand("curl https://h:443/a").getBaseUrl());
        assertEquals("http://h/a", CurlParser.parseCurlCommand("curl http://h:80/a").getBaseUrl());
        assertEquals(-1, CurlParser.parseCurlCommand("curl http://h/a").getPort());
        assertEquals(8080, CurlParser.parseCurlCommand("curl http://h:8080/a").getPort());
    }

    @Test
    void ipv6HostGetsBracketsInTheBaseUrl() {
        CurlParser.CurlRequest r = CurlParser.parseCurlCommand("curl 'http://[::1]:8080/a?b=c'");
        assertEquals("::1", r.getHost());
        assertEquals("http://[::1]:8080/a?b=c", r.getBaseUrl());
    }

    @Test
    void headersAreOnlyTheTypedOnesAndTrimmed() {
        CurlParser.CurlRequest r = CurlParser.parseCurlCommand(
                "curl -u a:b -A ua -b c=d --compressed -H '  X-A :  v  ' -H 'Name;' -H 'nocolon' http://h/x");
        List<HttpHeader> h = r.getHeaders();
        assertEquals(1, h.size());
        assertEquals("X-A", h.get(0).name());
        assertEquals("v", h.get(0).value());
    }

    @Test
    void methodAndBody() {
        CurlParser.CurlRequest r = CurlParser.parseCurlCommand("curl -d a=1 -d b=2 --data-urlencode 'c=d e' http://h/x");
        assertEquals("POST", r.getMethod());
        assertEquals("a=1&b=2&c=d+e", r.getBody());
        CurlParser.CurlRequest g = CurlParser.parseCurlCommand("curl http://h/x");
        assertEquals("GET", g.getMethod());
        assertEquals("", g.getBody());
        assertNotNull(g.getHeaders());
    }

    @Test
    void localFilesAreNeverReadThroughTheFacade() {
        CurlParser.CurlRequest r = CurlParser.parseCurlCommand("curl -d @/etc/passwd http://h/x");
        assertEquals("<<FILE: /etc/passwd>>", r.getBody());
    }

    @Test
    void doesNotPrintTheCommand() {
        PrintStream old = System.out;
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        System.setOut(new PrintStream(buf));
        try {
            CurlParser.parseCurlCommand("curl -H 'Authorization: Bearer SECRET' http://h/x");
        } finally {
            System.setOut(old);
        }
        assertEquals("", buf.toString());
    }
}
