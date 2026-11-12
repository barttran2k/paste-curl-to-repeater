package burp.curl;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import burp.curl.testsupport.CaptureServer;
import burp.curl.testsupport.CurlRunner;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** The capture server, driven by the real curl. */
class CaptureServerTest {
    @TempDir
    Path wd;

    @BeforeEach
    void tools() {
        Assumptions.assumeTrue(CurlRunner.toolsAvailable(), "curl or bash >= 4.2 is missing");
    }

    private List<byte[]> run(String script) throws IOException {
        try (CaptureServer srv = CaptureServer.start()) {
            CurlRunner.Result r = CurlRunner.runShell(script.replace("__PORT__", Integer.toString(srv.port())), wd);
            srv.close();
            assertEquals(0, r.exit(), r.output());
            assertFalse(r.timedOut());
            return srv.requests();
        }
    }

    private static String s(byte[] b) {
        return new String(b, StandardCharsets.ISO_8859_1);
    }

    @Test
    void twoRequestsOnOneKeepAliveConnection() throws IOException {
        List<byte[]> reqs = run("curl -s http://127.0.0.1:__PORT__/one http://127.0.0.1:__PORT__/two\n");
        assertEquals(2, reqs.size());
        assertTrue(s(reqs.get(0)).startsWith("GET /one HTTP/1.1\r\n"));
        assertTrue(s(reqs.get(1)).startsWith("GET /two HTTP/1.1\r\n"));
    }

    @Test
    void severalConnectionsAndContentLengthBodies() throws IOException {
        List<byte[]> reqs = run("curl -s -d a=1 http://127.0.0.1:__PORT__/p1 --next -s -d 'b=22' http://127.0.0.1:__PORT__/p2\n"
                + "curl -s --http1.0 -d c=333 http://127.0.0.1:__PORT__/p3\n");
        assertEquals(3, reqs.size());
        assertTrue(s(reqs.get(0)).endsWith("\r\n\r\na=1"), s(reqs.get(0)));
        assertTrue(s(reqs.get(1)).endsWith("\r\n\r\nb=22"));
        assertTrue(s(reqs.get(2)).endsWith("\r\n\r\nc=333"));
    }

    @Test
    void chunkedUploadFromStdinKeepsTheChunkFraming() throws IOException {
        List<byte[]> reqs = run("curl -s -T - http://127.0.0.1:__PORT__/up <<< 'hello'\n");
        assertEquals(1, reqs.size());
        String w = s(reqs.get(0));
        assertTrue(w.startsWith("PUT /up HTTP/1.1\r\n"), w);
        assertTrue(w.contains("Transfer-Encoding: chunked\r\n"), w);
        assertTrue(w.endsWith("\r\n\r\n6\r\nhello\n\r\n0\r\n\r\n"), w);
    }

    @Test
    void headRequest() throws IOException {
        List<byte[]> reqs = run("curl -s -I http://127.0.0.1:__PORT__/h\n");
        assertEquals(1, reqs.size());
        assertTrue(s(reqs.get(0)).startsWith("HEAD /h HTTP/1.1\r\n"));
    }

    @Test
    void largeBodyTriggersExpectContinueAndIsFullyCaptured() throws IOException {
        List<byte[]> reqs = run("head -c 1500000 /dev/zero > big.bin\n"
                + "curl -s --data-binary @big.bin http://127.0.0.1:__PORT__/big\n");
        assertEquals(1, reqs.size());
        String w = s(reqs.get(0));
        assertTrue(w.contains("Expect: 100-continue\r\n"), w.substring(0, 300));
        assertTrue(w.contains("Content-Length: 1500000\r\n"));
        assertEquals(1_500_000, reqs.get(0).length - w.indexOf("\r\n\r\n") - 4);
    }

    @Test
    void ipv6Loopback() throws IOException {
        Assumptions.assumeTrue(CaptureServer.ipv6LoopbackAvailable(), "no IPv6 loopback");
        List<byte[]> reqs = run("curl -s 'http://[::1]:__PORT__/six' http://127.0.0.1:__PORT__/four\n");
        assertEquals(2, reqs.size());
        assertTrue(s(reqs.get(0)).startsWith("GET /six HTTP/1.1\r\nHost: [::1]:"), s(reqs.get(0)));
    }

    @Test
    void loopbackOnlyAnythingElseGoesToADeadProxy() throws IOException {
        try (CaptureServer srv = CaptureServer.start()) {
            CurlRunner.Result r = CurlRunner.runShell("curl -s --max-time 5 http://nothing.invalid/x\n", wd);
            srv.close();
            assertTrue(r.exit() != 0);
            assertEquals(0, srv.requests().size());
        }
    }
}
