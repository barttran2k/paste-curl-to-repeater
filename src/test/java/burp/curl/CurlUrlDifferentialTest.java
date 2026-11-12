package burp.curl;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.IDN;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;

/** Runs the real curl against a local capture server and compares what it sends with {@link CurlUrl}. */
class CurlUrlDifferentialTest {

    /** What the capture server saw. */
    static final class Captured {
        int exit;
        String stderr = "";
        /** raw request bytes, null when curl never connected */
        byte[] raw;

        String wire() {
            return new String(raw, StandardCharsets.ISO_8859_1);
        }

        String header(String name) {
            String w = wire();
            int end = w.indexOf("\r\n\r\n");
            String head = end >= 0 ? w.substring(0, end) : w;
            for (String line : head.split("\r\n")) {
                if (line.regionMatches(true, 0, name + ":", 0, name.length() + 1)) {
                    return line.substring(name.length() + 1).trim();
                }
            }
            return null;
        }

        String requestLine() {
            String w = wire();
            return w.substring(0, w.indexOf("\r\n"));
        }

        byte[] body() {
            String w = wire();
            int end = w.indexOf("\r\n\r\n");
            byte[] all = raw;
            return java.util.Arrays.copyOfRange(all, end + 4, all.length);
        }
    }

    static boolean curlAvailable() {
        try {
            Process p = new ProcessBuilder("curl", "--version").redirectErrorStream(true).start();
            p.getInputStream().readAllBytes();
            return p.waitFor(10, TimeUnit.SECONDS) && p.exitValue() == 0;
        } catch (IOException | InterruptedException e) {
            return false;
        }
    }

    /** Runs curl with {@code --connect-to} pointing at a 127.0.0.1 capture server. */
    static Captured capture(String... args) throws Exception {
        Captured result = new Captured();
        try (ServerSocket ss = new ServerSocket(0, 1, InetAddress.getByName("127.0.0.1"))) {
            Thread t = new Thread(() -> serve(ss, result));
            t.setDaemon(true);
            t.start();
            List<String> cmd = new ArrayList<>(List.of("curl", "-sS", "-g", "--max-time", "8", "--connect-to",
                    "::127.0.0.1:" + ss.getLocalPort()));
            cmd.addAll(List.of(args));
            Process p = new ProcessBuilder(cmd).redirectErrorStream(true).start();
            byte[] out = p.getInputStream().readAllBytes();
            Assumptions.assumeTrue(p.waitFor(20, TimeUnit.SECONDS), "curl timed out");
            result.exit = p.exitValue();
            result.stderr = new String(out, StandardCharsets.UTF_8);
            ss.close();
            t.join(5000);
        }
        return result;
    }

    private static void serve(ServerSocket ss, Captured result) {
        try (Socket s = ss.accept()) {
            s.setSoTimeout(5000);
            InputStream in = s.getInputStream();
            ByteArrayOutputStream buf = new ByteArrayOutputStream();
            int headEnd = -1;
            int need = -1;
            byte[] chunk = new byte[8192];
            while (true) {
                if (headEnd < 0) {
                    byte[] cur = buf.toByteArray();
                    String w = new String(cur, StandardCharsets.ISO_8859_1);
                    int i = w.indexOf("\r\n\r\n");
                    if (i >= 0) {
                        headEnd = i + 4;
                        need = 0;
                        for (String line : w.substring(0, i).split("\r\n")) {
                            if (line.regionMatches(true, 0, "Content-Length:", 0, 15)) {
                                need = Integer.parseInt(line.substring(15).trim());
                            }
                        }
                    }
                }
                if (headEnd >= 0 && buf.size() >= headEnd + need) {
                    break;
                }
                int n = in.read(chunk);
                if (n < 0) {
                    break;
                }
                buf.write(chunk, 0, n);
            }
            result.raw = buf.toByteArray();
            s.getOutputStream().write("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".getBytes(StandardCharsets.US_ASCII));
            s.getOutputStream().flush();
        } catch (IOException e) {
            // closed without a connection: curl rejected the URL
        }
    }

    private static String wire(String s) {
        return new String(s.getBytes(StandardCharsets.UTF_8), StandardCharsets.ISO_8859_1);
    }

    /** {url, extra curl args...} */
    private static final String[][] CASES = {
        {"http://127.0.0.1:18765/a/../b/./c/%2e%2e/d?x=/../y#frag"},
        {"http://127.0.0.1:18765/a/../b/./c/%2e%2e/d?x=/../y#frag", "--path-as-is"},
        {"http://[::1]:18765/v6?x=[1]&y={a,b}"},
        {"127.0.0.1:18765/search"},
        {"http://usr:p%40ss@127.0.0.1:18765/u"},
        {"http://h.example"},
        {"http://h.example?x=1"},
        {"http://h.example/a/.."},
        {"http://h.example/a/."},
        {"http://h.example/../../x"},
        {"http://h.example/a/b/../../.."},
        {"http://h.example/a//../b"},
        {"http://h.example/a/./b/../../c/"},
        {"http://h.example/a/%2E/b/%2e%2E"},
        {"http://h.example/a/..%2f"},
        {"http://h.example/..a/a../.../b"},
        {"http://h.example/?a/../b"},
        {"http://h.example//a//b"},
        {"http://h.example/../a/./b/", "--path-as-is"},
        {"http://h.example/a\\b"},
        {"HTTP://H.Example/U"},
        {"http://h.example/é"},
        {"http://h.example/?q=é&ü"},
        {"http://h.example/a%zz%/%2"},
        {"http://h.example/a\"b<c>{d}|^`"},
        {"http://h.example/#"},
        {"http://h.example/?#f"},
        {"http://h.example/a?b?c#d?e#f"},
        {"http://h.example:80/"},
        {"http://h.example:0080/x"},
        {"http://h.example:8080/x"},
        {"http://h.example:/x"},
        {"http://h.example:0/"},
        {"http://h.example:00/"},
        {"http://h.example:65535/"},
        {"http://h.example:65536/"},
        {"http://h.example:-1/"},
        {"http://h.example:+80/"},
        {"http://h.example:abc/"},
        {"http://h.example:80:81/"},
        {"http://u@h.example/"},
        {"http://u:@h.example/"},
        {"http://:p@h.example/"},
        {"http://:@h.example/"},
        {"http://a%3Ab:c%3Ad@h.example/"},
        {"http://u:p:q@h.example/"},
        {"http://u:p%zz@h.example/"},
        {"http://u%0a:p@h.example/"},
        {"http://ü:ü@h.example/"},
        {"http://a@b@h.example/"},
        {"http://[::1]/"},
        {"http://[::1]:81/"},
        {"http://[::1]:80/"},
        {"http://[::1]:/"},
        {"http://[0:0:0:0:0:0:0:1]/"},
        {"http://[2001:DB8:0:0:0:0:0:1]/"},
        {"http://[2001:DB8::1]/"},
        {"http://[FE80::1]/"},
        {"http://[::FFFF:1.2.3.4]/"},
        {"http://[::ffff:0102:0304]/"},
        {"http://[1:0:0:2:0:0:0:3]/"},
        {"http://[FE80::1%25en0]/"},
        {"http://[::1%25]/"},
        {"http://[::1%lo0]/"},
        {"http://[]/"},
        {"http://[zz]/"},
        {"http://[1.2.3.4]/"},
        {"http://[::1]x/"},
        {"http://u:p@[::1]:81/"},
        {"http://127.1/"},
        {"http://0x7f.1/"},
        {"http://2130706433/"},
        {"http://017700000001/"},
        {"http://0/"},
        {"http://1.2.3/"},
        {"http://01.2.3.4/"},
        {"http://08.1.1.1/"},
        {"http://256.1.1.1/"},
        {"http://1.2.3.256/"},
        {"http://1.2.3.4.5/"},
        {"http://4294967296/"},
        {"http://0x/"},
        {"http://1.2.3.4./"},
        {"http://a.b.c.1/"},
        {"http://H.EXAMPLE./"},
        {"http://ex%61mple.com/"},
        {"http://a.com%2fx/"},
        {"http://a_b.com/"},
        {"http://a~b|c/"},
        {"http://a!b/"},
        {"http://a$b/"},
        {"http://a+b/"},
        {"http://a%b/"},
        {"http://a%00b/"},
        {"http://a..b/"},
        {"http://-a.com/"},
        {"http://bücher.de/"},
        {"http://BÜCHER.DE:81/"},
        {"http://xn--bcher-kva.de/"},
        {"http://h.example#f"},
        {"http://h.example?x"},
        {"http:/h.example/y"},
        {"http:///h.example/y"},
        {"http:////h.example/y"},
        {"http:h.example/y"},
        {"http://"},
        {"http://:81/"},
        {"//h.example/x"},
        {"/x"},
        {"h.example:8080"},
        {"h.example:80/x"},
        {"localhost/x"},
        {"a"},
        {":80"},
        {"1http://h.example/"},
        {"1http:/h.example"},
        {"h.example:/x"},
        {"1.2.3.4:/x"},
        {"1.2.3.4:/x", "--proto-default", "http"},
        {"h.example:", "--proto-default", "http"},
        {"h.example:80", "--proto-default", "http"},
        {"http://h.example:"},
        {"http://h.example:?x"},
        {"http://[::1]:"},
        {"ftp.example.com/x"},
        {"imap.example.com"},
        {"HTTP.example.com/x"},
        {"x.y:/a", "--proto-default", "http"},
    };

    @TestFactory
    Stream<DynamicTest> urlCasesAgainstRealCurl() {
        Assumptions.assumeTrue(curlAvailable(), "curl binary not found");
        return java.util.Arrays.stream(CASES).map(c -> DynamicTest.dynamicTest(String.join(" ", c), () -> check(c)));
    }

    private void check(String[] c) throws Exception {
        List<String> args = new ArrayList<>(List.of(c).subList(1, c.length));
        args.add(c[0]);
        boolean asIs = args.contains("--path-as-is");
        int pd = args.indexOf("--proto-default");
        String protoDefault = pd >= 0 ? args.get(pd + 1) : null;
        Captured got = capture(args.toArray(new String[0]));
        if (got.raw == null || got.raw.length == 0) {
            assertThrows(CurlParseException.class, () -> CurlUrl.parse(c[0], protoDefault, asIs),
                    "curl rejected it (exit " + got.exit + ": " + got.stderr.trim() + ")");
            return;
        }
        CurlUrl u = CurlUrl.parse(c[0], protoDefault, asIs);
        assertEquals(got.requestLine(), "GET " + wire(u.requestTarget()) + " HTTP/1.1", "request line");
        String curlHost = got.header("Host");
        String curlHostAscii = new String(curlHost.getBytes(StandardCharsets.ISO_8859_1), StandardCharsets.UTF_8);
        if (!curlHostAscii.chars().allMatch(ch -> ch < 0x80)) {
            // curl without libidn2 (macOS system curl) sends raw UTF-8; an IDN-enabled curl sends punycode
            int colon = curlHostAscii.lastIndexOf(':');
            String h = colon > curlHostAscii.indexOf(']') && curlHostAscii.indexOf('.') < colon
                    ? curlHostAscii.substring(0, colon) : curlHostAscii;
            String port = h.length() == curlHostAscii.length() ? "" : curlHostAscii.substring(colon);
            curlHostAscii = IDN.toASCII(h, IDN.ALLOW_UNASSIGNED) + port;
        }
        assertEquals(curlHostAscii, u.hostHeader(), "Host");
        String auth = got.header("Authorization");
        if (u.user() == null) {
            assertNull(auth, "Authorization");
        } else {
            String cred = u.user() + ":" + (u.password() == null ? "" : u.password());
            assertEquals("Basic " + Base64.getEncoder().encodeToString(cred.getBytes(StandardCharsets.UTF_8)), auth,
                    "Authorization");
        }
        assertTrue(got.exit == 0, got.stderr);
    }

    static int caseCount() {
        return CASES.length;
    }
}
