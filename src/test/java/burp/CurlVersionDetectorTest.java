package burp;

import burp.curl.CurlSettings;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

class CurlVersionDetectorTest {
    static final String REAL = "curl 8.7.1 (x86_64-apple-darwin26.0) libcurl/8.7.1 (SecureTransport) LibreSSL/3.3.6\n"
            + "Release-Date: 2024-03-27\nProtocols: dict file ftp\n";

    // ---- parsing ----

    @Test
    void parsesPlainDevAndOddVersions() {
        assertEquals("8.7.1", CurlVersionDetector.parseVersion(REAL));
        assertEquals("8.12.0-DEV", CurlVersionDetector.parseVersion("curl 8.12.0-DEV (x86_64-pc-linux-gnu) libcurl/8.12.0-DEV\n"));
        assertEquals("7.81.0", CurlVersionDetector.parseVersion("curl 7.81.0 (x86_64-pc-linux-gnu)\r\nRelease-Date: x\r\n"));
        assertEquals("8.5.0", CurlVersionDetector.parseVersion("  curl   8.5.0  \n"));
        assertEquals("8.9", CurlVersionDetector.parseVersion("curl 8.9 (x)"));
    }

    @Test
    void garbageIsRejected() {
        assertNull(CurlVersionDetector.parseVersion(null));
        assertNull(CurlVersionDetector.parseVersion(""));
        assertNull(CurlVersionDetector.parseVersion("   \n"));
        assertNull(CurlVersionDetector.parseVersion("wget 1.21"));
        assertNull(CurlVersionDetector.parseVersion("curl"));
        assertNull(CurlVersionDetector.parseVersion("curl: command not found"));
        assertNull(CurlVersionDetector.parseVersion("curl abc"));
        assertNull(CurlVersionDetector.parseVersion("curl 8.7.1\r\nX: y"
                .replace("8.7.1", "8.7.1\r\nInjected: yes").replace("curl 8", "xcurl 8")));
        assertNull(CurlVersionDetector.parseVersion("Release-Date: x\ncurl 8.7.1\n"));
    }

    @Test
    void aVersionWithHeaderInjectionCharactersIsNotUsable() {
        assertFalse(CurlSettings.isUsableVersion("8.7.1\r\nX: y"));
        assertFalse(CurlSettings.isUsableVersion("8.7.1 x"));
        assertEquals(CurlSettings.DEFAULT_CURL_VERSION, new CurlSettings("8.7.1\r\nX: y", "src").curlVersion());
        assertEquals(CurlSettings.DEFAULT_CURL_VERSION, new CurlSettings(null, null).curlVersion());
    }

    // ---- detection with a fake process runner ----

    static final Path USR_BIN = Paths.get("/usr/bin/curl");
    static final Path BREW = Paths.get("/opt/homebrew/bin/curl");

    static CurlVersionDetector detector(CurlVersionDetector.ProcessRunner r, String path, Set<Path> existing) {
        return new CurlVersionDetector(r, Map.of("PATH", path)::get, existing::contains, false);
    }

    @Test
    void usesTheFirstCurlOnPathAndSaysWhere() {
        List<List<String>> calls = new ArrayList<>();
        CurlVersionDetector d = detector((argv, t) -> {
            calls.add(argv);
            return new CurlVersionDetector.Output(true, 0, "curl 8.9.1 (x)\n");
        }, "/nonexistent:/opt/homebrew/bin:/usr/bin", Set.of(BREW, USR_BIN));
        CurlSettings s = d.detect();
        assertEquals("8.9.1", s.curlVersion());
        assertEquals("version of the curl found at " + BREW, s.versionSource());
        assertEquals(List.of(List.of(BREW.toString(), "--version")), calls);
    }

    @Test
    void fallsBackToWellKnownLocationsWhenPathHasNoCurl() {
        CurlVersionDetector d = detector((argv, t) -> new CurlVersionDetector.Output(true, 0, "curl 8.4.0 (x)"),
                "/somewhere/else", Set.of(USR_BIN));
        assertEquals("version of the curl found at " + USR_BIN, d.detect().versionSource());
        assertEquals("8.4.0", d.detect().curlVersion());
    }

    @Test
    void relativePathEntriesAreIgnored() {
        List<List<String>> calls = new ArrayList<>();
        CurlVersionDetector d = new CurlVersionDetector((argv, t) -> {
            calls.add(argv);
            return new CurlVersionDetector.Output(true, 0, "curl 8.4.0");
        }, Map.of("PATH", ".:bin::")::get, p -> true, false);
        d.detect();
        assertTrue(calls.get(0).get(0).startsWith("/"), calls.toString());
    }

    @Test
    void nextCandidateIsTriedWhenTheFirstIsUnusable() {
        AtomicInteger n = new AtomicInteger();
        CurlVersionDetector d = detector((argv, t) -> n.getAndIncrement() == 0
                ? new CurlVersionDetector.Output(true, 0, "garbage")
                : new CurlVersionDetector.Output(true, 0, "curl 8.2.0 (x)"),
                "/opt/homebrew/bin:/usr/bin", Set.of(BREW, USR_BIN));
        CurlSettings s = d.detect();
        assertEquals("8.2.0", s.curlVersion());
        assertEquals("version of the curl found at " + USR_BIN, s.versionSource());
    }

    private static void assertBuiltIn(CurlSettings s, String reasonPart) {
        assertEquals(CurlSettings.DEFAULT_CURL_VERSION, s.curlVersion());
        assertTrue(s.versionSource().startsWith("built-in default"), s.versionSource());
        assertTrue(s.versionSource().contains(reasonPart), s.versionSource());
    }

    @Test
    void nonZeroExitTimeoutMissingBinaryAndEmptyOutputGiveTheBuiltInDefault() {
        assertBuiltIn(detector((a, t) -> new CurlVersionDetector.Output(true, 2, "curl 9.9.9"), "/usr/bin",
                Set.of(USR_BIN)).detect(), "no usable version");
        assertBuiltIn(detector((a, t) -> new CurlVersionDetector.Output(false, -1, ""), "/usr/bin",
                Set.of(USR_BIN)).detect(), "no usable version");
        assertBuiltIn(detector((a, t) -> new CurlVersionDetector.Output(true, 0, ""), "/usr/bin",
                Set.of(USR_BIN)).detect(), "no usable version");
        assertBuiltIn(detector((a, t) -> new CurlVersionDetector.Output(true, 0, "garbage"), "/usr/bin",
                Set.of(USR_BIN)).detect(), "no usable version");
        assertBuiltIn(detector((a, t) -> { throw new IOException("cannot start"); }, "/usr/bin",
                Set.of(USR_BIN)).detect(), "no usable version");
        assertBuiltIn(detector((a, t) -> { throw new IllegalStateException("boom"); }, "/usr/bin",
                Set.of(USR_BIN)).detect(), "no usable version");
        assertBuiltIn(detector((a, t) -> null, "/usr/bin", Set.of(USR_BIN)).detect(), "no usable version");
        assertBuiltIn(detector((a, t) -> fail("must not run"), "/usr/bin", Set.of()).detect(),
                "no curl binary was found");
        assertBuiltIn(new CurlVersionDetector((a, t) -> fail("must not run"), k -> null, p -> false, false).detect(),
                "no curl binary was found");
    }

    @Test
    void theArgumentListIsFixedAndHasTheTimeout() {
        List<Long> timeouts = new ArrayList<>();
        List<List<String>> argvs = new ArrayList<>();
        detector((argv, t) -> {
            argvs.add(argv);
            timeouts.add(t);
            return new CurlVersionDetector.Output(true, 0, REAL);
        }, "/usr/bin", Set.of(USR_BIN)).detect();
        assertEquals(List.of(3000L), timeouts);
        assertEquals(List.of("/usr/bin/curl", "--version"), argvs.get(0));
    }

    @Test
    void windowsLooksForCurlExeInPathAndSystem32() {
        Path sys = Paths.get("/win/System32/curl.exe");
        List<String> tried = new ArrayList<>();
        CurlVersionDetector d = new CurlVersionDetector((argv, t) -> {
            tried.add(argv.get(0));
            return new CurlVersionDetector.Output(true, 0, "curl 8.4.0");
        }, Map.of("PATH", "/nowhere", "SystemRoot", "/win")::get, sys::equals, true);
        CurlSettings s = d.detect();
        assertEquals(List.of(sys.toString()), tried);
        assertTrue(s.versionSource().endsWith("curl.exe"), s.versionSource());
    }

    // ---- background detection ----

    @Test
    void beforeItStartsAndWhileItRunsThePasteGetsTheBuiltInDefault() throws Exception {
        CountDownLatch release = new CountDownLatch(1);
        CountDownLatch started = new CountDownLatch(1);
        AtomicInteger runs = new AtomicInteger();
        CurlVersionDetector d = detector((a, t) -> {
            runs.incrementAndGet();
            started.countDown();
            try {
                release.await();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            return new CurlVersionDetector.Output(true, 0, "curl 8.1.1");
        }, "/usr/bin", Set.of(USR_BIN));
        assertBuiltIn(d.settings(10), "not looked for");
        d.startInBackground();
        d.startInBackground();
        assertTrue(started.await(2, java.util.concurrent.TimeUnit.SECONDS));
        long t0 = System.nanoTime();
        assertBuiltIn(d.settings(60), "had not finished");
        assertTrue((System.nanoTime() - t0) / 1_000_000 < 1000);
        release.countDown();
        assertEquals("8.1.1", d.settings(2000).curlVersion());
        for (int i = 0; i < 5; i++) {
            d.settings(10);
        }
        assertEquals(1, runs.get(), "the process runs once, not per paste");
    }

    @Test
    void theDetectionThreadIsADaemon() throws Exception {
        List<Boolean> daemon = new ArrayList<>();
        CurlVersionDetector d = detector((a, t) -> {
            daemon.add(Thread.currentThread().isDaemon());
            return new CurlVersionDetector.Output(true, 0, "curl 8.1.1");
        }, "/usr/bin", Set.of(USR_BIN));
        d.startInBackground();
        d.settings(2000);
        assertEquals(List.of(true), daemon);
    }

    // ---- the real binary ----

    @Test
    void realDetectionMatchesTheUserAgentTheRealCurlSends() throws Exception {
        CurlSettings s = new CurlVersionDetector().detect();
        Assumptions.assumeTrue(s.versionSource().startsWith("version of the curl found at"),
                "no curl on this machine: " + s.versionSource());
        String sent = userAgentSentByRealCurl(Paths.get(s.versionSource().substring("version of the curl found at ".length())));
        assertEquals(s.defaultUserAgent(), sent);
    }

    @Test
    void theRealRunnerTimesOutAndDestroysTheProcess() throws Exception {
        Path sleep = Paths.get("/bin/sleep");
        Assumptions.assumeTrue(sleep.toFile().canExecute());
        long t0 = System.nanoTime();
        CurlVersionDetector.Output o = CurlVersionDetector.runProcess(List.of(sleep.toString(), "30"), 300);
        assertFalse(o.finished());
        assertTrue((System.nanoTime() - t0) / 1_000_000 < 5000);
    }

    @Test
    void theRealRunnerReportsAMissingBinaryAsAnIoException() {
        assertThrows(IOException.class,
                () -> CurlVersionDetector.runProcess(List.of("/definitely/not/here/curl", "--version"), 300));
    }

    @Test
    void theRealRunnerCollectsStdoutAndTheExitCode() throws Exception {
        Path echo = Paths.get("/bin/echo");
        Assumptions.assumeTrue(echo.toFile().canExecute());
        CurlVersionDetector.Output o = CurlVersionDetector.runProcess(List.of(echo.toString(), "curl 1.2.3"), 3000);
        assertTrue(o.finished());
        assertEquals(0, o.exitCode());
        assertEquals("1.2.3", CurlVersionDetector.parseVersion(o.stdout()));
    }

    static String userAgentSentByRealCurl(Path curl) throws Exception {
        try (ServerSocket server = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            server.setSoTimeout(5000);
            Process p = new ProcessBuilder(curl.toString(), "-s", "-m", "3", "http://127.0.0.1:" + server.getLocalPort() + "/")
                    .redirectErrorStream(true).start();
            try (Socket c = server.accept()) {
                c.setSoTimeout(3000);
                InputStream in = c.getInputStream();
                ByteArrayOutputStream head = new ByteArrayOutputStream();
                int b;
                while ((b = in.read()) >= 0) {
                    head.write(b);
                    String s = head.toString(StandardCharsets.ISO_8859_1);
                    if (s.endsWith("\r\n\r\n")) {
                        break;
                    }
                }
                c.getOutputStream().write("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".getBytes(StandardCharsets.ISO_8859_1));
                for (String line : head.toString(StandardCharsets.ISO_8859_1).split("\r\n")) {
                    if (line.startsWith("User-Agent: ")) {
                        return line.substring("User-Agent: ".length());
                    }
                }
                return null;
            } finally {
                p.destroyForcibly();
            }
        }
    }
}
