package burp;

import burp.BrowserUserAgent.Os;
import burp.BrowserUserAgent.Output;
import burp.curl.CurlSettings;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.OptionalInt;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

class BrowserUserAgentTest {
    @TempDir
    Path tmp;

    static final String PLIST = """
            <?xml version="1.0" encoding="UTF-8"?>
            <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
            <plist version="1.0"><dict>
              <key>CFBundleName</key><string>Chrome</string>
              <key>CFBundleShortVersionString</key>
              <string>156.0.8078.81</string>
              <key>CFBundleVersion</key><string>8078.81</string>
            </dict></plist>
            """;

    static final LocalDate TODAY = LocalDate.of(2026, 11, 13);

    BrowserUserAgent detector(Os os, Path home, Map<String, String> env, BrowserUserAgent.ProcessRunner r, List<Path> linux) {
        return new BrowserUserAgent(os, home, tmp.resolve("system-applications"), env::get, r, () -> TODAY, linux);
    }

    // ---- templates ----

    @Test
    void osMapsToItsTemplate() {
        assertEquals("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36",
                BrowserUserAgent.userAgent(Os.of("Mac OS X"), 142));
        assertEquals("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36",
                BrowserUserAgent.userAgent(Os.of("Windows 11"), 142));
        assertEquals("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36",
                BrowserUserAgent.userAgent(Os.of("Linux"), 142));
        assertEquals(Os.LINUX, Os.of("FreeBSD"));
        assertEquals(Os.LINUX, Os.of(null));
        assertEquals(Os.MAC, Os.of("Darwin"));
    }

    // ---- parsing ----

    @Test
    void plistParsing() {
        assertEquals(OptionalInt.of(156), BrowserUserAgent.majorFromPlist(PLIST));
        assertEquals(OptionalInt.empty(), BrowserUserAgent.majorFromPlist("<plist><dict><key>CFBundleName</key><string>x</string></dict></plist>"));
        assertEquals(OptionalInt.empty(), BrowserUserAgent.majorFromPlist("not a plist <key>CFBundleShortVersionString"));
        assertEquals(OptionalInt.empty(), BrowserUserAgent.majorFromPlist("bplist00\u0000\u0001"));
        assertEquals(OptionalInt.empty(), BrowserUserAgent.majorFromPlist(""));
        assertEquals(OptionalInt.empty(), BrowserUserAgent.majorFromPlist(null));
        assertEquals(OptionalInt.empty(), BrowserUserAgent.majorFromPlist(
                "<key>CFBundleShortVersionString</key><string>abc</string>"));
        assertEquals(OptionalInt.empty(), BrowserUserAgent.majorFromPlist(
                "<key>CFBundleShortVersionString</key><string></string>"));
    }

    @Test
    void betaAndDevVersionStrings() {
        assertEquals(OptionalInt.of(157), BrowserUserAgent.majorFromVersion("157.0.8100.12 beta"));
        assertEquals(OptionalInt.of(158), BrowserUserAgent.majorFromVersion("158.0.8200.0 dev"));
        assertEquals(OptionalInt.of(159), BrowserUserAgent.majorFromVersion(" 159.0.8300.0 canary "));
        assertEquals(OptionalInt.of(99), BrowserUserAgent.majorFromVersion("99.0.4844.51"));
        assertEquals(OptionalInt.empty(), BrowserUserAgent.majorFromVersion("beta 157.0"));
        assertEquals(OptionalInt.empty(), BrowserUserAgent.majorFromVersion("7"));
        assertEquals(OptionalInt.empty(), BrowserUserAgent.majorFromVersion(null));
    }

    @Test
    void windowsDirectoryNames() throws IOException {
        Path app = tmp.resolve("Google/Chrome/Application");
        Files.createDirectories(app.resolve("141.0.7390.55"));
        Files.createDirectories(app.resolve("142.0.7444.60"));
        Files.createDirectories(app.resolve("SetupMetrics"));
        Files.createDirectories(app.resolve("143.0.1"));
        Files.writeString(app.resolve("chrome.exe"), "x");
        Files.writeString(app.resolve("150.0.0.1"), "a file, not a directory");
        assertEquals(OptionalInt.of(142), BrowserUserAgent.majorFromWindowsDir(app));
        assertEquals(OptionalInt.empty(), BrowserUserAgent.majorFromWindowsDir(tmp.resolve("missing")));
        Path empty = tmp.resolve("empty");
        Files.createDirectories(empty);
        assertEquals(OptionalInt.empty(), BrowserUserAgent.majorFromWindowsDir(empty));
    }

    @Test
    void linuxOutput() {
        assertEquals(OptionalInt.of(138), BrowserUserAgent.majorFromLinuxOutput("Google Chrome 138.0.7204.100 \n"));
        assertEquals(OptionalInt.of(138), BrowserUserAgent.majorFromLinuxOutput("Chromium 138.0.7204.100 built on Debian"));
        assertEquals(OptionalInt.empty(), BrowserUserAgent.majorFromLinuxOutput("bash: chromium: command not found"));
        assertEquals(OptionalInt.empty(), BrowserUserAgent.majorFromLinuxOutput(""));
        assertEquals(OptionalInt.empty(), BrowserUserAgent.majorFromLinuxOutput(null));
    }

    // ---- the date estimate, against Chrome stable release dates (Chromium Dash) ----

    private static final Object[][] RELEASES = {
        {138, "2025-06-24"}, {139, "2025-08-05"}, {140, "2025-09-02"}, {141, "2025-09-30"}, {142, "2025-10-28"},
        {143, "2025-12-02"}, {144, "2026-01-13"}, {145, "2026-02-10"}, {146, "2026-03-10"}, {147, "2026-04-07"},
        {148, "2026-05-05"}, {149, "2026-06-02"}, {150, "2026-06-30"}, {151, "2026-07-28"}, {152, "2026-08-25"},
        {153, "2026-09-08"}, {154, "2026-09-22"}, {155, "2026-10-06"}, {156, "2026-10-20"}, {157, "2026-11-03"},
        {158, "2026-11-17"}, {159, "2026-12-08"}, {160, "2027-01-05"},
    };

    @Test
    void estimateIsExactOnReleaseDaysFromChrome144() {
        for (Object[] r : RELEASES) {
            int major = (Integer) r[0];
            if (major >= 144 && major != 159 && major != 160) {
                LocalDate d = LocalDate.parse((String) r[1]);
                assertEquals(major, BrowserUserAgent.estimateMajor(d), "release day of " + major);
                assertEquals(major, BrowserUserAgent.estimateMajor(d.plusDays(13)), "13 days after " + major);
            }
        }
    }

    @Test
    void estimateIsWithinTwoMajorsOnEveryKnownReleaseDay() {
        for (Object[] r : RELEASES) {
            int major = (Integer) r[0];
            LocalDate d = LocalDate.parse((String) r[1]);
            assertTrue(Math.abs(BrowserUserAgent.estimateMajor(d) - major) <= 2, "release day of " + major);
        }
    }

    @Test
    void estimateOnTheDayBeforeANewMajorIsThePreviousOne() {
        assertEquals(152, BrowserUserAgent.estimateMajor(LocalDate.of(2026, 9, 7)));
        assertEquals(157, BrowserUserAgent.estimateMajor(LocalDate.of(2026, 11, 16)));
        assertEquals(157, BrowserUserAgent.estimateMajor(TODAY));
        assertEquals(158, BrowserUserAgent.estimateMajor(LocalDate.of(2026, 11, 17)));
    }

    // ---- the chain: installed Chrome first, then the date ----

    @Test
    void macReadsThePlistInTheUserApplicationsFolder() throws IOException {
        Path home = tmp.resolve("home");
        Path plist = home.resolve("Applications/Google Chrome.app/Contents/Info.plist");
        Files.createDirectories(plist.getParent());
        Files.writeString(plist, PLIST);
        CurlSettings s = detector(Os.MAC, home, Map.of(), (a, t) -> fail("no process on macOS"), List.of()).detect();
        assertEquals(BrowserUserAgent.userAgent(Os.MAC, 156), s.defaultUserAgent());
        assertEquals("User-Agent set to a browser value (Chrome 156, version of the installed Chrome); "
                + "curl itself would send its own curl/x.y.z", s.note());
    }

    @Test
    void thePlistInSystemApplicationsComesFirst() throws IOException {
        Path sys = tmp.resolve("system-applications/Google Chrome.app/Contents/Info.plist");
        Files.createDirectories(sys.getParent());
        Files.writeString(sys, PLIST.replace("156.0.8078.81", "150.0.1.2"));
        Path user = tmp.resolve("home/Applications/Google Chrome.app/Contents/Info.plist");
        Files.createDirectories(user.getParent());
        Files.writeString(user, PLIST);
        assertEquals(BrowserUserAgent.userAgent(Os.MAC, 150),
                detector(Os.MAC, tmp.resolve("home"), Map.of(), null, List.of()).detect().defaultUserAgent());
        Files.writeString(sys, "garbage");
        assertEquals(BrowserUserAgent.userAgent(Os.MAC, 156),
                detector(Os.MAC, tmp.resolve("home"), Map.of(), null, List.of()).detect().defaultUserAgent());
    }

    @Test
    void aMalformedOrMissingPlistFallsBackToTheDateEstimate() throws IOException {
        Path home = tmp.resolve("home");
        Path plist = home.resolve("Applications/Google Chrome.app/Contents/Info.plist");
        Files.createDirectories(plist.getParent());
        Files.writeString(plist, "<plist><dict><key>CFBundleShortVersionString</key><string>garbage</string>");
        CurlSettings bad = detector(Os.MAC, home, Map.of(), null, List.of()).detect();
        CurlSettings none = detector(Os.MAC, tmp.resolve("nohome"), Map.of(), null, List.of()).detect();
        for (CurlSettings s : List.of(bad, none)) {
            assertEquals(BrowserUserAgent.userAgent(Os.MAC, 157), s.defaultUserAgent());
            assertEquals("User-Agent set to a browser value (Chrome 157, estimated from the date; Chrome was not found); "
                    + "curl itself would send its own curl/x.y.z", s.note());
        }
    }

    @Test
    void anUnreadablePlistIsSkipped() throws IOException {
        Path home = tmp.resolve("home");
        Path plist = home.resolve("Applications/Google Chrome.app/Contents/Info.plist");
        Files.createDirectories(plist); // a directory where the file should be
        assertTrue(detector(Os.MAC, home, Map.of(), null, List.of()).detect().note().contains("estimated"));
    }

    @Test
    void windowsUsesProgramFilesThenX86ThenLocalAppData() throws IOException {
        Path pf = tmp.resolve("pf");
        Path x86 = tmp.resolve("x86");
        Path local = tmp.resolve("local");
        Files.createDirectories(local.resolve("Google/Chrome/Application/139.0.1.2"));
        Map<String, String> env = Map.of("ProgramFiles", pf.toString(), "ProgramFiles(x86)", x86.toString(),
                "LocalAppData", local.toString());
        CurlSettings s = detector(Os.WINDOWS, tmp, env, null, List.of()).detect();
        assertEquals(BrowserUserAgent.userAgent(Os.WINDOWS, 139), s.defaultUserAgent());
        Files.createDirectories(x86.resolve("Google/Chrome/Application/140.0.1.2"));
        assertEquals(BrowserUserAgent.userAgent(Os.WINDOWS, 140), detector(Os.WINDOWS, tmp, env, null, List.of()).detect().defaultUserAgent());
        Files.createDirectories(pf.resolve("Google/Chrome/Application/141.0.1.2"));
        assertEquals(BrowserUserAgent.userAgent(Os.WINDOWS, 141), detector(Os.WINDOWS, tmp, env, null, List.of()).detect().defaultUserAgent());
        assertEquals(BrowserUserAgent.userAgent(Os.WINDOWS, 157),
                detector(Os.WINDOWS, tmp, Map.of(), null, List.of()).detect().defaultUserAgent());
    }

    @Test
    void linuxAsksTheBrowsersInOrderWithAFixedArgumentList() throws IOException {
        Path a = tmp.resolve("google-chrome");
        Path b = tmp.resolve("chromium");
        Files.writeString(a, "#!/bin/sh\n");
        Files.writeString(b, "#!/bin/sh\n");
        Assumptions.assumeTrue(a.toFile().setExecutable(true) && b.toFile().setExecutable(true));
        List<List<String>> calls = new ArrayList<>();
        List<Long> timeouts = new ArrayList<>();
        CurlSettings s = detector(Os.LINUX, tmp, Map.of(), (argv, t) -> {
            calls.add(argv);
            timeouts.add(t);
            return argv.get(0).equals(a.toString()) ? new Output(true, 1, "") : new Output(true, 0, "Chromium 137.0.7151.68\n");
        }, List.of(tmp.resolve("missing"), a, b)).detect();
        assertEquals(List.of(List.of(a.toString(), "--version"), List.of(b.toString(), "--version")), calls);
        assertEquals(List.of(3000L, 3000L), timeouts);
        assertEquals(BrowserUserAgent.userAgent(Os.LINUX, 137), s.defaultUserAgent());
    }

    @Test
    void linuxTimeoutExceptionOrGarbageFallBackToTheEstimate() throws IOException {
        Path a = tmp.resolve("google-chrome");
        Files.writeString(a, "x");
        Assumptions.assumeTrue(a.toFile().setExecutable(true));
        for (BrowserUserAgent.ProcessRunner r : List.<BrowserUserAgent.ProcessRunner>of(
                (argv, t) -> new Output(false, -1, ""), (argv, t) -> { throw new IOException("x"); },
                (argv, t) -> { throw new IllegalStateException("x"); }, (argv, t) -> null,
                (argv, t) -> new Output(true, 0, "nonsense"))) {
            CurlSettings s = detector(Os.LINUX, tmp, Map.of(), r, List.of(a)).detect();
            assertEquals(BrowserUserAgent.userAgent(Os.LINUX, 157), s.defaultUserAgent());
            assertTrue(s.note().contains("estimated from the date; Chrome was not found"));
        }
    }

    // ---- background ----

    @Test
    void aPasteBeforeDetectionFinishesUsesTheEstimateAndTheProcessRunsOnce() throws Exception {
        Path a = tmp.resolve("google-chrome");
        Files.writeString(a, "x");
        Assumptions.assumeTrue(a.toFile().setExecutable(true));
        CountDownLatch release = new CountDownLatch(1);
        CountDownLatch started = new CountDownLatch(1);
        AtomicInteger runs = new AtomicInteger();
        List<Boolean> daemon = new ArrayList<>();
        BrowserUserAgent d = detector(Os.LINUX, tmp, Map.of(), (argv, t) -> {
            runs.incrementAndGet();
            daemon.add(Thread.currentThread().isDaemon());
            started.countDown();
            try {
                release.await();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            return new Output(true, 0, "Google Chrome 130.0.1.2");
        }, List.of(a));
        assertTrue(d.settings(10).note().contains("was not looked for"));
        d.startInBackground();
        d.startInBackground();
        assertTrue(started.await(2, TimeUnit.SECONDS));
        long t0 = System.nanoTime();
        CurlSettings early = d.settings(60);
        assertTrue((System.nanoTime() - t0) / 1_000_000 < 1000);
        assertEquals(BrowserUserAgent.userAgent(Os.LINUX, 157), early.defaultUserAgent());
        assertTrue(early.note().contains("had not finished"));
        release.countDown();
        assertEquals(BrowserUserAgent.userAgent(Os.LINUX, 130), d.settings(2000).defaultUserAgent());
        for (int i = 0; i < 5; i++) {
            d.settings(10);
        }
        assertEquals(1, runs.get());
        assertEquals(List.of(true), daemon);
    }

    // ---- the real machine ----

    @Test
    void thisMachineGetsAWellFormedUserAgent() {
        CurlSettings s = BrowserUserAgent.forThisMachine().detect();
        assertTrue(s.defaultUserAgent().matches("Mozilla/5\\.0 \\([^)]+\\) AppleWebKit/537\\.36 \\(KHTML, like Gecko\\) "
                + "Chrome/\\d+\\.0\\.0\\.0 Safari/537\\.36"), s.defaultUserAgent());
        assertNotNull(s.note());
        System.out.println("THIS MACHINE: " + s.defaultUserAgent() + " | " + s.note());
    }

    @Test
    void theRealRunnerTimesOutAndReportsAMissingBinary() throws Exception {
        Path sleep = Paths.get("/bin/sleep");
        Assumptions.assumeTrue(sleep.toFile().canExecute());
        long t0 = System.nanoTime();
        assertFalse(BrowserUserAgent.runProcess(List.of(sleep.toString(), "30"), 300).finished());
        assertTrue((System.nanoTime() - t0) / 1_000_000 < 5000);
        assertThrows(IOException.class, () -> BrowserUserAgent.runProcess(List.of("/definitely/not/here", "--version"), 300));
        Output o = BrowserUserAgent.runProcess(List.of("/bin/echo", "Google Chrome 120.0.1.2"), 3000);
        assertEquals(OptionalInt.of(120), BrowserUserAgent.majorFromLinuxOutput(o.stdout()));
    }
}
