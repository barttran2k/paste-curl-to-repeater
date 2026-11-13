package burp;

import burp.curl.CurlSettings;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.LocalDate;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.OptionalInt;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.function.Function;
import java.util.function.Supplier;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

/**
 * The default {@code User-Agent} of a request whose command sets none: a current desktop Chrome for the local
 * operating system, in Chrome's reduced format. This deliberately differs from what curl sends; a note says so.
 *
 * <p>Templates (Chromium project, "User-Agent Reduction", https://www.chromium.org/updates/ua-reduction/, desktop
 * template {@code Mozilla/5.0 (<unifiedPlatform>) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/<majorVersion>.0.0.0
 * Safari/537.36} with the unified platforms {@code Macintosh; Intel Mac OS X 10_15_7},
 * {@code Windows NT 10.0; Win64; x64} and {@code X11; Linux x86_64}).
 *
 * <p>The major version, in this order: (1) the installed Chrome, read from files where possible (macOS
 * {@code Info.plist}, Windows version-named directory; on Linux {@code google-chrome --version} style output with a
 * fixed argument list, no shell, {@link #TIMEOUT_MS} timeout), (2) an estimate from the date, see
 * {@link #estimateMajor}. Everything is defensive: a missing or malformed source moves on to the next, nothing throws.
 * Detection runs once on a daemon thread ({@link #startInBackground}); a paste that comes earlier waits at most
 * {@link #PASTE_WAIT_MS} and then uses the date estimate.
 */
public final class BrowserUserAgent {
    /** Longest a single {@code --version} call may run (Linux only). */
    public static final long TIMEOUT_MS = 3000;
    /** Longest a paste waits for a detection that is still running. */
    public static final long PASTE_WAIT_MS = 400;

    /**
     * Calibration of {@link #estimateMajor}; source: Chromium Dash milestone schedule,
     * https://chromiumdash.appspot.com/fetch_milestone_schedule?mstone=N (stable_date), read 2026-11-13. Chrome 152
     * was released 2026-08-25 after four-week cycles; from Chrome 153 (2026-09-08) a new major comes every two weeks.
     */
    static final int SHORT_CYCLE_ANCHOR_MAJOR = 153;
    static final LocalDate SHORT_CYCLE_ANCHOR_DATE = LocalDate.of(2026, 9, 8);
    static final int SHORT_CYCLE_DAYS = 14;
    static final int LONG_CYCLE_ANCHOR_MAJOR = 152;
    static final LocalDate LONG_CYCLE_ANCHOR_DATE = LocalDate.of(2026, 8, 25);
    static final int LONG_CYCLE_DAYS = 28;

    /** Operating systems with a distinct template. */
    public enum Os {
        MAC("Macintosh; Intel Mac OS X 10_15_7"),
        WINDOWS("Windows NT 10.0; Win64; x64"),
        LINUX("X11; Linux x86_64");

        final String platform;

        Os(String platform) {
            this.platform = platform;
        }

        /** @param osName the os.name property @return the template to use (Linux for everything unknown) */
        public static Os of(String osName) {
            String n = osName == null ? "" : osName.toLowerCase(Locale.ROOT);
            if (n.contains("mac") || n.contains("darwin")) {
                return MAC;
            }
            return n.contains("win") ? WINDOWS : LINUX;
        }
    }

    /** What a run of a program produced. */
    public record Output(boolean finished, int exitCode, String stdout) { }

    /** Runs {@code argv} (no shell) and returns its stdout; replaceable in tests. */
    public interface ProcessRunner {
        /** @param argv executable and arguments @param timeoutMs time limit @return the output @throws IOException if it cannot start */
        Output run(List<String> argv, long timeoutMs) throws IOException;
    }

    private static final Pattern PLIST_VERSION = Pattern.compile(
            "<key>\\s*CFBundleShortVersionString\\s*</key>\\s*<string>\\s*([^<]*?)\\s*</string>");
    private static final Pattern LEADING_MAJOR = Pattern.compile("^(\\d{2,3})\\.\\d+(\\.\\d+)*");
    private static final Pattern DIR_VERSION = Pattern.compile("^(\\d{2,3})\\.\\d+\\.\\d+\\.\\d+$");
    private static final Pattern LINUX_OUTPUT = Pattern.compile("(?:Google Chrome|Chromium|Chrome)\\s+(\\d{2,3})\\.\\d+");

    private final Os os;
    private final Path home;
    private final Path systemApplications;
    private final Function<String, String> env;
    private final ProcessRunner runner;
    private final Supplier<LocalDate> today;
    private final List<Path> linuxExecutables;
    private volatile CompletableFuture<CurlSettings> result;

    /** @return a detector for the machine this JVM runs on */
    public static BrowserUserAgent forThisMachine() {
        Os os = Os.of(System.getProperty("os.name"));
        Path home = Paths.get(System.getProperty("user.home", "/"));
        return new BrowserUserAgent(os, home, Paths.get("/Applications"), System::getenv, BrowserUserAgent::runProcess,
                LocalDate::now,
                List.of(Paths.get("/usr/bin/google-chrome"), Paths.get("/usr/bin/google-chrome-stable"),
                        Paths.get("/opt/google/chrome/google-chrome"), Paths.get("/usr/bin/chromium"),
                        Paths.get("/usr/bin/chromium-browser"), Paths.get("/snap/bin/chromium"),
                        Paths.get("/usr/local/bin/google-chrome"), Paths.get("/usr/local/bin/chromium")));
    }

    /**
     * @param os the operating system
     * @param home the user's home directory (macOS {@code ~/Applications})
     * @param systemApplications the macOS {@code /Applications} directory
     * @param env environment lookup (ProgramFiles, ProgramFiles(x86), LocalAppData)
     * @param runner runs {@code --version} (Linux only)
     * @param today the current date, for the estimate
     * @param linuxExecutables browsers to ask for their version on Linux, in order
     */
    public BrowserUserAgent(Os os, Path home, Path systemApplications, Function<String, String> env, ProcessRunner runner,
                            Supplier<LocalDate> today, List<Path> linuxExecutables) {
        this.os = os;
        this.home = home;
        this.systemApplications = systemApplications;
        this.env = env;
        this.runner = runner;
        this.today = today;
        this.linuxExecutables = List.copyOf(linuxExecutables);
    }

    // ---- the value ----

    /** @param os operating system @param major Chrome major version @return the reduced User-Agent */
    public static String userAgent(Os os, int major) {
        return "Mozilla/5.0 (" + os.platform + ") AppleWebKit/537.36 (KHTML, like Gecko) Chrome/" + major
                + ".0.0.0 Safari/537.36";
    }

    // ---- sources ----

    /**
     * @param plistText the text of a macOS Info.plist
     * @return the major version of {@code CFBundleShortVersionString}, or empty when absent or malformed
     */
    public static OptionalInt majorFromPlist(String plistText) {
        if (plistText == null) {
            return OptionalInt.empty();
        }
        Matcher m = PLIST_VERSION.matcher(plistText);
        return m.find() ? majorFromVersion(m.group(1)) : OptionalInt.empty();
    }

    /** @param version e.g. {@code 156.0.8078.81}, {@code 157.0.8100.4 dev} @return the major, or empty */
    public static OptionalInt majorFromVersion(String version) {
        if (version == null) {
            return OptionalInt.empty();
        }
        Matcher m = LEADING_MAJOR.matcher(version.strip());
        return m.find() ? OptionalInt.of(Integer.parseInt(m.group(1))) : OptionalInt.empty();
    }

    /**
     * @param applicationDir e.g. {@code C:\Program Files\Google\Chrome\Application}, which holds a directory named
     *                       after the version
     * @return the highest major among directories named {@code a.b.c.d}, or empty
     */
    public static OptionalInt majorFromWindowsDir(Path applicationDir) {
        int best = -1;
        try (Stream<Path> children = Files.list(applicationDir)) {
            for (Path c : (Iterable<Path>) children::iterator) {
                Matcher m = DIR_VERSION.matcher(String.valueOf(c.getFileName()));
                if (m.matches() && Files.isDirectory(c)) {
                    best = Math.max(best, Integer.parseInt(m.group(1)));
                }
            }
        } catch (IOException | RuntimeException e) {
            return OptionalInt.empty();
        }
        return best < 0 ? OptionalInt.empty() : OptionalInt.of(best);
    }

    /** @param output stdout of {@code google-chrome --version} @return the major, or empty */
    public static OptionalInt majorFromLinuxOutput(String output) {
        if (output == null) {
            return OptionalInt.empty();
        }
        Matcher m = LINUX_OUTPUT.matcher(output.strip().lines().findFirst().orElse(""));
        return m.find() ? OptionalInt.of(Integer.parseInt(m.group(1))) : OptionalInt.empty();
    }

    /**
     * Estimates the current stable Chrome major from the date, using the release cadence: every two weeks from
     * Chrome 153, every four weeks before (the four-week part is exact from Chrome 144 on and within two majors
     * before; holiday breaks stretched some earlier cycles).
     *
     * @param date the day
     * @return the estimated major
     */
    public static int estimateMajor(LocalDate date) {
        if (!date.isBefore(SHORT_CYCLE_ANCHOR_DATE)) {
            long days = ChronoUnit.DAYS.between(SHORT_CYCLE_ANCHOR_DATE, date);
            return SHORT_CYCLE_ANCHOR_MAJOR + (int) (days / SHORT_CYCLE_DAYS);
        }
        long days = ChronoUnit.DAYS.between(LONG_CYCLE_ANCHOR_DATE, date);
        return LONG_CYCLE_ANCHOR_MAJOR + (int) Math.floorDiv(days, (long) LONG_CYCLE_DAYS);
    }

    private OptionalInt macMajor() {
        List<Path> plists = new ArrayList<>();
        plists.add(systemApplications.resolve("Google Chrome.app").resolve("Contents").resolve("Info.plist"));
        plists.add(home.resolve("Applications").resolve("Google Chrome.app").resolve("Contents").resolve("Info.plist"));
        for (Path p : plists) {
            try {
                if (Files.isRegularFile(p) && Files.size(p) < 1_000_000) {
                    OptionalInt m = majorFromPlist(Files.readString(p, StandardCharsets.UTF_8));
                    if (m.isPresent()) {
                        return m;
                    }
                }
            } catch (IOException | RuntimeException e) {
                // unreadable or not text: next source
            }
        }
        return OptionalInt.empty();
    }

    private OptionalInt windowsMajor() {
        List<Path> dirs = new ArrayList<>();
        for (String[] v : new String[][] {{"ProgramFiles"}, {"ProgramFiles(x86)"}, {"LocalAppData"}}) {
            String root = env.apply(v[0]);
            if (root != null && !root.isBlank()) {
                try {
                    dirs.add(Paths.get(root).resolve("Google").resolve("Chrome").resolve("Application"));
                } catch (InvalidPathException e) {
                    // not a path: skip
                }
            }
        }
        for (Path d : dirs) {
            OptionalInt m = majorFromWindowsDir(d);
            if (m.isPresent()) {
                return m;
            }
        }
        return OptionalInt.empty();
    }

    private OptionalInt linuxMajor() {
        for (Path exe : linuxExecutables) {
            try {
                if (!Files.isRegularFile(exe) || !Files.isExecutable(exe)) {
                    continue;
                }
                Output out = runner.run(List.of(exe.toString(), "--version"), TIMEOUT_MS);
                if (out != null && out.finished() && out.exitCode() == 0) {
                    OptionalInt m = majorFromLinuxOutput(out.stdout());
                    if (m.isPresent()) {
                        return m;
                    }
                }
            } catch (IOException | RuntimeException e) {
                // next browser
            }
        }
        return OptionalInt.empty();
    }

    /**
     * Runs the lookup now, on the calling thread. Never throws.
     *
     * @return the User-Agent to use with the note that says where its version came from
     */
    public CurlSettings detect() {
        OptionalInt installed = OptionalInt.empty();
        try {
            installed = switch (os) {
                case MAC -> macMajor();
                case WINDOWS -> windowsMajor();
                case LINUX -> linuxMajor();
            };
        } catch (RuntimeException | LinkageError e) {
            // fall through to the estimate
        }
        if (installed.isPresent()) {
            return settings(installed.getAsInt(), "version of the installed Chrome");
        }
        return estimated("estimated from the date; Chrome was not found");
    }

    private CurlSettings settings(int major, String origin) {
        return new CurlSettings(userAgent(os, major), "User-Agent set to a browser value (Chrome " + major + ", "
                + origin + "); curl itself would send its own curl/x.y.z");
    }

    private CurlSettings estimated(String origin) {
        int major;
        try {
            major = estimateMajor(today.get());
        } catch (RuntimeException e) {
            major = estimateMajor(LocalDate.now());
        }
        return settings(major, origin);
    }

    // ---- background ----

    /** Starts {@link #detect} once on a daemon thread; later calls do nothing. @return this */
    public synchronized BrowserUserAgent startInBackground() {
        if (result == null) {
            CompletableFuture<CurlSettings> f = new CompletableFuture<>();
            result = f;
            Thread t = new Thread(() -> f.complete(detect()), "paste-curl-chrome-detection");
            t.setDaemon(true);
            t.start();
        }
        return this;
    }

    /**
     * @param maxWaitMs how long to wait for a detection that is still running
     * @return the detected settings, or the date estimate when detection was not started or is not finished
     */
    public CurlSettings settings(long maxWaitMs) {
        CompletableFuture<CurlSettings> f = result;
        if (f != null) {
            try {
                return f.get(maxWaitMs, TimeUnit.MILLISECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            } catch (java.util.concurrent.ExecutionException | java.util.concurrent.TimeoutException e) {
                // fall through
            }
            return estimated("estimated from the date; the Chrome lookup had not finished");
        }
        return estimated("estimated from the date; Chrome was not looked for");
    }

    /** @return the settings for a paste: waits at most {@link #PASTE_WAIT_MS} */
    public CurlSettings settings() {
        return settings(PASTE_WAIT_MS);
    }

    static Output runProcess(List<String> argv, long timeoutMs) throws IOException {
        Process p = new ProcessBuilder(argv).redirectError(ProcessBuilder.Redirect.DISCARD).start();
        try {
            p.getOutputStream().close();
            ByteArrayOutputStream buf = new ByteArrayOutputStream();
            Thread reader = new Thread(() -> {
                try (InputStream in = p.getInputStream()) {
                    byte[] chunk = new byte[4096];
                    int n;
                    while ((n = in.read(chunk)) > 0 && buf.size() < 64 * 1024) {
                        synchronized (buf) {
                            buf.write(chunk, 0, n);
                        }
                    }
                } catch (IOException e) {
                    // the process ended or was destroyed
                }
            }, "paste-curl-version-reader");
            reader.setDaemon(true);
            reader.start();
            if (!p.waitFor(timeoutMs, TimeUnit.MILLISECONDS)) {
                return new Output(false, -1, "");
            }
            reader.join(1000);
            synchronized (buf) {
                return new Output(true, p.exitValue(), buf.toString(StandardCharsets.UTF_8));
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return new Output(false, -1, "");
        } finally {
            p.destroyForcibly();
        }
    }
}
