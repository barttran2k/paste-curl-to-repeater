package burp;

import burp.curl.CurlSettings;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Finds the version of the curl installed on this machine, for the default {@code User-Agent: curl/<version>}.
 *
 * <p>It runs {@code <curl> --version} once (fixed argument list, no shell, nothing from the pasted text, stdout
 * only, {@link #TIMEOUT_MS} timeout after which the process is destroyed) and never throws. Order: {@code curl} on
 * the JVM's PATH, then the well-known locations. When nothing usable is found the result is the built-in default
 * version of {@link CurlSettings}. {@link #startInBackground} does this once on a daemon thread; a paste waits at
 * most {@link #PASTE_WAIT_MS} for it.
 */
public final class CurlVersionDetector {
    /** Longest a single {@code curl --version} may run. */
    public static final long TIMEOUT_MS = 3000;
    /** Longest a paste waits for a detection that is still running. */
    public static final long PASTE_WAIT_MS = 400;

    private static final Pattern FIRST_LINE = Pattern.compile("^curl\\s+(\\S+)");

    /** What a run of the program produced. */
    public record Output(boolean finished, int exitCode, String stdout) { }

    /** Runs {@code argv} (no shell) and returns its stdout; replaceable in tests. */
    public interface ProcessRunner {
        /**
         * @param argv executable and arguments
         * @param timeoutMs how long it may run
         * @return the output
         * @throws IOException if the program cannot be started
         */
        Output run(List<String> argv, long timeoutMs) throws IOException;
    }

    private final ProcessRunner runner;
    private final Function<String, String> env;
    private final Predicate<Path> isExecutableFile;
    private final boolean windows;
    private volatile CompletableFuture<CurlSettings> result;

    /** The real machine. */
    public CurlVersionDetector() {
        this(CurlVersionDetector::runProcess, System::getenv,
                p -> Files.isRegularFile(p) && Files.isExecutable(p),
                System.getProperty("os.name", "").toLowerCase(java.util.Locale.ROOT).contains("win"));
    }

    /**
     * @param runner runs a program
     * @param env environment lookup (PATH, SystemRoot)
     * @param isExecutableFile true for an existing executable file
     * @param windows whether to use Windows file names and locations
     */
    public CurlVersionDetector(ProcessRunner runner, Function<String, String> env, Predicate<Path> isExecutableFile,
                               boolean windows) {
        this.runner = runner;
        this.env = env;
        this.isExecutableFile = isExecutableFile;
        this.windows = windows;
    }

    /**
     * Parses the first line of {@code curl --version}.
     *
     * @param stdout the output
     * @return the version such as {@code 8.7.1} or {@code 8.12.0-DEV}, or null when it is not there
     */
    public static String parseVersion(String stdout) {
        if (stdout == null) {
            return null;
        }
        String firstLine = stdout.strip().lines().findFirst().orElse("");
        Matcher m = FIRST_LINE.matcher(firstLine.strip());
        if (m.find() && CurlSettings.isUsableVersion(m.group(1))) {
            return m.group(1);
        }
        return null;
    }

    /** @return the curl executables to try, in order: PATH first, then the well-known locations */
    List<Path> candidates() {
        Set<Path> found = new LinkedHashSet<>();
        String pathVar = env.apply("PATH");
        if (pathVar == null && windows) {
            pathVar = env.apply("Path");
        }
        if (pathVar != null) {
            for (String dir : pathVar.split(java.util.regex.Pattern.quote(File.pathSeparator))) {
                addIfExecutable(found, dir.strip().replace("\"", ""));
            }
        }
        for (String known : List.of("/usr/bin", "/opt/homebrew/bin", "/usr/local/bin")) {
            addIfExecutable(found, known);
        }
        String root = env.apply("SystemRoot");
        if (windows && root != null && !root.isBlank()) {
            try {
                addIfExecutable(found, Paths.get(root).resolve("System32").toString());
            } catch (InvalidPathException e) {
                // SystemRoot is not a path: skip
            }
        }
        return new ArrayList<>(found);
    }

    private void addIfExecutable(Set<Path> into, String dir) {
        if (dir.isEmpty()) {
            return;
        }
        try {
            Path d = Paths.get(dir);
            if (!d.isAbsolute()) {
                return;
            }
            for (String name : windows ? List.of("curl.exe", "curl") : List.of("curl")) {
                Path p = d.resolve(name);
                if (isExecutableFile.test(p)) {
                    into.add(p);
                    return;
                }
            }
        } catch (InvalidPathException | SecurityException e) {
            // not a usable directory: skip
        }
    }

    /**
     * Runs the lookup now, on the calling thread. Never throws.
     *
     * @return the version found with the reason, or the built-in default with the reason
     */
    public CurlSettings detect() {
        try {
            List<Path> candidates = candidates();
            if (candidates.isEmpty()) {
                return new CurlSettings(CurlSettings.DEFAULT_CURL_VERSION,
                        "built-in default, no curl binary was found");
            }
            for (Path exe : candidates) {
                String version = versionOf(exe);
                if (version != null) {
                    return new CurlSettings(version, "version of the curl found at " + exe);
                }
            }
            return new CurlSettings(CurlSettings.DEFAULT_CURL_VERSION,
                    "built-in default, curl --version gave no usable version");
        } catch (RuntimeException | LinkageError e) {
            return new CurlSettings(CurlSettings.DEFAULT_CURL_VERSION,
                    "built-in default, the curl lookup failed (" + e.getClass().getSimpleName() + ")");
        }
    }

    private String versionOf(Path exe) {
        try {
            Output out = runner.run(List.of(exe.toString(), "--version"), TIMEOUT_MS);
            if (out == null || !out.finished() || out.exitCode() != 0) {
                return null;
            }
            return parseVersion(out.stdout());
        } catch (IOException | RuntimeException e) {
            return null;
        }
    }

    /** Starts {@link #detect} once on a daemon thread; later calls do nothing. @return this */
    public synchronized CurlVersionDetector startInBackground() {
        if (result == null) {
            CompletableFuture<CurlSettings> f = new CompletableFuture<>();
            result = f;
            Thread t = new Thread(() -> f.complete(detect()), "paste-curl-version-detection");
            t.setDaemon(true);
            t.start();
        }
        return this;
    }

    /**
     * @param maxWaitMs how long to wait for a detection that is still running
     * @return the detected settings, or the built-in default when detection was not started or is not finished
     */
    public CurlSettings settings(long maxWaitMs) {
        CompletableFuture<CurlSettings> f = result;
        if (f != null) {
            try {
                return f.get(maxWaitMs, TimeUnit.MILLISECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            } catch (java.util.concurrent.ExecutionException | java.util.concurrent.TimeoutException e) {
                // fall through to the default
            }
            return new CurlSettings(CurlSettings.DEFAULT_CURL_VERSION,
                    "built-in default, curl --version had not finished yet");
        }
        return new CurlSettings(CurlSettings.DEFAULT_CURL_VERSION, "built-in default, curl was not looked for");
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
            boolean done = p.waitFor(timeoutMs, TimeUnit.MILLISECONDS);
            if (!done) {
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
