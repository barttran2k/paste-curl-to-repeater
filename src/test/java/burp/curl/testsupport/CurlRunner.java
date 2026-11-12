package burp.curl.testsupport;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Runs the real shell and the real curl, resolved from PATH, with a hard kill after a timeout. */
public final class CurlRunner {
    /** Outcome of one process run. */
    public record Result(int exit, String output, boolean timedOut) {
    }

    /** Hard limit for one shell run. */
    public static final long TIMEOUT_SECONDS = 30;

    private static String curlVersionCached;
    private static Boolean bashOk;

    private CurlRunner() {
    }

    /** @return curl's version like "8.7.1", or null when curl cannot be run */
    public static synchronized String curlVersion() {
        if (curlVersionCached == null) {
            try {
                Result r = run(List.of("curl", "--version"), null, null, 10);
                Matcher m = Pattern.compile("^curl (\\d+\\.\\d+\\.\\d+)").matcher(r.output());
                curlVersionCached = r.exit() == 0 && m.find() ? m.group(1) : "";
            } catch (IOException e) {
                curlVersionCached = "";
            }
        }
        return curlVersionCached.isEmpty() ? null : curlVersionCached;
    }

    /** @return true when curl runs and a bash of version 4.2 or newer is on PATH */
    public static synchronized boolean toolsAvailable() {
        if (curlVersion() == null) {
            return false;
        }
        if (bashOk == null) {
            bashOk = false;
            try {
                Result r = run(List.of("bash", "-c", "echo ${BASH_VERSINFO[0]} ${BASH_VERSINFO[1]}"), null, null, 10);
                String[] p = r.output().trim().split(" ");
                if (r.exit() == 0 && p.length == 2) {
                    int major = Integer.parseInt(p[0]);
                    int minor = Integer.parseInt(p[1]);
                    bashOk = major > 4 || major == 4 && minor >= 2;
                }
            } catch (IOException | RuntimeException e) {
                bashOk = false;
            }
        }
        return bashOk;
    }

    /**
     * Compares dotted versions.
     * @param a first version
     * @param b second version
     * @return negative, zero or positive like compareTo
     */
    public static int compareVersions(String a, String b) {
        String[] x = a.split("\\.");
        String[] y = b.split("\\.");
        for (int i = 0; i < Math.max(x.length, y.length); i++) {
            int xi = i < x.length ? Integer.parseInt(x[i]) : 0;
            int yi = i < y.length ? Integer.parseInt(y[i]) : 0;
            if (xi != yi) {
                return Integer.compare(xi, yi);
            }
        }
        return 0;
    }

    /**
     * Runs a script text with bash in a directory: stdin is /dev/null, stdout and stderr are merged, proxies and
     * curl config are neutralised, and anything not on loopback is sent to a dead proxy so nothing can leave the host.
     * @param script the shell text exactly as pasted
     * @param workDir the working directory
     * @return exit code and output
     * @throws IOException if the process cannot be started
     */
    public static Result runShell(String script, Path workDir) throws IOException {
        Path scriptDir = Files.createTempDirectory("curl-diff-script");
        try {
            Path sh = scriptDir.resolve("paste.sh");
            Files.writeString(sh, script, StandardCharsets.UTF_8);
            Path home = Files.createDirectory(scriptDir.resolve("home"));
            return run(List.of("bash", "--noprofile", "--norc", sh.toString()), workDir.toFile(), home, TIMEOUT_SECONDS);
        } finally {
            deleteRecursively(scriptDir);
        }
    }

    /**
     * Runs a program with the same isolation as {@link #runShell}.
     * @param cmd the command and arguments
     * @param workDir working directory or null
     * @param home an empty directory used as HOME and CURL_HOME, or null to inherit
     * @param timeoutSeconds kill the process tree after this long
     * @return exit code and output
     * @throws IOException if the process cannot be started
     */
    public static Result run(List<String> cmd, File workDir, Path home, long timeoutSeconds) throws IOException {
        ProcessBuilder pb = new ProcessBuilder(cmd).redirectErrorStream(true)
                .redirectInput(ProcessBuilder.Redirect.from(new File("/dev/null")));
        if (workDir != null) {
            pb.directory(workDir);
        }
        if (home != null) {
            Map<String, String> env = pb.environment();
            new ArrayList<>(env.keySet()).stream()
                    .filter(k -> k.matches("(?i)(http|https|ftp|all|no)_proxy|CURL_.*|SSLKEYLOGFILE"))
                    .forEach(env::remove);
            env.put("HOME", home.toString());
            env.put("CURL_HOME", home.toString());
            String dead = "http://127.0.0.1:9";
            for (String k : new String[] {"http_proxy", "https_proxy", "all_proxy", "ftp_proxy"}) {
                env.put(k, dead);
            }
            env.put("no_proxy", "127.0.0.1,::1,[::1],localhost");
        }
        Process p = pb.start();
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        Thread reader = new Thread(() -> {
            try (InputStream in = p.getInputStream()) {
                in.transferTo(out);
            } catch (IOException e) {
                // process killed
            }
        });
        reader.setDaemon(true);
        reader.start();
        boolean timedOut = false;
        try {
            if (!p.waitFor(timeoutSeconds, TimeUnit.SECONDS)) {
                timedOut = true;
                p.descendants().forEach(ProcessHandle::destroyForcibly);
                p.destroyForcibly();
                p.waitFor(5, TimeUnit.SECONDS);
            }
            reader.join(2000);
        } catch (InterruptedException e) {
            p.destroyForcibly();
            Thread.currentThread().interrupt();
        }
        int exit = timedOut ? -1 : p.exitValue();
        String text;
        synchronized (out) {
            text = out.toString(StandardCharsets.UTF_8);
        }
        return new Result(exit, text, timedOut);
    }

    /**
     * Deletes a directory tree, ignoring failures.
     * @param dir the root
     */
    public static void deleteRecursively(Path dir) {
        try (var s = Files.walk(dir)) {
            s.sorted(java.util.Comparator.reverseOrder()).forEach(p -> p.toFile().delete());
        } catch (IOException e) {
            // best effort
        }
    }
}
