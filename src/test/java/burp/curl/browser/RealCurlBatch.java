package burp.curl.browser;

import burp.curl.testsupport.CaptureServer;
import burp.curl.testsupport.CurlRunner;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.function.IntFunction;

/**
 * Runs pasted bash commands with the real bash and curl against a loopback capture server, many commands per bash
 * run. bash runs with a UTF-8 locale because its backslash-u escapes depend on it. Reuses the shared test support.
 */
final class RealCurlBatch {
    private RealCurlBatch() {
    }

    private static String localeCached;

    /** @return a UTF-8 locale name that bash can use, or null when the machine has none */
    static synchronized String utf8Locale() {
        if (localeCached == null) {
            localeCached = "";
            try {
                CurlRunner.Result r = CurlRunner.run(List.of("locale", "-a"), null, null, 10);
                for (String want : new String[] {"en_US.UTF-8", "C.UTF-8", "en_US.utf8", "C.utf8"}) {
                    for (String l : r.output().split("\\s+")) {
                        if (l.equals(want)) {
                            localeCached = want;
                            return want;
                        }
                    }
                }
                for (String l : r.output().split("\\s+")) {
                    if (l.toLowerCase().matches(".*utf-?8")) {
                        localeCached = l;
                        return l;
                    }
                }
            } catch (IOException e) {
                // no locale command
            }
        }
        return localeCached.isEmpty() ? null : localeCached;
    }

    /** @return true when curl, bash >= 4.2 and a UTF-8 locale are available */
    static boolean available() {
        return CurlRunner.toolsAvailable() && utf8Locale() != null;
    }

    /** What the real curl did for each command: the request bytes or null when it sent none. */
    record Outcome(List<Integer> ports, List<String> commands, List<byte[]> requests, String diagnostics) {
    }

    /** Runs one pasted command with the real bash. */
    static CurlRunner.Result runOne(String text) throws IOException {
        return runScript(text + "\n");
    }

    private static CurlRunner.Result runScript(String script) throws IOException {
        Path dir = Files.createTempDirectory("browser-real-curl");
        try {
            Path sh = dir.resolve("paste.sh");
            Files.writeString(sh, script, StandardCharsets.UTF_8);
            Path home = Files.createDirectory(dir.resolve("home"));
            Path wd = Files.createDirectory(dir.resolve("wd"));
            return CurlRunner.run(List.of("env", "LC_ALL=" + utf8Locale(), "bash", "--noprofile", "--norc", sh.toString()),
                    wd.toFile(), home, CurlRunner.TIMEOUT_SECONDS);
        } finally {
            CurlRunner.deleteRecursively(dir);
        }
    }

    /**
     * @param factory builds the commands for a capture server port (called again with a new port in fallback mode)
     * @return one request per command, in order; commands curl sent nothing for have a null entry
     * @throws IOException on infrastructure failure
     */
    static Outcome run(IntFunction<List<String>> factory) throws IOException {
        List<String> commands;
        List<byte[]> reqs;
        CurlRunner.Result res;
        int firstPort;
        try (CaptureServer srv = CaptureServer.start()) {
            firstPort = srv.port();
            commands = factory.apply(srv.port());
            res = runScript(String.join("\n", commands) + "\n");
            srv.close();
            reqs = new ArrayList<>(srv.requests());
        }
        if (!res.timedOut() && reqs.size() == commands.size()) {
            List<Integer> same = new ArrayList<>();
            commands.forEach(c -> same.add(firstPort));
            return new Outcome(same, commands, reqs, res.output());
        }
        // something did not send exactly one request: find out which, one command per run
        List<byte[]> each = new ArrayList<>();
        List<Integer> ports = new ArrayList<>();
        StringBuilder diag = new StringBuilder();
        for (int i = 0; i < commands.size(); i++) {
            final int idx = i;
            try (CaptureServer srv = CaptureServer.start()) {
                ports.add(srv.port());
                String cmd = factory.apply(srv.port()).get(idx);
                CurlRunner.Result r = runScript(cmd + "\n");
                srv.close();
                List<byte[]> got = srv.requests();
                if (got.size() == 1) {
                    each.add(got.get(0));
                } else {
                    each.add(null);
                    diag.append("command #").append(idx).append(": ").append(got.size()).append(" request(s), exit ")
                            .append(r.exit()).append(r.timedOut() ? " (timeout)" : "").append(": ").append(r.output().trim())
                            .append('\n');
                }
            }
        }
        return new Outcome(ports, commands, each, diag.toString());
    }
}
