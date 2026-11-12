package burp.curl.testsupport;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/** The single request one curl invocation sent to a {@link CaptureServer}. */
public final class Captured {
    /** curl's exit code */
    public int exit;
    /** curl's merged stdout and stderr */
    public String stderr = "";
    /** raw request bytes, null when curl never connected */
    public byte[] raw;

    /** @return the request as one char per byte */
    public String wire() {
        return new String(raw, StandardCharsets.ISO_8859_1);
    }

    /**
     * @param name header name
     * @return the trimmed value of the first such header, or null
     */
    public String header(String name) {
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

    /** @return the request line */
    public String requestLine() {
        String w = wire();
        return w.substring(0, w.indexOf("\r\n"));
    }

    /** @return the bytes after the blank line */
    public byte[] body() {
        int end = wire().indexOf("\r\n\r\n");
        return Arrays.copyOfRange(raw, end + 4, raw.length);
    }

    /**
     * Runs curl with {@code --connect-to} pointing every URL at a fresh 127.0.0.1 capture server.
     * @param args curl arguments
     * @return what curl did and sent
     * @throws Exception on infrastructure failure
     */
    public static Captured capture(String... args) throws Exception {
        Captured result = new Captured();
        Path home = Files.createTempDirectory("curl-capture-home");
        try (CaptureServer srv = CaptureServer.start()) {
            List<String> cmd = new ArrayList<>(List.of("curl", "-sS", "-g", "--noproxy", "*", "--max-time", "8", "--connect-to",
                    "::127.0.0.1:" + srv.port()));
            cmd.addAll(List.of(args));
            CurlRunner.Result r = CurlRunner.run(cmd, null, home, 20);
            srv.close();
            result.exit = r.exit();
            result.stderr = r.output();
            List<byte[]> reqs = srv.requests();
            result.raw = reqs.isEmpty() ? null : reqs.get(0);
        } finally {
            CurlRunner.deleteRecursively(home);
        }
        return result;
    }
}
