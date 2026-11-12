package burp.curl;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.regex.Pattern;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;

/** Every tracked file must be checkable on Windows: no illegal characters, no trailing space or dot, no device names. */
class TrackedFileNamesTest {
    private static final Pattern BAD_CHARS = Pattern.compile("[\\\\:*?\"<>|\\u0000-\\u001f]");
    private static final Pattern DEVICE = Pattern.compile("(?i)(con|prn|aux|nul|com[1-9]|lpt[1-9])(\\..*)?");

    private static List<String> trackedPaths() throws IOException {
        try {
            Process p = new ProcessBuilder("git", "ls-files", "-z").redirectErrorStream(false).start();
            byte[] out = p.getInputStream().readAllBytes();
            if (p.waitFor() == 0 && out.length > 0) {
                List<String> l = new ArrayList<>();
                for (String s : new String(out, StandardCharsets.UTF_8).split("\0")) {
                    if (!s.isEmpty()) {
                        l.add(s);
                    }
                }
                return l;
            }
        } catch (IOException | InterruptedException e) {
            // no git: fall back to the source tree
        }
        List<String> l = new ArrayList<>();
        Path src = Path.of("src");
        if (Files.isDirectory(src)) {
            try (Stream<Path> s = Files.walk(src)) {
                s.forEach(f -> l.add(f.toString().replace('\\', '/')));
            }
        }
        return l;
    }

    @Test
    void noTrackedPathIsIllegalOnWindows() throws IOException {
        List<String> paths = trackedPaths();
        assertTrue(paths.size() > 50, "no file list: " + paths.size());
        List<String> bad = new ArrayList<>();
        for (String path : paths) {
            for (String part : path.split("/")) {
                String stem = part.toLowerCase(Locale.ROOT);
                if (BAD_CHARS.matcher(part).find() || part.endsWith(" ") || part.endsWith(".")
                        || DEVICE.matcher(stem).matches()) {
                    bad.add(path);
                    break;
                }
            }
        }
        assertTrue(bad.isEmpty(), "illegal on Windows: " + bad);
    }
}
