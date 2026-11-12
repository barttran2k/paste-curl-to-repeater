package burp.curl.testsupport;

import java.io.IOException;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

/** Loader for the differential corpus under {@code src/test/resources/differential}. */
public final class Corpus {
    /** One corpus file. */
    public record Case(String name, String dir, Path file, String body, List<String> directives) {
        /**
         * @param port the capture server port
         * @return the pasted text with placeholders filled in and directive lines removed
         */
        public String text(int port) {
            return body.replace("__BASE__", "http://127.0.0.1:" + port)
                    .replace("__HOSTPORT__", "127.0.0.1:" + port)
                    .replace("__PORT__", Integer.toString(port));
        }

        /** @return true when a directive makes this case unusable on the installed curl or machine */
        public String skipReason() {
            for (String d : directives) {
                Matcher m = Pattern.compile("skip-curl-version < (\\d+(?:\\.\\d+)*)").matcher(d);
                if (m.matches()) {
                    String v = CurlRunner.curlVersion();
                    if (v != null && CurlRunner.compareVersions(v, m.group(1)) < 0) {
                        return "needs curl >= " + m.group(1) + " (have " + v + ")";
                    }
                } else if (d.equals("requires-ipv6")) {
                    if (!CaptureServer.ipv6LoopbackAvailable()) {
                        return "needs IPv6 loopback";
                    }
                }
            }
            return null;
        }
    }

    private static final Pattern KNOWN_DIRECTIVE = Pattern.compile("skip-curl-version < \\d+(\\.\\d+)*|requires-ipv6");

    private Corpus() {
    }

    /** @return the directory holding the resources of the corpus */
    public static Path root() {
        try {
            URL u = Corpus.class.getResource("/differential/files");
            if (u == null) {
                throw new IllegalStateException("differential resources missing from the classpath");
            }
            return Path.of(u.toURI()).getParent();
        } catch (URISyntaxException e) {
            throw new IllegalStateException(e);
        }
    }

    /** @return the fixture directory copied into each case's working directory */
    public static Path filesDir() {
        return root().resolve("files");
    }

    /**
     * Loads every {@code *.curl} file of a corpus subdirectory, sorted by name.
     * @param sub "core" or "extended"
     * @return the cases
     * @throws IOException if reading fails
     */
    public static List<Case> load(String sub) throws IOException {
        List<Case> out = new ArrayList<>();
        try (Stream<Path> s = Files.list(root().resolve(sub))) {
            for (Path p : s.filter(f -> f.getFileName().toString().endsWith(".curl")).sorted().toList()) {
                out.add(parse(sub, p));
            }
        }
        return out;
    }

    static Case parse(String sub, Path p) throws IOException {
        String all = Files.readString(p, StandardCharsets.UTF_8);
        List<String> directives = new ArrayList<>();
        int pos = 0;
        while (all.startsWith("#!", pos)) {
            int nl = all.indexOf('\n', pos);
            String line = (nl < 0 ? all.substring(pos) : all.substring(pos, nl)).substring(2).trim();
            if (!KNOWN_DIRECTIVE.matcher(line).matches()) {
                throw new IllegalStateException(p + ": unknown directive '" + line + "'");
            }
            directives.add(line);
            pos = nl < 0 ? all.length() : nl + 1;
        }
        String name = p.getFileName().toString();
        return new Case(name.substring(0, name.length() - ".curl".length()), sub, p, all.substring(pos), directives);
    }
}
