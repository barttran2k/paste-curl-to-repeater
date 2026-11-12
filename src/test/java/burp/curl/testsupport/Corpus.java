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

    /** A fixture whose name cannot be tracked in git (Windows-illegal characters): created at test time. */
    public record SpecialFile(String name, byte[] content) { }

    private static String unescape(String s) {
        java.io.ByteArrayOutputStream o = new java.io.ByteArrayOutputStream();
        byte[] b = s.getBytes(StandardCharsets.UTF_8);
        for (int i = 0; i < b.length; i++) {
            if (b[i] == '%' && i + 2 < b.length) {
                o.write(Integer.parseInt(new String(b, i + 1, 2, StandardCharsets.US_ASCII), 16));
                i += 2;
            } else {
                o.write(b[i]);
            }
        }
        return o.toString(StandardCharsets.UTF_8);
    }

    /** @return the fixtures listed in {@code special-files.tsv} (see the README for the escaping) */
    public static List<SpecialFile> specialFiles() throws IOException {
        List<SpecialFile> out = new ArrayList<>();
        for (String line : Files.readAllLines(root().resolve("special-files.tsv"), StandardCharsets.UTF_8)) {
            if (line.isEmpty() || line.startsWith("#")) {
                continue;
            }
            int tab = line.indexOf('\t');
            out.add(new SpecialFile(unescape(line.substring(0, tab)),
                    unescape(line.substring(tab + 1)).getBytes(StandardCharsets.UTF_8)));
        }
        return out;
    }

    /** Writes the special fixtures into {@code dir}; returns null on success or the reason the file system refuses. */
    public static String materialiseSpecialFiles(Path dir) throws IOException {
        for (SpecialFile f : specialFiles()) {
            try {
                Path p = dir.resolve(f.name());
                if (p.getParent() != null) {
                    Files.createDirectories(p.getParent());
                }
                Files.write(p, f.content());
            } catch (java.nio.file.InvalidPathException | IOException e) {
                return "this file system cannot create the fixture name '" + f.name() + "' (" + e.getClass()
                        .getSimpleName() + ")";
            }
        }
        return null;
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
