package burp.curl.testsupport;

import burp.curl.BuiltRequest;
import burp.curl.Curl;
import burp.curl.CurlParseException;
import burp.curl.FileAccess;
import burp.curl.ParsedCurl;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.DynamicTest;
import org.opentest4j.AssertionFailedError;

/** Runs one corpus case through the real shell+curl and through {@link Curl}, then compares the request bytes. */
public final class DifferentialHarness {
    private DifferentialHarness() {
    }

    /** What the real shell and curl did with a case. */
    public record CurlRun(String text, CurlRunner.Result result, List<byte[]> requests) {
    }

    /**
     * Copies the fixtures to a fresh working directory.
     * @return the new directory
     * @throws IOException if copying fails
     */
    public static Path freshWorkDir() throws IOException {
        Path wd = Files.createTempDirectory("curl-diff-wd");
        Path src = Corpus.filesDir();
        try (Stream<Path> s = Files.walk(src)) {
            for (Path p : s.toList()) {
                Path dest = wd.resolve(src.relativize(p).toString());
                if (Files.isDirectory(p)) {
                    Files.createDirectories(dest);
                } else {
                    Files.copy(p, dest);
                }
            }
        }
        Corpus.materialiseSpecialFiles(wd);
        return wd;
    }

    /** Skips (with the reason) a case that names a fixture the file system cannot create. */
    private static void assumeFixturesAvailable(Corpus.Case c) throws IOException {
        Path probe = Files.createTempDirectory("curl-diff-probe");
        try {
            String reason = Corpus.materialiseSpecialFiles(probe);
            if (reason != null) {
                for (Corpus.SpecialFile f : Corpus.specialFiles()) {
                    Assumptions.assumeTrue(!c.body().contains(f.name()), reason);
                }
            }
        } finally {
            CurlRunner.deleteRecursively(probe);
        }
    }

    /**
     * Runs the case text with the real shell against a fresh capture server.
     * @param c the case
     * @return text, process result and the captured requests
     * @throws IOException on setup failure
     */
    public static CurlRun runCurl(Corpus.Case c) throws IOException {
        Path wd = freshWorkDir();
        try (CaptureServer srv = CaptureServer.start()) {
            String text = c.text(srv.port());
            CurlRunner.Result r = CurlRunner.runShell(text, wd);
            srv.close();
            return new CurlRun(text, r, srv.requests());
        } finally {
            CurlRunner.deleteRecursively(wd);
        }
    }

    /**
     * Full differential check of one case.
     * @param c the case
     * @throws Exception on infrastructure errors; assertion failures carry the readable report
     */
    public static void check(Corpus.Case c) throws Exception {
        String skip = c.skipReason();
        Assumptions.assumeTrue(skip == null, skip);
        assumeFixturesAvailable(c);
        CurlRun run = runCurl(c);
        if (run.result().timedOut() || run.result().exit() != 0 || run.requests().isEmpty()) {
            throw new AssertionFailedError("corpus case " + c.name() + " is not valid curl on this machine: exit "
                    + run.result().exit() + (run.result().timedOut() ? " (timed out)" : "") + ", "
                    + run.requests().size() + " request(s) captured\n--- output ---\n" + run.result().output()
                    + "\n--- text ---\n" + run.text());
        }
        Path wd = freshWorkDir();
        try {
            FileAccess files = path -> Files.readAllBytes(wd.resolve(path));
            List<byte[]> ours = new ArrayList<>();
            try {
                ParsedCurl parsed = Curl.parse(run.text());
                for (BuiltRequest r : parsed.build(files)) {
                    ours.add(r.raw());
                }
            } catch (UnsupportedOperationException e) {
                if (e.getClass() != UnsupportedOperationException.class) {
                    throw e;
                }
                Assumptions.abort("core not implemented in this worktree");
            } catch (CurlParseException e) {
                String report = DiffPrinter.compare(run.text(), run.requests(), ours);
                throw new AssertionFailedError("CurlParseException: " + e.getMessage() + "\n"
                        + (report == null ? "" : report));
            }
            String report = DiffPrinter.compare(run.text(), run.requests(), ours);
            if (report != null) {
                throw new AssertionFailedError("MISMATCH in " + c.dir() + "/" + c.name() + ".curl\n" + report);
            }
        } finally {
            CurlRunner.deleteRecursively(wd);
        }
    }

    /**
     * @param sub corpus subdirectory
     * @return one dynamic test per corpus file, named after the file
     * @throws IOException if the corpus cannot be read
     */
    public static Stream<DynamicTest> tests(String sub) throws IOException {
        Assumptions.assumeTrue(CurlRunner.toolsAvailable(), "curl or bash >= 4.2 is missing");
        return Corpus.load(sub).stream().map(c -> DynamicTest.dynamicTest(c.name(), c.file().toUri(), () -> check(c)));
    }
}
