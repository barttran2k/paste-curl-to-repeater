package burp.curl;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import burp.curl.testsupport.Corpus;
import burp.curl.testsupport.CurlRunner;
import burp.curl.testsupport.DiffPrinter;
import burp.curl.testsupport.DifferentialHarness;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

/** Proves the corpus is valid curl on this machine before any parser exists: no parser code is involved. */
class CorpusSanityTest {
    private static final Pattern URL_HOST = Pattern.compile("[A-Za-z][A-Za-z0-9+.-]*://([^/\\s'\"?#\\\\]*)");
    private static final Pattern REAL_TLD = Pattern.compile(
            "(?i)\\b[a-z0-9-]+(\\.[a-z0-9-]+)*\\.(com|org|net|io|dev|vn|gov|edu|app|cloud|ai|info|biz|co|me|us|uk|de|fr|cn|ru|jp)\\b");

    private static List<Corpus.Case> all() throws IOException {
        List<Corpus.Case> all = new ArrayList<>(Corpus.load("core"));
        all.addAll(Corpus.load("extended"));
        return all;
    }

    @Test
    void corpusSizesAndUniqueNames() throws IOException {
        assertTrue(Corpus.load("core").size() >= 100, "core corpus needs at least 100 files");
        assertTrue(Corpus.load("extended").size() >= 60, "extended corpus needs at least 60 files");
        Set<String> seen = new HashSet<>();
        for (Corpus.Case c : all()) {
            assertTrue(seen.add(c.name()), "duplicate corpus file name: " + c.name());
            assertTrue(c.name().matches("[a-z0-9][a-z0-9-]*"), "file names are lowercase-kebab: " + c.name());
        }
    }

    @Test
    void normalisationMasksOnlyBoundariesAndTheDefaultUserAgentVersion() {
        String req = "POST / HTTP/1.1\r\nUser-Agent: curl/8.7.1\r\nContent-Type: multipart/form-data; boundary="
                + "------------------------AbCdEfGhIjKlMnOpQrStUv\r\n\r\n"
                + "--------------------------AbCdEfGhIjKlMnOpQrStUv\r\nUser-Agent: curl/8.7.1\r\n"
                + "--------------------------ZZZZZZZZZZZZZZZZZZZZZZ--";
        String n = DiffPrinter.normalise(req.getBytes(java.nio.charset.StandardCharsets.ISO_8859_1));
        assertTrue(n.contains("User-Agent: curl/X.Y.Z\r\nContent-Type"), n);
        assertTrue(n.contains("boundary=<boundary-1>\r\n\r\n--<boundary-1>\r\nUser-Agent: curl/8.7.1\r\n--<boundary-2>--"), n);
        String custom = "GET / HTTP/1.1\r\nUser-Agent: Mozilla/5.0\r\nX: curl/8.7.1\r\n\r\n";
        assertEquals(custom, DiffPrinter.normalise(custom.getBytes(java.nio.charset.StandardCharsets.ISO_8859_1)));
    }

    @Test
    void placeholdersAreTheOnlyHostReferences() throws IOException {
        for (Corpus.Case c : all()) {
            String body = c.body();
            Matcher m = URL_HOST.matcher(body);
            while (m.find()) {
                String authority = m.group(1);
                String host = authority.substring(authority.lastIndexOf('@') + 1);
                if (host.startsWith("[")) {
                    host = host.substring(0, host.indexOf(']') + 1);
                } else if (host.contains(":") && !host.startsWith("__")) {
                    host = host.substring(0, host.indexOf(':'));
                }
                boolean ok = host.equals("__HOSTPORT__") || host.startsWith("__BASE__") || host.equals("127.0.0.1")
                        || host.equals("[::1]") || host.matches("[a-z0-9.-]*\\.(example|invalid|test)")
                        || host.equals("");
                assertTrue(ok, c.name() + ": host '" + host + "' is not a placeholder or a reserved name");
            }
            Matcher t = REAL_TLD.matcher(body);
            assertFalse(t.find(), c.name() + ": mentions a real-looking host '" + (t.hitEnd() ? "" : t.group()) + "'");
        }
    }

    @Test
    void everyCaseUsesAPlaceholderForItsTarget() throws IOException {
        for (Corpus.Case c : all()) {
            assertTrue(c.body().contains("__BASE__") || c.body().contains("__HOSTPORT__") || c.body().contains("__PORT__"),
                    c.name() + ": no placeholder, so curl could not reach the capture server");
        }
    }

    @TestFactory
    Stream<DynamicTest> realShellAndCurlRunEveryFile() throws IOException {
        Assumptions.assumeTrue(CurlRunner.toolsAvailable(), "curl or bash >= 4.2 is missing");
        return all().stream().map(c -> DynamicTest.dynamicTest(c.dir() + "/" + c.name(), c.file().toUri(), () -> {
            String skip = c.skipReason();
            Assumptions.assumeTrue(skip == null, skip);
            DifferentialHarness.CurlRun run = DifferentialHarness.runCurl(c);
            assertFalse(run.result().timedOut(), "timed out: " + run.text());
            assertEquals(0, run.result().exit(), "exit code; output:\n" + run.result().output() + "\ntext:\n" + run.text());
            assertTrue(run.requests().size() >= 1, "no request captured; output:\n" + run.result().output());
        }));
    }
}
