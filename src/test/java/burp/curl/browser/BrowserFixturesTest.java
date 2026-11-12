package burp.curl.browser;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import burp.curl.Curl;
import burp.curl.FileAccess;
import burp.curl.browser.BrowserGenerators.Flavor;
import burp.curl.testsupport.DiffPrinter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

/**
 * Complete clipboard texts per browser flavour (src/test/resources/browser/fixtures/README.md) each parse to the bytes
 * the real curl sent for the same logical request.
 */
class BrowserFixturesTest {
    static final String PLACEHOLDER = "__HOSTPORT__";

    private static Path root() throws Exception {
        return Path.of(BrowserFixturesTest.class.getResource("/browser/fixtures").toURI());
    }

    @TestFactory
    Stream<DynamicTest> everyFixtureParsesToTheBytesOfRealCurl() throws Exception {
        List<DynamicTest> tests = new ArrayList<>();
        for (Flavor f : Flavor.values()) {
            Path d = root().resolve(FixtureGenerator.dir(f));
            List<Path> texts;
            try (Stream<Path> s = Files.list(d)) {
                texts = s.filter(p -> p.getFileName().toString().endsWith("." + FixtureGenerator.ext(f))).sorted().toList();
            }
            assertTrue(texts.size() >= 12, f + ": at least 12 fixtures, found " + texts.size());
            for (Path p : texts) {
                tests.add(DynamicTest.dynamicTest(FixtureGenerator.dir(f) + "/" + p.getFileName(), p.toUri(), () -> check(p)));
            }
        }
        return tests.stream();
    }

    private static void check(Path p) throws Exception {
        String name = p.getFileName().toString();
        String text = Files.readString(p, StandardCharsets.UTF_8);
        byte[] expected = Files.readAllBytes(p.resolveSibling(name.substring(0, name.lastIndexOf('.')) + ".expected.http"));
        assertTrue(text.contains(PLACEHOLDER), "fixture has no host placeholder");
        String hostPort = "127.0.0.1:41999";
        String pasted = text.replace(PLACEHOLDER, hostPort);
        byte[] want = new String(expected, StandardCharsets.ISO_8859_1).replace(PLACEHOLDER, hostPort)
                .getBytes(StandardCharsets.ISO_8859_1);
        byte[] ours = Curl.parse(pasted).build(FileAccess.DENY).get(0).raw();
        assertNull(DiffPrinter.compare(pasted, List.of(want), List.of(ours)), name);
    }

    /** The stored texts are exactly what the validated generator ports produce for the logical requests. */
    @Test
    void fixturesAreWhatTheGeneratorsProduce() throws Exception {
        int n = 0;
        for (Map.Entry<String, List<FixtureRequests.Fx>> e : FixtureRequests.all().entrySet()) {
            for (Flavor f : FixtureGenerator.flavors(e.getKey())) {
                List<FixtureRequests.Fx> reqs = e.getValue();
                assertTrue(reqs.size() >= 12, e.getKey() + " has " + reqs.size() + " logical requests");
                for (int i = 0; i < reqs.size(); i++) {
                    Path p = root().resolve(FixtureGenerator.dir(f))
                            .resolve(String.format("%02d-%s.%s", i + 1, reqs.get(i).name(), FixtureGenerator.ext(f)));
                    assertEquals(f.gen(reqs.get(i).req()).text(), Files.readString(p, StandardCharsets.UTF_8), p.toString());
                    n++;
                }
            }
        }
        assertTrue(n >= 60, "fixtures checked: " + n);
    }
}
