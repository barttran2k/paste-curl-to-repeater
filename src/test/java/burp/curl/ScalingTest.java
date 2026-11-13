package burp.curl;

import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;

import java.util.ArrayList;
import java.util.List;
import java.util.function.IntFunction;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The paste path runs on the Swing event thread, so no input shape may take super-linear time.
 *
 * <p>Every shape is built at size n and 2n, run through {@code Curl.parse(...).build(...)} (best of several runs),
 * and must finish within {@link #BOUND_MS} and must not take much more than twice as long for twice the input.
 */
class ScalingTest {
    static final long BOUND_MS = 3000;
    static final double MAX_RATIO = 3.5;
    static final long NOISE_FLOOR_MS = 40;
    static final int RUNS = 4;

    record Shape(String name, int n, IntFunction<String> text) { }

    static String rep(String piece, int n) {
        return piece.repeat(n);
    }

    static List<Shape> shapes() {
        List<Shape> l = new ArrayList<>();
        // very long path, each segment kind
        for (String seg : new String[] {"/a", "/./b", "/a/..", "/..", "/.", "/%41", "/%2e%2e", "/a b", "/é", "//",
                "/a;b", "/?", "/a/../b/./c"}) {
            l.add(new Shape("path " + seg, 100_000, n -> "curl 'http://t.example" + rep(seg, n) + "'"));
        }
        l.add(new Shape("path dots then pop", 100_000, n -> "curl 'http://t.example" + rep("/a", n) + rep("/..", n) + "'"));
        l.add(new Shape("long single segment", 1_000_000, n -> "curl 'http://t.example/" + rep("a", n) + "'"));
        l.add(new Shape("long query", 200_000, n -> "curl 'http://t.example/p?" + rep("a=b&", n) + "'"));
        l.add(new Shape("long query via -G -d", 20_000, n -> "curl -G " + rep("-d a=b ", n) + "http://t.example/"));
        l.add(new Shape("long query appended to url with dots", 100_000,
                n -> "curl --url-query a=b http://t.example" + rep("/a/..", n)));
        l.add(new Shape("headers", 50_000, n -> "curl http://t.example/ " + rep("-H 'X-A: b' ", n)));
        l.add(new Shape("distinct headers", 25_000, n -> {
            StringBuilder sb = new StringBuilder("curl http://t.example/");
            for (int i = 0; i < n; i++) {
                sb.append(" -H 'X-").append(i).append(": v'");
            }
            return sb.toString();
        }));
        l.add(new Shape("data pieces", 50_000, n -> "curl http://t.example/ " + rep("-d a=b ", n)));
        l.add(new Shape("data-urlencode pieces", 50_000, n -> "curl http://t.example/ " + rep("--data-urlencode 'a=b c' ", n)));
        l.add(new Shape("form fields", 20_000, n -> "curl http://t.example/ " + rep("-F a=b ", n)));
        l.add(new Shape("raw body single quotes", 2_500_000, n -> "curl http://t.example/ --data-raw '" + rep("x", n) + "'"));
        l.add(new Shape("raw body double quotes", 2_500_000, n -> "curl http://t.example/ --data-raw \"" + rep("x", n) + "\""));
        l.add(new Shape("raw body dollar quotes", 2_500_000, n -> "curl http://t.example/ --data-raw $'" + rep("x", n) + "'"));
        l.add(new Shape("raw body unquoted", 2_500_000, n -> "curl http://t.example/ --data-raw " + rep("x", n)));
        l.add(new Shape("raw body escapes", 1_000_000, n -> "curl http://t.example/ --data-raw " + rep("\\ x", n / 3)));
        l.add(new Shape("raw body dollar escapes", 1_000_000, n -> "curl http://t.example/ --data-raw $'" + rep("\\n\\x41", n / 6) + "'"));
        l.add(new Shape("raw body double-quote escapes", 1_000_000, n -> "curl http://t.example/ --data-raw \"" + rep("\\\"a$", n / 3) + "\""));
        l.add(new Shape("urls", 20_000, n -> {
            StringBuilder sb = new StringBuilder("curl");
            for (int i = 0; i < n; i++) {
                sb.append(" http://t.example/").append(i);
            }
            return sb.toString();
        }));
        l.add(new Shape("next groups", 20_000, n -> "curl http://t.example/ " + rep("--next -X POST http://t.example/ ", n)));
        l.add(new Shape("cookie string", 100_000, n -> {
            StringBuilder sb = new StringBuilder("curl http://t.example/ -b '");
            for (int i = 0; i < n; i++) {
                sb.append("c").append(i).append("=v; ");
            }
            return sb.append("'").toString();
        }));
        l.add(new Shape("cookie option repeated", 20_000, n -> "curl http://t.example/ " + rep("-b a=b ", n)));
        l.add(new Shape("nested command substitution", 1_500, n -> "curl http://t.example/ -d " + rep("\"$(", n) + "x" + rep(")\"", n)));
        l.add(new Shape("nested plain substitution", 1_500, n -> "curl http://t.example/ -d " + rep("$(", n) + "x" + rep(")", n)));
        l.add(new Shape("nested braces", 5_000, n -> "curl http://t.example/ -d " + rep("${a:-", n) + "x" + rep("}", n)));
        l.add(new Shape("many commands", 20_000, n -> rep("curl http://t.example/\n", n)));
        l.add(new Shape("many pipes and ors", 20_000, n -> "curl http://t.example/" + rep(" | cat", n)));
        l.add(new Shape("line continuations", 100_000, n -> "curl \\\n" + rep("  -H 'a: b' \\\n", n) + " http://t.example/"));
        l.add(new Shape("cmd dialect", 40_000,
                n -> "curl ^\"http://t.example/^\" " + rep("-H ^\"A: b^\" ", n)));
        l.add(new Shape("cmd dialect lines", 40_000,
                n -> "curl.exe ^\n" + rep("  -H ^\"A: b^\" ^\n", n) + "  ^\"http://t.example/^\""));
        l.add(new Shape("cmd dialect carets", 400_000, n -> "curl ^\"http://t.example/^\" -d ^\"" + rep("^^a", n) + "^\""));
        l.add(new Shape("many options with abbreviations", 20_000, n -> "curl http://t.example/ " + rep("--head --compr ", n / 2)));
        l.add(new Shape("variables", 5_000, n -> {
            StringBuilder sb = new StringBuilder("curl http://t.example/");
            for (int i = 0; i < n; i++) {
                sb.append(" --variable v").append(i).append("=x");
            }
            return sb.append(" --expand-data '{{v1}}'").toString();
        }));
        return l;
    }

    static long timeMs(String text) {
        long best = Long.MAX_VALUE;
        for (int i = 0; i < RUNS; i++) {
            long t0 = System.nanoTime();
            try {
                Curl.parse(text).build(FileAccess.DENY);
            } catch (CurlParseException e) {
                // a refusal is fine, it must just be quick
            }
            best = Math.min(best, (System.nanoTime() - t0) / 1_000_000);
        }
        return best;
    }

    @TestFactory
    List<DynamicTest> everyShapeScalesLinearly() {
        List<DynamicTest> tests = new ArrayList<>();
        for (Shape s : shapes()) {
            tests.add(DynamicTest.dynamicTest(s.name(), () -> {
                String small = s.text().apply(s.n());
                String big = s.text().apply(2 * s.n());
                long t1 = timeMs(small);
                long t2 = timeMs(big);
                System.out.println("SCALING " + s.name() + " n=" + s.n() + " " + t1 + " ms, 2n " + t2 + " ms");
                assertTrue(t2 <= BOUND_MS, s.name() + ": 2n took " + t2 + " ms (bound " + BOUND_MS + ")");
                assertTrue(t2 <= MAX_RATIO * Math.max(t1, NOISE_FLOOR_MS),
                        s.name() + ": doubling the input took " + t1 + " ms -> " + t2 + " ms");
            }));
        }
        return tests;
    }
}
