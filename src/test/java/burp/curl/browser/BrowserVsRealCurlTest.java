package burp.curl.browser;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import burp.curl.BuiltRequest;
import burp.curl.Curl;
import burp.curl.FileAccess;
import burp.curl.browser.BrowserGenerators.Flavor;
import burp.curl.browser.BrowserGenerators.Gen;
import burp.curl.browser.BrowserGenerators.Req;
import burp.curl.testsupport.CaptureServer;
import burp.curl.testsupport.CurlRunner;
import burp.curl.testsupport.DiffPrinter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

/**
 * Ties the generators and both dialects to the real curl, which cannot run cmd syntax on this machine.
 *
 * <p>For every logical request: (a) the browser's BASH command is run with the real bash and curl against a loopback
 * capture server, and our parse of the same text must produce the same bytes; (b) our parse of the browser's CMD
 * command must produce the same bytes as well. When the cmd flavour is lossy for the request (tab, non-ASCII, CR ...)
 * the reference for (b) is the bash command of the generator's exact loss: the intended arguments mapped through the
 * proven loss function and written in UTF-8 bash quoting; real curl is still the judge of those bytes.
 * Normalisations are those of the differential harness: multipart boundaries and the default User-Agent version.
 */
class BrowserVsRealCurlTest {
    static final int RANDOM_PER_BROWSER = 320;
    private static final int BATCH = 25;
    private static final Pattern URL = Pattern.compile("^https?://([^/?#]*)(.*)$", Pattern.DOTALL);

    /** Points the request at the capture server (same IPv6 flavour of loopback when the URL had a bracketed host). */
    static Req toLoopback(Req r, int port) {
        Matcher m = URL.matcher(r.url());
        assertTrue(m.matches(), r.url());
        String host = m.group(1).startsWith("[") && CaptureServer.ipv6LoopbackAvailable() ? "[::1]" : "127.0.0.1";
        return r.withUrl("http://" + host + ":" + port + m.group(2));
    }

    /** A work item: the logical request prepared for one browser. */
    record Item(String name, Req req) {
    }

    private static List<Item> handWritten(Flavor bash) {
        List<Item> out = new ArrayList<>();
        for (Samples.Named s : Samples.nasty()) {
            Req r = Samples.avoidCoreBug(bash, Samples.clean(s.req()));
            if (Samples.notApplicable(bash, r) == null && Samples.generatorOutputUnusable(bash, bash.gen(r)) == null
                    && !Samples.splitsTheRequestOnTheWire(bash, bash.gen(r))) {
                out.add(new Item(s.name(), r));
            }
        }
        return out;
    }

    private static List<Item> random(Flavor bash, Flavor cmdOrNull, long seed) {
        Random rnd = new Random(seed);
        List<Item> out = new ArrayList<>();
        while (out.size() < RANDOM_PER_BROWSER) {
            Req r = Samples.avoidCoreBug(bash, Samples.clean(Samples.random(rnd)));
            if (Samples.notApplicable(bash, r) != null || Samples.generatorOutputUnusable(bash, bash.gen(r)) != null
                    || Samples.splitsTheRequestOnTheWire(bash, bash.gen(r))
                    || (cmdOrNull != null && Samples.splitsTheRequestOnTheWire(cmdOrNull, cmdOrNull.gen(r)))) {
                continue;
            }
            if (cmdOrNull != null && !BrowserRoundTripTest.allLossless(cmdOrNull, cmdOrNull.gen(r))) {
                continue; // random items are restricted to what the cmd generator carries losslessly
            }
            out.add(new Item("random#" + out.size(), r));
        }
        return out;
    }

    private static byte[] ours(String text) throws Exception {
        List<BuiltRequest> b = Curl.parse(text).build(FileAccess.DENY);
        assertEquals(1, b.size(), "requests built for:\n" + text);
        return b.get(0).raw();
    }

    private static String compare(String label, String text, byte[] curl, byte[] ours) {
        String rep = DiffPrinter.compare(text, List.of(curl), List.of(ours));
        return rep == null ? null : label + "\n" + rep;
    }

    /** Runs all items for one browser; returns the failure reports. */
    private static List<String> check(Flavor bash, Flavor cmdOrNull, List<Item> items, int[] counters) throws Exception {
        List<String> failures = new ArrayList<>();
        for (int from = 0; from < items.size(); from += BATCH) {
            List<Item> chunk = items.subList(from, Math.min(items.size(), from + BATCH));
            // per item: the browser's bash text, plus the bash text of the cmd flavour's exact meaning when that is lossy
            int[] bashIdx = new int[chunk.size()];
            int[] cmdIdx = new int[chunk.size()];
            RealCurlBatch.Outcome o = RealCurlBatch.run(port -> {
                List<String> cmds = new ArrayList<>();
                for (int i = 0; i < chunk.size(); i++) {
                    Req r = toLoopback(chunk.get(i).req(), port);
                    bashIdx[i] = cmds.size();
                    cmds.add(bash.gen(r).text());
                    if (cmdOrNull == null) {
                        cmdIdx[i] = -1;
                    } else if (Expectation.sameMeaning(bash, cmdOrNull, bash.gen(r), cmdOrNull.gen(r))) {
                        cmdIdx[i] = bashIdx[i];
                    } else {
                        cmdIdx[i] = cmds.size();
                        cmds.add(Expectation.bashOfCmdMeaning(cmdOrNull, cmdOrNull.gen(r)));
                    }
                }
                return cmds;
            });
            for (int i = 0; i < chunk.size(); i++) {
                Item it = chunk.get(i);
                byte[] curlBash = o.requests().get(bashIdx[i]);
                if (curlBash == null) {
                    failures.add(bash + " " + it.name() + ": the real curl sent no request\n" + o.diagnostics()
                            + o.commands().get(bashIdx[i]));
                    continue;
                }
                // (a) the browser's bash text
                Req r = toLoopback(it.req(), o.ports().get(bashIdx[i]));
                String bashText = bash.gen(r).text();
                counters[0]++;
                String bad = compare(bash + " bash " + it.name(), bashText, curlBash, ours(bashText));
                if (bad != null) {
                    failures.add(bad);
                }
                // (b) the browser's cmd text
                if (cmdOrNull != null) {
                    byte[] curlCmd = o.requests().get(cmdIdx[i]);
                    if (curlCmd == null) {
                        failures.add(cmdOrNull + " " + it.name() + ": the real curl sent no request for the cmd meaning\n"
                                + o.diagnostics() + o.commands().get(cmdIdx[i]));
                        continue;
                    }
                    String cmdText = cmdOrNull.gen(toLoopback(it.req(), o.ports().get(cmdIdx[i]))).text();
                    counters[1]++;
                    if (cmdIdx[i] == bashIdx[i]) {
                        counters[2]++;
                    }
                    bad = compare(cmdOrNull + " " + it.name() + (cmdIdx[i] == bashIdx[i] ? ""
                            : " (lossy: reference is the bash text of the exact loss)"), cmdText, curlCmd, ours(cmdText));
                    if (bad != null) {
                        failures.add(bad);
                    }
                }
            }
        }
        return failures;
    }

    private void run(Flavor bash, Flavor cmd, long seed) throws Exception {
        Assumptions.assumeTrue(RealCurlBatch.available(), "curl, bash >= 4.2 or a UTF-8 locale is missing");
        List<Item> items = new ArrayList<>(handWritten(bash));
        int hand = items.size();
        assertTrue(hand >= 60, "hand-written requests: " + hand);
        items.addAll(random(bash, cmd, seed));
        int[] counters = new int[3];
        List<String> failures = check(bash, cmd, items, counters);
        System.out.println("browser vs real curl " + bash + (cmd == null ? "" : " + " + cmd) + ": " + hand + " hand-written + "
                + RANDOM_PER_BROWSER + " random logical requests; bash comparisons " + counters[0] + ", cmd comparisons "
                + counters[1] + " (" + counters[2] + " with the browser's own bash text as reference); failures " + failures.size());
        for (String f : failures) {
            String[] ls = f.split("\n");
            StringBuilder one = new StringBuilder("  FAIL ").append(ls[0]);
            for (String l : ls) {
                if (l.startsWith("  curl: ") || l.startsWith("  ours: ") || l.startsWith("request count")) {
                    one.append(" | ").append(l.trim());
                }
            }
            System.out.println(one);
        }
        assertTrue(failures.isEmpty(), failures.size() + " mismatches, first ones:\n"
                + String.join("\n=========================\n", failures.subList(0, Math.min(3, failures.size()))));
    }

    @Test
    void chromeBashAndCmdEqualRealCurl() throws Exception {
        run(Flavor.CHROME_BASH, Flavor.CHROME_CMD, 21L);
    }

    @Test
    void firefoxBashAndCmdEqualRealCurl() throws Exception {
        run(Flavor.FIREFOX_BASH, Flavor.FIREFOX_CMD, 22L);
    }

    @Test
    void safariBashEqualsRealCurl() throws Exception {
        run(Flavor.SAFARI_BASH, null, 23L);
    }

    // ------------------------------------------------------------------------------------ proofs against real curl

    private static String captureWire(String bashText) throws IOException {
        RealCurlBatch.Outcome o = RealCurlBatch.run(port -> List.of(bashText.replace("PORT", Integer.toString(port))));
        return o.requests().get(0) == null ? null
                : new String(o.requests().get(0), java.nio.charset.StandardCharsets.ISO_8859_1);
    }

    @Test
    void realCurlRefusesHeadWithBodyWhichFirefoxEmitsForHeadWithUrlencodedBody() throws Exception {
        Assumptions.assumeTrue(RealCurlBatch.available(), "curl, bash >= 4.2 or a UTF-8 locale is missing");
        Req r = new Req("HEAD", "http://127.0.0.1:PORT/x", List.of(Samples.h("Content-Type", Samples.FORM_CT)), "a=1", false, false, null);
        String text = Flavor.FIREFOX_BASH.gen(r).text();
        assertTrue(text.contains("-I") && text.contains("--data-raw"), text);
        try (CaptureServer srv = CaptureServer.start()) {
            CurlRunner.Result res = RealCurlBatch.runOne(text.replace("PORT", Integer.toString(srv.port())));
            srv.close();
            assertEquals(2, res.exit(), "real curl exit code for -I with -d: " + res.output());
            assertEquals(0, srv.requests().size());
        }
    }

    @Test
    void realCurlDropsAnEmptyHeaderThatFirefoxAndSafariWriteAndKeepsChromes() throws Exception {
        Assumptions.assumeTrue(RealCurlBatch.available(), "curl, bash >= 4.2 or a UTF-8 locale is missing");
        Req r = Req.of("GET", "http://127.0.0.1:PORT/", Samples.h("X-Empty", ""), Samples.h("X-Keep", "v"));
        String chrome = captureWire(Flavor.CHROME_BASH.gen(r).text());
        assertTrue(chrome.contains("\r\nX-Empty:\r\n"), chrome);
        for (Flavor f : new Flavor[] {Flavor.FIREFOX_BASH, Flavor.SAFARI_BASH}) {
            String w = captureWire(f.gen(r).text());
            assertTrue(!w.contains("X-Empty") && w.contains("\r\nX-Keep: v\r\n"), f + ":\n" + w);
        }
    }

    @Test
    void firefoxDoesNotEscapeBracesSoRealCurlGlobsThem() throws Exception {
        Assumptions.assumeTrue(RealCurlBatch.available(), "curl, bash >= 4.2 or a UTF-8 locale is missing");
        Req r = Req.of("GET", "http://127.0.0.1:PORT/p?x={a,b}");
        String text = Flavor.FIREFOX_BASH.gen(r).text();
        RealCurlBatch.Outcome o = RealCurlBatch.run(port -> List.of(text.replace("PORT", Integer.toString(port))));
        // the batch helper expects one request per command; two requests are captured by the fallback as "none"
        assertTrue(o.requests().get(0) == null && o.diagnostics().contains("2 request(s)"), o.diagnostics());
        String chrome = Flavor.CHROME_BASH.gen(r).text();
        assertTrue(chrome.contains("\\{a,b\\}"), chrome);
        assertTrue(captureWire(chrome.replace("PORT", "PORT")) != null, "Chrome escapes the braces, one request");
    }

    @Test
    void nulCannotBeCarriedByAnyBashCommand() throws Exception {
        Assumptions.assumeTrue(RealCurlBatch.available(), "curl, bash >= 4.2 or a UTF-8 locale is missing");
        Req r = Req.of("GET", "http://127.0.0.1:PORT/", Samples.h("X-Nul", "a\u0000b"));
        String w = captureWire(Flavor.CHROME_BASH.gen(r).text());
        assertTrue(w.contains("\r\nX-Nul: a\r\n"), "bash truncates the argument at NUL:\n" + w);
    }
}
