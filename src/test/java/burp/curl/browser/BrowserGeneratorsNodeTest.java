package burp.curl.browser;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import burp.curl.browser.BrowserGenerators.Flavor;
import burp.curl.browser.BrowserGenerators.Hdr;
import burp.curl.browser.BrowserGenerators.JsError;
import burp.curl.browser.BrowserGenerators.Req;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

/**
 * Proves the Java ports in {@link BrowserGenerators} equal the real browser JavaScript (stored verbatim in
 * src/test/resources/browser/js, see SOURCES.md there), byte for byte, on the hand-written set and on thousands of
 * seeded random inputs including lone surrogates, C1 controls, exotic whitespace and malformed multipart bodies.
 */
class BrowserGeneratorsNodeTest {
    static final int RANDOM_PER_FLAVOR = 4000;

    private static final String[] WILD = {
        "\ud800", "\udc00", "\ud83d", "\ude00", "😀", "é", "ü", "日本語", "Ω", "ж", "\u0080", "\u0085", "\u009f", " ", "­",
        "Ā", "؜", " ", " ", " ", "​", "‍", " ", " ", " ", " ", "　",
        "﻿", "", "͸", "\u0001", "\u001f", "\u007f", "\u0000", "\u000b", "\u000c",
    };

    static String wildString(Random r) {
        int n = r.nextInt(12);
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < n; i++) {
            int k = r.nextInt(8);
            if (k == 0) {
                sb.append(WILD[r.nextInt(WILD.length)]);
            } else if (k == 1) {
                sb.append((char) (0x20 + r.nextInt(0x5f)));
            } else {
                sb.append(Samples.FRAGMENTS[r.nextInt(Samples.FRAGMENTS.length)]);
            }
        }
        return sb.toString();
    }

    private static final String[] SCHEMES = {"https://", "http://", "https://", "https://", "ws://", "wss://", "data:,",
        "blob:https://x.test/", "ftp://", "file:///", "chrome://", "HTTPS://", "javascript:", "filesystem:https://x.test/"};
    private static final String[] WILD_NAMES = {"Content-Type", "content-type", "Content-Length", "Host", ":authority", ":path",
        ":method", "Accept-Encoding", "Cookie", "cookie", "COOKIE", "X-A", "X-B", "0", "1", "10", "02", "4294967295", "4294967294",
        "x y", "", ":", "::x", "Origin"};
    private static final String[] WILD_CT = {"application/x-www-form-urlencoded", "multipart/form-data; boundary=----geckoformboundaryabc",
        "multipart/form-data;", "multipart/form-data", "APPLICATION/X-WWW-FORM-URLENCODED ; charset=x", "application/x-www-form-urlencoded\n",
        "application/x-www-form-urlencoded \t; a\nb", "text/plain", "application/json", "x/y; boundary=-----abc multipart/form-data;"};

    static Req wild(Random r) {
        String[] methods = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "get", "Post", wildString(r)};
        String url = SCHEMES[r.nextInt(SCHEMES.length)] + "h.test/" + wildString(r);
        List<Hdr> hs = new ArrayList<>();
        int nh = r.nextInt(6);
        for (int k = 0; k < nh; k++) {
            String name = r.nextInt(3) == 0 ? wildString(r) : WILD_NAMES[r.nextInt(WILD_NAMES.length)];
            String value;
            int c = r.nextInt(8);
            if (c == 0) {
                value = "";
            } else if (c == 1) {
                value = " \t";
            } else if (name.equalsIgnoreCase("content-type")) {
                value = WILD_CT[r.nextInt(WILD_CT.length)];
            } else {
                value = wildString(r);
            }
            hs.add(new Hdr(name, value));
        }
        String body = null;
        int b = r.nextInt(8);
        if (b == 0) {
            body = "";
        } else if (b == 1) {
            body = Samples.randomMultipart(r);
        } else if (b == 2) {
            body = "Content-Type: multipart/form-data; boundary=-----xyz\r\n\r\n--" + "-----xyz\r\nContent-Disposition: form-data; name=\"a\"; filename=\"f\"\r\n\r\nDATA\r\n-------xyz--\r\n";
        } else if (b == 3) {
            body = "x\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\na=" + wildString(r);
        } else if (b < 6) {
            body = wildString(r);
        }
        String sct = r.nextInt(3) == 0 ? null : WILD_CT[r.nextInt(WILD_CT.length)];
        return new Req(methods[r.nextInt(methods.length)], url, hs, body, r.nextBoolean(), r.nextBoolean(), sct);
    }

    @Test
    void javaPortsEqualTheRealJavaScript() throws Exception {
        Assumptions.assumeTrue(NodeRunner.available(), "node is not installed");
        for (Flavor f : Flavor.values()) {
            List<Req> reqs = new ArrayList<>();
            for (Samples.Named s : Samples.nasty()) {
                reqs.add(s.req());
            }
            Random rnd = new Random(0xB20_5E000L + f.ordinal());
            int fromRandom = f == Flavor.SAFARI_BASH ? RANDOM_PER_FLAVOR / 2 : RANDOM_PER_FLAVOR / 2;
            for (int i = 0; i < fromRandom; i++) {
                reqs.add(wild(rnd));
            }
            for (int i = 0; i < RANDOM_PER_FLAVOR - fromRandom; i++) {
                reqs.add(Samples.random(rnd));
            }
            List<String> lines = new ArrayList<>();
            for (Req r : reqs) {
                lines.add(NodeRunner.line(f, r));
            }
            List<String> js = NodeRunner.run(lines);
            assertEquals(reqs.size(), js.size(), "result count for " + f);
            int errors = 0;
            for (int i = 0; i < reqs.size(); i++) {
                String ours;
                try {
                    ours = f.gen(reqs.get(i)).text();
                } catch (JsError e) {
                    ours = "ERROR:" + e.getMessage();
                    errors++;
                }
                assertEquals(js.get(i), ours, f + " case " + i + ": " + describe(reqs.get(i)));
            }
            assertTrue(reqs.size() >= RANDOM_PER_FLAVOR, "enough cases for " + f);
            System.out.println("node validation " + f + ": " + reqs.size() + " cases identical (" + errors + " of them JS TypeErrors)");
        }
    }

    static String describe(Req r) {
        StringBuilder b = new StringBuilder(r.method() + " " + BrowserGenerators.show(r.url()));
        for (Hdr h : r.headers()) {
            b.append("\n  ").append(BrowserGenerators.show(h.name())).append(": ").append(BrowserGenerators.show(h.value()));
        }
        b.append("\n  body=").append(r.body() == null ? "null" : BrowserGenerators.show(r.body()));
        return b.toString();
    }
}
