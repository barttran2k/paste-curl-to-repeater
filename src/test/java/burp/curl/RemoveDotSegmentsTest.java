package burp.curl;

import org.junit.jupiter.api.Test;

import java.util.Random;

import static org.junit.jupiter.api.Assertions.assertEquals;

/** The linear dot-segment removal against the original (quadratic) implementation, kept here as the reference. */
class RemoveDotSegmentsTest {
    /** the implementation before the rewrite, verbatim */
    static String reference(String in) {
        StringBuilder out = new StringBuilder();
        String input = in;
        while (!input.isEmpty()) {
            if (input.startsWith("../")) {
                input = input.substring(3);
            } else if (input.startsWith("./")) {
                input = input.substring(2);
            } else if (input.startsWith("/./")) {
                input = input.substring(2);
            } else if (input.equals("/.")) {
                input = "/";
            } else if (input.startsWith("/../")) {
                input = input.substring(3);
                int slash = out.lastIndexOf("/");
                out.setLength(Math.max(slash, 0));
            } else if (input.equals("/..")) {
                input = "/";
                int slash = out.lastIndexOf("/");
                out.setLength(Math.max(slash, 0));
            } else if (input.equals(".") || input.equals("..")) {
                input = "";
            } else {
                int next = input.indexOf('/', 1);
                if (next < 0) {
                    next = input.length();
                }
                out.append(input, 0, next);
                input = input.substring(next);
            }
        }
        return out.toString();
    }

    @Test
    void sameAsTheReferenceForEveryShortStringOverASmallAlphabet() {
        char[] alphabet = {'/', '.', 'a', '?'};
        for (int len = 0; len <= 9; len++) {
            int total = (int) Math.pow(alphabet.length, len);
            for (int k = 0; k < total; k++) {
                char[] c = new char[len];
                int x = k;
                for (int j = 0; j < len; j++) {
                    c[j] = alphabet[x % alphabet.length];
                    x /= alphabet.length;
                }
                String s = new String(c);
                assertEquals(reference(s), CurlUrl.removeDotSegments(s), "input: " + s);
            }
        }
    }

    @Test
    void sameAsTheReferenceForRandomLongPaths() {
        Random r = new Random(42);
        String[] pieces = {"/", "/.", "/..", "./", "../", "/./", "/../", "a", "bc", ".", "..", "...", "%2e", ";x", "é"};
        for (int i = 0; i < 20000; i++) {
            StringBuilder sb = new StringBuilder(r.nextBoolean() ? "/" : "");
            int parts = r.nextInt(30);
            for (int j = 0; j < parts; j++) {
                sb.append(pieces[r.nextInt(pieces.length)]);
            }
            String s = sb.toString();
            assertEquals(reference(s), CurlUrl.removeDotSegments(s), "input: " + s);
        }
    }

    @Test
    void largeInputsAreQuick() {
        String s = "/a/..".repeat(200_000);
        long t0 = System.nanoTime();
        assertEquals(reference("/a/../b/./c/.."), CurlUrl.removeDotSegments("/a/../b/./c/.."));
        CurlUrl.removeDotSegments(s);
        CurlUrl.removeDotSegments("/./b".repeat(200_000));
        CurlUrl.removeDotSegments("/a".repeat(200_000));
        org.junit.jupiter.api.Assertions.assertTrue((System.nanoTime() - t0) / 1_000_000 < 1000);
    }
}
