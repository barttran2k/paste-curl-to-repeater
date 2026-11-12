package burp.curl.browser;

import burp.curl.browser.BrowserGenerators.Flavor;
import burp.curl.browser.BrowserGenerators.Gen;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * What curl must send for the arguments a browser generator intends, after the exact information loss of the
 * generator's shell escaping ({@link #loss}). Header handling follows curl's {@code Curl_add_custom_headers}: the
 * {@code -H} string is sent verbatim, unless nothing but white space follows the colon (header removed) or the string
 * is {@code Name;} (sent as {@code Name:}).
 */
final class Expectation {
    final String method;
    final String target;
    final List<byte[]> headerLines = new ArrayList<>();
    /** Header names whose -H argument has an empty value: curl must not send them. */
    final List<String> removedHeaders = new ArrayList<>();
    final byte[] body;
    final List<byte[]> argvBytes = new ArrayList<>();

    private Expectation(String method, String target, byte[] body) {
        this.method = method;
        this.target = target;
        this.body = body;
    }

    // ------------------------------------------------------------------ loss of the shell escaping

    /** JS-level normalisation of Chrome's cmd escaping: non-printables become one space per UTF-16 unit, CR/CRLF become LF. */
    static String chromeCmdLoss(String s) {
        StringBuilder b = new StringBuilder();
        for (char c : s.toCharArray()) {
            b.append((c >= ' ' && c <= '~') || c == '\r' || c == '\n' ? c : ' ');
        }
        return b.toString().replace("\r\n", "\n").replace('\r', '\n');
    }

    /** Firefox's cmd escaping: JS white space other than CR/LF becomes a space, CR/CRLF become LF. */
    static String firefoxCmdLoss(String s) {
        StringBuilder b = new StringBuilder();
        for (char c : s.toCharArray()) {
            b.append(BrowserGenerators.jsWs(c) && c != '\r' && c != '\n' ? ' ' : c);
        }
        return b.toString().replace("\r\n", "\n").replace('\r', '\n');
    }

    /** What bash makes of the hex escapes (backslash x and backslash u) of Firefox's and Safari's escapeStringPosix. */
    static byte[] bashAnsiBytes(String s) {
        ByteArrayOutputStream b = new ByteArrayOutputStream();
        for (char c : s.toCharArray()) {
            if (c < 0x100) {
                b.write(c);
            } else if (c < 0x800) {
                b.write(0xC0 | (c >> 6));
                b.write(0x80 | (c & 0x3F));
            } else {
                b.write(0xE0 | (c >> 12));
                b.write(0x80 | ((c >> 6) & 0x3F));
                b.write(0x80 | (c & 0x3F));
            }
        }
        return b.toByteArray();
    }

    /** @return the bytes curl receives for the intended argument s, in the given flavour */
    static byte[] loss(Flavor f, String s) {
        return switch (f) {
            case CHROME_BASH -> s.getBytes(StandardCharsets.UTF_8);
            case CHROME_CMD -> chromeCmdLoss(s).getBytes(StandardCharsets.UTF_8);
            case FIREFOX_CMD -> firefoxCmdLoss(s).getBytes(StandardCharsets.UTF_8);
            case FIREFOX_BASH, SAFARI_BASH -> bashAnsiBytes(s);
        };
    }

    /** @return true when the flavour loses nothing of s */
    static boolean lossless(Flavor f, String s) {
        return Arrays.equals(loss(f, s), s.getBytes(StandardCharsets.UTF_8));
    }

    // ------------------------------------------------------------------ interpretation

    private static String latin1(byte[] b) {
        return new String(b, StandardCharsets.ISO_8859_1);
    }

    private static byte[] bytes(String latin1) {
        return latin1.getBytes(StandardCharsets.ISO_8859_1);
    }

    private static boolean isSpace(char c) {
        return c == ' ' || c == '\t' || c == '\n' || c == 0x0b || c == '\f' || c == '\r';
    }

    /** @return the expected request for the generator output */
    static Expectation of(Flavor f, Gen g) {
        List<String> a = g.argv();
        String url = null;
        String method = null;
        boolean head = false;
        boolean globoff = false;
        byte[] body = null;
        List<byte[]> headers = new ArrayList<>();
        List<byte[]> cookies = new ArrayList<>();
        for (int i = 0; i < a.size(); i++) {
            String w = a.get(i);
            switch (w) {
                case "--url" -> url = a.get(++i);
                case "-X" -> method = a.get(++i);
                case "-I" -> head = true;
                case "-H" -> headers.add(loss(f, a.get(++i)));
                case "-b" -> cookies.add(loss(f, a.get(++i)));
                case "--data-raw", "--data-binary", "--data" -> body = loss(f, a.get(++i));
                case "--globoff" -> globoff = true;
                case "--insecure", "--compressed" -> { }
                default -> {
                    if (w.startsWith("-")) {
                        throw new IllegalStateException("unknown generator option " + w);
                    }
                    url = w;
                }
            }
        }
        if (url == null) {
            throw new IllegalStateException("no url in " + a);
        }
        String m = method != null ? method : head ? "HEAD" : body != null ? "POST" : "GET";
        String u = latin1(loss(f, url));
        if (!globoff) {
            u = u.replaceAll("\\\\([\\[\\]{}])", "$1");
        }
        Expectation e = new Expectation(m, target(u), body == null ? new byte[0] : body);
        for (byte[] h : headers) {
            String s = latin1(h);
            int colon = s.indexOf(':');
            if (colon >= 0) {
                int p = colon + 1;
                while (p < s.length() && isSpace(s.charAt(p))) {
                    p++;
                }
                if (p < s.length()) {
                    // curl rebuilds a custom Host header as "Host:" + the text after the colon
                    e.headerLines.add(s.substring(0, colon).equalsIgnoreCase("host") ? bytes("Host:" + s.substring(colon + 1)) : h);
                } else {
                    e.removedHeaders.add(s.substring(0, colon));
                }
            } else if (s.endsWith(";")) {
                e.headerLines.add(bytes(s.substring(0, s.length() - 1) + ":"));
            }
        }
        for (byte[] c : cookies) {
            e.headerLines.add(bytes("Cookie: " + latin1(c)));
        }
        return e;
    }

    /** The request target curl sends for an absolute http(s) URL (fragment dropped, empty path becomes /). */
    static String target(String url) {
        int hash = url.indexOf('#');
        String u = hash >= 0 ? url.substring(0, hash) : url;
        int auth = u.indexOf("://") + 3;
        int cut = auth;
        while (cut < u.length() && "/?".indexOf(u.charAt(cut)) < 0) {
            cut++;
        }
        String rest = u.substring(cut);
        if (rest.isEmpty()) {
            return "/";
        }
        return rest.charAt(0) == '?' ? "/" + rest : rest;
    }

    // ------------------------------------------------------------------ verification

    private static int indexOf(byte[] hay, byte[] needle, int from, int to) {
        outer:
        for (int i = from; i + needle.length <= to; i++) {
            for (int k = 0; k < needle.length; k++) {
                if (hay[i + k] != needle[k]) {
                    continue outer;
                }
            }
            return i;
        }
        return -1;
    }

    /**
     * @param raw the request bytes we built
     * @return null when they satisfy the expectation, otherwise a description of the first violation
     */
    String check(byte[] raw) {
        byte[] crlf = {'\r', '\n'};
        int lineEnd = indexOf(raw, crlf, 0, raw.length);
        if (lineEnd < 0) {
            return "no request line";
        }
        String line = latin1(Arrays.copyOfRange(raw, 0, lineEnd));
        String want = method + " " + target + " HTTP/1.1";
        if (!line.equals(want)) {
            return "request line: expected [" + want + "] but was [" + line + "]";
        }
        int bodyStart = raw.length - body.length;
        if (bodyStart < lineEnd + 4 || !Arrays.equals(Arrays.copyOfRange(raw, bodyStart, raw.length), body)
                || !Arrays.equals(Arrays.copyOfRange(raw, bodyStart - 4, bodyStart), new byte[] {13, 10, 13, 10})) {
            return "body: expected " + body.length + " bytes [" + latin1(body).replace("\r", "\\r").replace("\n", "\\n")
                    + "] after the blank line; request ends with ["
                    + latin1(Arrays.copyOfRange(raw, Math.max(0, raw.length - body.length - 8), raw.length))
                            .replace("\r", "\\r").replace("\n", "\\n") + "]";
        }
        for (byte[] h : headerLines) {
            byte[] needle = new byte[h.length + 4];
            needle[0] = 13;
            needle[1] = 10;
            System.arraycopy(h, 0, needle, 2, h.length);
            needle[needle.length - 2] = 13;
            needle[needle.length - 1] = 10;
            if (indexOf(raw, needle, lineEnd, bodyStart) < 0) {
                return "header line missing: [" + latin1(h).replace("\r", "\\r").replace("\n", "\\n") + "]";
            }
        }
        String head = latin1(Arrays.copyOfRange(raw, lineEnd, bodyStart)).toLowerCase(java.util.Locale.ROOT);
        for (String name : removedHeaders) {
            if (head.contains("\r\n" + name.toLowerCase(java.util.Locale.ROOT) + ":")) {
                return "header with empty value must not be sent: " + name;
            }
        }
        return null;
    }

    /** True when the bash and the cmd text of the browser mean the same bytes for every intended argument. */
    static boolean sameMeaning(Flavor bash, Flavor cmd, Gen bashGen, Gen cmdGen) {
        if (!bashGen.argv().equals(cmdGen.argv())) {
            return false;
        }
        for (String a : bashGen.argv()) {
            if (!java.util.Arrays.equals(Expectation.loss(bash, a), Expectation.loss(cmd, a))) {
                return false;
            }
        }
        return true;
    }

    /** Bash text of exactly what the cmd flavour means: intended arguments through the cmd loss, UTF-8 quoting. */
    static String bashOfCmdMeaning(Flavor cmd, Gen cmdGen) {
        StringBuilder b = new StringBuilder("curl");
        for (String a : cmdGen.argv()) {
            b.append(' ').append(BrowserGenerators.chromePosix(new String(Expectation.loss(cmd, a), StandardCharsets.UTF_8)));
        }
        return b.toString();
    }
}
