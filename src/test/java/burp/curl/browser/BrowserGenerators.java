package burp.curl.browser;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Java ports of the "Copy as cURL" generators of Chrome DevTools, Firefox DevTools and Safari Web Inspector.
 * The sources are in {@code src/test/resources/browser/js/} (see SOURCES.md there); {@code BrowserGeneratorsNodeTest}
 * proves byte-for-byte equality with the real JavaScript.
 *
 * <p>Besides the clipboard text every generator reports the argument list it <em>intends</em> curl to receive
 * (before the shell's escaping loses information), so tests can model the loss separately from the generator.
 */
public final class BrowserGenerators {
    private BrowserGenerators() {
    }

    /** A request header. */
    public record Hdr(String name, String value) {
    }

    /**
     * The request as a browser knows it.
     * @param method request method
     * @param url absolute URL
     * @param headers ordered request headers
     * @param body request body text or null
     * @param insecure Chrome: security state Insecure
     * @param respEncoded Firefox: the response has a content-encoding header
     * @param safariContentType Safari: {@code requestDataContentType} (null = none)
     */
    public record Req(String method, String url, List<Hdr> headers, String body, boolean insecure,
                      boolean respEncoded, String safariContentType) {
        /** @return a request with no body and default flags */
        public static Req of(String method, String url, Hdr... headers) {
            return new Req(method, url, List.of(headers), null, false, false, null);
        }

        /** @return a copy with a body (Safari content type taken from the Content-Type header) */
        public Req withBody(String b) {
            String ct = null;
            for (Hdr h : headers) {
                if (h.name.equalsIgnoreCase("content-type")) {
                    ct = h.value;
                }
            }
            return new Req(method, url, headers, b, insecure, respEncoded, safariContentType != null ? safariContentType : ct);
        }

        /** @return a copy with another URL */
        public Req withUrl(String u) {
            return new Req(method, u, headers, body, insecure, respEncoded, safariContentType);
        }

        /** @return a copy with other headers */
        public Req withHeaders(List<Hdr> h) {
            return new Req(method, url, h, body, insecure, respEncoded, safariContentType);
        }
    }

    /**
     * Generator output.
     * @param text the clipboard text
     * @param argv the intended arguments after the command word, before shell escaping loses anything
     */
    public record Gen(String text, List<String> argv) {
    }

    /** A JS TypeError the original code would throw. */
    public static final class JsError extends RuntimeException {
        private static final long serialVersionUID = 1L;

        JsError(String m) {
            super(m);
        }
    }

    // ------------------------------------------------------------------------------------ JS helpers

    /** JS {@code \s} (WhiteSpace + LineTerminator). */
    public static boolean jsWs(int c) {
        return c == 9 || c == 10 || c == 11 || c == 12 || c == 13 || c == 32 || c == 0xA0 || c == 0x1680
                || (c >= 0x2000 && c <= 0x200A) || c == 0x2028 || c == 0x2029 || c == 0x202F || c == 0x205F
                || c == 0x3000 || c == 0xFEFF;
    }

    static String jsTrim(String s) {
        int a = 0;
        int b = s.length();
        while (a < b && jsWs(s.charAt(a))) {
            a++;
        }
        while (b > a && jsWs(s.charAt(b - 1))) {
            b--;
        }
        return s.substring(a, b);
    }

    static String jsTrimStart(String s) {
        int a = 0;
        while (a < s.length() && jsWs(s.charAt(a))) {
            a++;
        }
        return s.substring(a);
    }

    static boolean alnum(int c) {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9');
    }

    /** {@code s.replace(/%(?=[a-zA-Z0-9_])/g, "%^")} */
    static String percentCaret(String s) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            sb.append(c);
            if (c == '%' && i + 1 < s.length() && (alnum(s.charAt(i + 1)) || s.charAt(i + 1) == '_')) {
                sb.append('^');
            }
        }
        return sb.toString();
    }

    /** {@code s.replace(/\r?\n|\r/g, "^\n\n")} */
    static String newlines(String s) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '\r') {
                if (i + 1 < s.length() && s.charAt(i + 1) == '\n') {
                    i++;
                }
                sb.append("^\n\n");
            } else if (c == '\n') {
                sb.append("^\n\n");
            } else {
                sb.append(c);
            }
        }
        return sb.toString();
    }

    static boolean jsC(int cp) {
        int t = Character.getType(cp);
        return t == Character.CONTROL || t == Character.FORMAT || t == Character.SURROGATE
                || t == Character.PRIVATE_USE || t == Character.UNASSIGNED;
    }

    static String hex(int v, int pad) {
        String h = Integer.toHexString(v);
        return "0".repeat(Math.max(0, pad - h.length())) + h;
    }

    static String bracketEscape(String s) {
        return s.replaceAll("[\\[{}\\]]", "\\\\$0");
    }

    // ------------------------------------------------------------------------------------ Chrome

    /** Chrome escapeStringWin. */
    public static String chromeWin(String str) {
        String s = str.replace("\\", "\\\\").replace("\"", "\"\"");
        StringBuilder b = new StringBuilder();
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            boolean ok = alnum(c) || jsWs(c) || "_-:=+~'/.',?;*".indexOf(c) >= 0;
            if (!ok) {
                b.append('^');
            }
            b.append(c);
        }
        s = percentCaret(b.toString());
        b = new StringBuilder();
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            b.append((c >= ' ' && c <= '~') || c == '\r' || c == '\n' ? c : ' ');
        }
        return "^\"" + newlines(b.toString()) + "^\"";
    }

    /** Chrome escapeStringPosix. */
    public static String chromePosix(String str) {
        boolean need = false;
        for (int i = 0; i < str.length(); i++) {
            char c = str.charAt(i);
            if (c <= 0x1f || (c >= 0x7f && c <= 0x9f) || c == '!' || c == '\'') {
                need = true;
                break;
            }
        }
        if (!need) {
            return "'" + str + "'";
        }
        StringBuilder b = new StringBuilder("$'");
        for (int i = 0; i < str.length(); i++) {
            char c = str.charAt(i);
            if (c == '\\') {
                b.append("\\\\");
            } else if (c == '\'') {
                b.append("\\'");
            } else if (c == '\n') {
                b.append("\\n");
            } else if (c == '\r') {
                b.append("\\r");
            } else if (c <= 0x1f || (c >= 0x7f && c <= 0x9f) || c == '!') {
                b.append("\\u").append(hex(c, 4));
            } else {
                b.append(c);
            }
        }
        return b.append('\'').toString();
    }

    private static final Set<String> CHROME_IGNORED = Set.of("accept-encoding", "host", "method", "path", "scheme",
            "version", "authority", "protocol");

    /** NetworkLogView.generateCurlCommand. */
    public static Gen chrome(Req r, boolean win) {
        List<String> command = new ArrayList<>();
        List<String> argv = new ArrayList<>();
        Set<String> ignored = new HashSet<>(CHROME_IGNORED);
        java.util.function.Function<String, String> esc = win ? BrowserGenerators::chromeWin : BrowserGenerators::chromePosix;
        if (!chromeWebSafe(r.url())) {
            return new Gen("# Unsupported URL scheme", List.of());
        }
        command.add("--url " + bracketEscape(esc.apply(r.url())));
        argv.add("--url");
        argv.add(bracketEscape(r.url()));
        String inferred = "GET";
        List<String> data = new ArrayList<>();
        List<String> dataArgv = new ArrayList<>();
        if (r.body() != null && !r.body().isEmpty()) {
            data.add("--data-raw " + esc.apply(r.body()));
            dataArgv.add("--data-raw");
            dataArgv.add(r.body());
            ignored.add("content-length");
            inferred = "POST";
        }
        if (!r.method().equals(inferred)) {
            command.add("-X " + esc.apply(r.method()));
            argv.add("-X");
            argv.add(r.method());
        }
        for (Hdr h : r.headers()) {
            String name = h.name().startsWith(":") ? h.name().substring(1) : h.name();
            if (ignored.contains(name.toLowerCase(Locale.ROOT))) {
                continue;
            }
            String value = h.value();
            if (jsTrim(value).isEmpty()) {
                command.add("-H " + esc.apply(name + ";"));
                argv.add("-H");
                argv.add(name + ";");
            } else if (name.toLowerCase(Locale.ROOT).equals("cookie") && value.contains("=")) {
                command.add("-b " + esc.apply(value));
                argv.add("-b");
                argv.add(value);
            } else {
                command.add("-H " + esc.apply(name + ": " + value));
                argv.add("-H");
                argv.add(name + ": " + value);
            }
        }
        command.addAll(data);
        argv.addAll(dataArgv);
        if (r.insecure()) {
            command.add("--insecure");
            argv.add("--insecure");
        }
        String join = command.size() >= 3 ? (win ? " ^\n  " : " \\\n  ") : " ";
        return new Gen("curl " + String.join(join, command), argv);
    }

    /** Common.ParsedURL.hasWebSafeScheme for the http(s)/ws(s)/data schemes and the blob: / filesystem: rejection. */
    static boolean chromeWebSafe(String url) {
        Matcher m = Pattern.compile("^([A-Za-z][A-Za-z0-9+.-]*):").matcher(jsTrimStart(url));
        if (!m.find()) {
            return false;
        }
        String scheme = m.group(1).toLowerCase(Locale.ROOT);
        return Set.of("http", "https", "ws", "wss", "data").contains(scheme);
    }

    // ------------------------------------------------------------------------------------ Firefox

    /** Firefox escapeStringWin. */
    public static String firefoxWin(String str) {
        String s = str.replace("\\", "\\\\").replace("\"", "\\\"");
        StringBuilder b = new StringBuilder();
        for (int i = 0; i < s.length();) {
            int cp = s.codePointAt(i);
            i += Character.charCount(cp);
            boolean ok = alnum(cp) || jsWs(cp) || (cp < 128 && "-_:=+~/.',?;()*`".indexOf(cp) >= 0) || jsC(cp);
            if (!ok) {
                b.append('^');
            }
            b.appendCodePoint(cp);
        }
        s = percentCaret(b.toString());
        b = new StringBuilder();
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            b.append(jsWs(c) && c != '\r' && c != '\n' ? ' ' : c);
        }
        return "^\"" + newlines(b.toString()) + "^\"";
    }

    /** Firefox escapeStringPosix. */
    public static String firefoxPosix(String str) {
        return ansiOrSingle(str, true);
    }

    /** Safari escapeStringPosix: like Firefox's but a bare ! does not trigger ANSI-C quoting. */
    public static String safariPosix(String str) {
        return ansiOrSingle(str, false);
    }

    private static String ansiOrSingle(String str, boolean bangTriggers) {
        boolean need = false;
        for (int i = 0; i < str.length(); i++) {
            char c = str.charAt(i);
            if (c < 0x20 || c > 0x7e || (bangTriggers && c == '!') || c == '\'') {
                need = true;
                break;
            }
        }
        if (!need) {
            return "'" + str + "'";
        }
        StringBuilder b = new StringBuilder("$'");
        for (int i = 0; i < str.length(); i++) {
            char c = str.charAt(i);
            if (c == '\\') {
                b.append("\\\\");
            } else if (c == '\'') {
                b.append("\\'");
            } else if (c == '\n') {
                b.append("\\n");
            } else if (c == '\r') {
                b.append("\\r");
            } else if (c == '!') {
                b.append("\\041");
            } else if (c < 0x20 || c > 0x7e) {
                b.append(c < 256 ? "\\x" : "\\u").append(hex(c, c < 256 ? 2 : 4));
            } else {
                b.append(c);
            }
        }
        return b.append('\'').toString();
    }

    private static String findHeader(List<Hdr> headers, String name) {
        for (Hdr h : headers) {
            if (h.name().toLowerCase(Locale.ROOT).equals(name.toLowerCase(Locale.ROOT))) {
                return h.value();
            }
        }
        return null;
    }

    private static final Pattern BOUNDARY = Pattern.compile("(?<![A-Za-z0-9_])boundary=(-{3,}[A-Za-z0-9_]+)",
            Pattern.CASE_INSENSITIVE);

    private static String multipartBoundary(Req r) {
        String ct = findHeader(r.headers(), "Content-Type");
        if (ct != null) {
            Matcher m = BOUNDARY.matcher(ct);
            if (m.find()) {
                return m.group(1);
            }
        }
        Matcher m = BOUNDARY.matcher(r.body());
        if (!m.find()) {
            throw new JsError("TypeError");
        }
        return m.group(1);
    }

    private static boolean isUrlEncoded(Req r) {
        String p = r.body();
        if (p == null || p.isEmpty()) {
            return false;
        }
        if (p.toLowerCase(Locale.ROOT).contains("content-type: application/x-www-form-urlencoded")) {
            return true;
        }
        String ct = findHeader(r.headers(), "content-type");
        return ct != null && ct.toLowerCase(Locale.ROOT).contains("application/x-www-form-urlencoded");
    }

    private static boolean isMultipart(Req r) {
        String p = r.body();
        if (p == null || p.isEmpty()) {
            return false;
        }
        if (p.toLowerCase(Locale.ROOT).contains("content-type: multipart/form-data")) {
            return true;
        }
        String ct = findHeader(r.headers(), "content-type");
        return ct != null && ct.toLowerCase(Locale.ROOT).contains("multipart/form-data;");
    }

    private static List<String> splitJs(String s, String sep) {
        List<String> out = new ArrayList<>();
        int from = 0;
        while (true) {
            int at = s.indexOf(sep, from);
            if (at < 0) {
                out.add(s.substring(from));
                return out;
            }
            out.add(s.substring(from, at));
            from = at + sep.length();
        }
    }

    private static String removeBinaryData(String multipartText, String boundaryIn) {
        StringBuilder result = new StringBuilder();
        String boundary = "--" + boundaryIn;
        for (String part : splitJs(multipartText, boundary)) {
            String line = splitJs(jsTrimStart(part), "\r\n").get(0);
            if (line.isEmpty()) {
                continue;
            }
            line = line.toLowerCase(Locale.ROOT);
            if (line.contains("content-disposition: form-data")) {
                if (line.contains("filename=")) {
                    String headers = splitJs(part, "\r\n\r\n").get(0);
                    result.append(boundary).append(headers).append("\r\n\r\n");
                } else {
                    result.append(boundary).append(part);
                }
            }
        }
        return result.append(boundary).append("--\r\n").toString();
    }

    private static List<Hdr> headersFromMultipart(String text) {
        List<Hdr> headers = new ArrayList<>();
        if (text == null || text.isEmpty() || text.startsWith("---")) {
            return headers;
        }
        int index = text.indexOf("\r\n\r\n");
        if (index == -1) {
            return headers;
        }
        String lastName = null;
        for (String line : splitJs(text.substring(0, index), "\r\n")) {
            if (lastName != null && !line.isEmpty() && jsWs(line.charAt(0))) {
                headers.add(new Hdr(lastName, jsTrim(line)));
                continue;
            }
            int colon = line.indexOf(':');
            if (colon == -1) {
                continue;
            }
            lastName = jsTrim(line.substring(0, colon));
            headers.add(new Hdr(lastName, jsTrim(line.substring(colon + 1))));
        }
        return headers;
    }

    /** Curl.generateCommand. */
    public static Gen firefox(Req r, boolean win) {
        java.util.function.Function<String, String> esc = win ? BrowserGenerators::firefoxWin : BrowserGenerators::firefoxPosix;
        java.util.function.Function<String, String> ifNeeded = v -> v.matches("[a-zA-Z-]+") ? v : esc.apply(v);
        List<String> parts = new ArrayList<>();
        List<String> argv = new ArrayList<>();
        parts.add(esc.apply(r.url()));
        argv.add(r.url());
        if (r.url().contains("[") || r.url().contains("]")) {
            parts.add("--globoff");
            argv.add("--globoff");
        }
        Set<String> ignored = new HashSet<>();
        String postDataText = null;
        boolean multipart = isMultipart(r);
        List<String> postData = new ArrayList<>();
        List<String> postArgv = new ArrayList<>();
        if (multipart) {
            postDataText = r.body();
            postData.add("--data-binary");
            String text = removeBinaryData(postDataText, multipartBoundary(r));
            postData.add(ifNeeded.apply(text));
            postArgv.add("--data-binary");
            postArgv.add(text);
            ignored.add("content-length");
        } else if (r.body() != null && !r.body().isEmpty()
                && (isUrlEncoded(r) || List.of("PUT", "POST", "PATCH").contains(r.method()))) {
            postDataText = r.body();
            List<String> lines = splitJs(postDataText, "\r\n");
            String last = lines.get(lines.size() - 1);
            postData.add("--data-raw " + ifNeeded.apply(last));
            postArgv.add("--data-raw");
            postArgv.add(last);
            ignored.add("content-length");
        }
        ignored.add("host");
        if (r.respEncoded()) {
            parts.add("--compressed");
            argv.add("--compressed");
        }
        if (r.method().equals("HEAD")) {
            parts.add("-I");
            argv.add("-I");
        } else if (!r.method().equals("GET")) {
            parts.add("-X " + ifNeeded.apply(r.method()));
            argv.add("-X");
            argv.add(r.method());
        }
        List<Hdr> headers = new ArrayList<>(r.headers());
        if (multipart) {
            headers.addAll(headersFromMultipart(postDataText));
        }
        for (Hdr h : headers) {
            if (ignored.contains(h.name().toLowerCase(Locale.ROOT))) {
                continue;
            }
            parts.add("-H " + ifNeeded.apply(h.name() + ": " + h.value()));
            argv.add("-H");
            argv.add(h.name() + ": " + h.value());
        }
        parts.addAll(postData);
        argv.addAll(postArgv);
        String join = parts.size() >= 3 ? (win ? " ^\n  " : " \\\n  ") : " ";
        return new Gen((win ? "curl.exe " : "curl ") + String.join(join, parts), argv);
    }

    // ------------------------------------------------------------------------------------ Safari

    private static boolean arrayIndex(String k) {
        if (k.isEmpty() || k.length() > 10 || (k.length() > 1 && k.charAt(0) == '0')) {
            return false;
        }
        for (int i = 0; i < k.length(); i++) {
            if (k.charAt(i) < '0' || k.charAt(i) > '9') {
                return false;
            }
        }
        return Long.parseLong(k) < 4294967295L;
    }

    private static final Pattern FORM_CT = Pattern.compile(
            "application/x-www-form-urlencoded[\\t\\n\\x0B\\f\\r \\u00A0\\u1680\\u2000-\\u200A\\u2028\\u2029\\u202F\\u205F\\u3000\\uFEFF]*"
                    + "(;[^\\n\\r\\u2028\\u2029]*)?", Pattern.CASE_INSENSITIVE);

    /** WI.ResourceUtilities.generateCURLCommand. */
    public static Gen safari(Req r) {
        List<String> argv = new ArrayList<>();
        List<String> cmd = new ArrayList<>();
        cmd.add("curl " + bracketEscape(safariPosix(r.url())));
        argv.add(bracketEscape(r.url()));
        cmd.add("-X " + safariPosix(r.method()));
        argv.add("-X");
        argv.add(r.method());
        // for (let key in headers): a JS object keeps duplicate names once, array-index-like keys come first
        Map<String, String> obj = new LinkedHashMap<>();
        for (Hdr h : r.headers()) {
            obj.put(h.name(), h.value());
        }
        List<String> keys = new ArrayList<>();
        obj.keySet().stream().filter(BrowserGenerators::arrayIndex)
                .sorted((a, b) -> Long.compare(Long.parseLong(a), Long.parseLong(b))).forEach(keys::add);
        obj.keySet().stream().filter(k -> !arrayIndex(k)).forEach(keys::add);
        for (String k : keys) {
            cmd.add("-H " + safariPosix(k + ": " + obj.get(k)));
            argv.add("-H");
            argv.add(k + ": " + obj.get(k));
        }
        String ct = r.safariContentType();
        if (ct != null && !ct.isEmpty() && !r.method().equals("GET") && r.body() != null && !r.body().isEmpty()) {
            boolean form = FORM_CT.matcher(ct).matches();
            cmd.add((form ? "--data " : "--data-raw ") + safariPosix(r.body()));
            argv.add(form ? "--data" : "--data-raw");
            argv.add(r.body());
        }
        return new Gen(String.join(" \\\n", cmd), argv);
    }

    /** All (browser, dialect) generators. */
    public enum Flavor {
        CHROME_BASH, CHROME_CMD, FIREFOX_BASH, FIREFOX_CMD, SAFARI_BASH;

        /** @return the generated command */
        public Gen gen(Req r) {
            return switch (this) {
                case CHROME_BASH -> chrome(r, false);
                case CHROME_CMD -> chrome(r, true);
                case FIREFOX_BASH -> firefox(r, false);
                case FIREFOX_CMD -> firefox(r, true);
                case SAFARI_BASH -> safari(r);
            };
        }

        /** @return true for the Windows cmd flavours */
        public boolean cmd() {
            return this == CHROME_CMD || this == FIREFOX_CMD;
        }
    }

    static String show(String s) {
        StringBuilder b = new StringBuilder("[");
        for (char c : s.toCharArray()) {
            if (c >= ' ' && c <= '~') {
                b.append(c);
            } else {
                b.append(String.format("\\u%04x", (int) c));
            }
        }
        return b.append("]").toString();
    }

    static List<String> list(String... s) {
        return Arrays.asList(s);
    }
}
