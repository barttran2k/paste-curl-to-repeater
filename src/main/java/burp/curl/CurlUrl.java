package burp.curl;

import java.net.IDN;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Immutable, curl-compatible view of an http(s) URL. Parsed by hand (no {@code java.net.URL/URI}) and
 * checked against curl 8.7.1 by {@code CurlUrlDifferentialTest}.
 *
 * <p>Behaviour mirrored from curl:
 * <ul>
 * <li>Missing scheme: {@code protoDefault}, else curl's guess from the host prefix ({@code ftp.}, {@code dict.},
 *     {@code ldap.}, {@code imap.}, {@code smtp.}, {@code pop3.} give a non-http scheme and therefore an
 *     "unsupported protocol" error; anything else is http). One to three slashes after {@code scheme:} are accepted.
 * <li>Fragment dropped. Empty path becomes "/". Dot segments are removed per RFC 3986 5.2.4 in the path only
 *     (not in the query, {@code %2e} is left alone) unless {@code pathAsIs}.
 * <li>Non-ASCII in the path becomes lower-case {@code %xx} UTF-8; in the query it is kept as-is (curl sends the raw
 *     bytes, so the caller must encode {@link #requestTarget()} as UTF-8). Other bytes, invalid {@code %} sequences,
 *     {@code {} [] | " < >} and backslashes are passed through untouched ({@code -g} behaviour; no globbing).
 * <li>Userinfo is percent-decoded; invalid escapes stay literal. An empty port ({@code http://h:/}) means the
 *     default port (but is an error when the scheme had to be guessed, as in curl 8.7.1); the port must be decimal 0-65535 (leading zeros allowed).
 * <li>Host: percent-decoded, case kept, only {@code A-Za-z0-9 - . _ ~ |} and non-ASCII accepted. All-numeric
 *     IPv4 forms ({@code 127.1}, {@code 0x7f.1}, {@code 2130706433}) are rewritten to dotted quad. IPv6 is
 *     re-rendered like {@code inet_ntop} when it was not already in that form (case-insensitively); a zone id is
 *     dropped.
 * <li>{@link #withAppendedQuery} and {@link #withPathSuffix} re-run dot-segment removal on the path even with
 *     {@code --path-as-is}, because curl 8.7.1 does (it re-parses the URL).
 * </ul>
 *
 * <p>Deliberate leniencies (curl rejects with "Malformed input to a URL function"): leading/trailing whitespace is
 * trimmed, and a literal space inside path, query or fragment is sent as {@code %20}. Other control characters,
 * and spaces in the host, userinfo or port, are still errors.
 *
 * <p>Bytes: the URL is a wire text ({@link ByteText}): a byte that is not UTF-8 is an escape character. In the
 * path such a byte becomes {@code %xx} (one byte, lower-case), in the query and userinfo it is kept and the caller
 * encodes {@link #requestTarget()} with {@link ByteText#encode}.
 *
 * <p>IDN: {@link #host()} and {@link #hostHeader()} use punycode. curl 8.7.1 built without libidn2 (the macOS
 * system curl) sends the raw UTF-8 host in {@code Host:}; an IDN-enabled curl sends punycode like this class.
 */
public final class CurlUrl {
    private final String scheme;
    private final String hostText;   // decoded host as typed (case kept), IPv6 without brackets, no zone
    private final boolean ipv6;
    private final int explicitPort;  // -1 when absent
    private final String user;
    private final String password;
    private final String path;
    private final String query;

    private CurlUrl(String scheme, String hostText, boolean ipv6, int explicitPort, String user, String password,
                    String path, String query) {
        this.scheme = scheme;
        this.hostText = hostText;
        this.ipv6 = ipv6;
        this.explicitPort = explicitPort;
        this.user = user;
        this.password = password;
        this.path = path;
        this.query = query;
    }

    /**
     * Parses a URL the way curl does.
     *
     * @param url          the URL as typed
     * @param protoDefault scheme to assume when none is given ({@code --proto-default}), may be null
     * @param pathAsIs     true for {@code --path-as-is}
     * @return the parsed URL
     * @throws CurlParseException when curl would refuse the URL or the scheme is not http/https
     */
    public static CurlUrl parse(String url, String protoDefault, boolean pathAsIs) throws CurlParseException {
        if (url == null) {
            throw new CurlParseException("no URL specified");
        }
        String s = url.strip();
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c < 0x20 || c == 0x7f) {
                throw new CurlParseException("URL rejected: malformed input (control character)", i);
            }
        }
        // scheme
        String scheme;
        String rest;
        int colon = schemeEnd(s);
        if (colon > 0) {
            int j = colon + 1;
            while (j < s.length() && s.charAt(j) == '/') {
                j++;
            }
            int slashes = j - colon - 1;
            if (slashes >= 1) {
                if (slashes > 3) {
                    throw new CurlParseException("URL rejected: unsupported number of slashes following scheme");
                }
                scheme = s.substring(0, colon).toLowerCase(Locale.ROOT);
                rest = s.substring(j);
            } else {
                scheme = null;
                rest = s;
            }
        } else {
            scheme = null;
            rest = s;
        }
        boolean guessed = false;
        if (scheme == null) {
            guessed = protoDefault == null || protoDefault.isEmpty();
            if (protoDefault != null && !protoDefault.isEmpty()) {
                scheme = protoDefault.toLowerCase(Locale.ROOT);
            } else {
                scheme = guessScheme(rest);
            }
        }
        if (!scheme.equals("http") && !scheme.equals("https")) {
            throw new CurlParseException("unsupported protocol: " + scheme);
        }

        // fragment, authority, path, query
        int hash = rest.indexOf('#');
        if (hash >= 0) {
            rest = rest.substring(0, hash);
        }
        int authEnd = rest.length();
        for (int i = 0; i < rest.length(); i++) {
            char c = rest.charAt(i);
            if (c == '/' || c == '?') {
                authEnd = i;
                break;
            }
        }
        String authority = rest.substring(0, authEnd);
        String tail = rest.substring(authEnd);
        String rawPath = tail;
        String rawQuery = null;
        int q = tail.indexOf('?');
        if (q >= 0) {
            rawPath = tail.substring(0, q);
            rawQuery = tail.substring(q + 1);
        }

        // userinfo
        String user = null;
        String password = null;
        String hostPort = authority;
        int at = authority.indexOf('@');
        if (at >= 0) {
            String ui = authority.substring(0, at);
            hostPort = authority.substring(at + 1);
            if (ui.indexOf(' ') >= 0) {
                throw new CurlParseException("URL rejected: malformed input (space in userinfo)");
            }
            int c = ui.indexOf(':');
            if (c >= 0) {
                user = percentDecode(ui.substring(0, c));
                password = percentDecode(ui.substring(c + 1));
            } else {
                user = percentDecode(ui);
            }
        }

        // host and port
        String hostRaw;
        String portStr = null;
        boolean v6 = false;
        if (hostPort.startsWith("[")) {
            int close = hostPort.indexOf(']');
            if (close < 0) {
                throw new CurlParseException("URL rejected: bad range in URL (missing ']')");
            }
            String inner = stripZone(hostPort.substring(1, close));
            if (inner.isEmpty()) {
                throw new CurlParseException("URL rejected: bad IPv6 address");
            }
            hostRaw = canonicalIpv6(inner);
            v6 = true;
            String after = hostPort.substring(close + 1);
            if (!after.isEmpty()) {
                if (after.charAt(0) != ':') {
                    throw new CurlParseException("URL rejected: port number was not a decimal number between 0 and 65535");
                }
                portStr = after.substring(1);
            }
        } else {
            int c = hostPort.indexOf(':');
            if (c >= 0) {
                portStr = hostPort.substring(c + 1);
                hostRaw = hostPort.substring(0, c);
            } else {
                hostRaw = hostPort;
            }
            if (hostRaw.isEmpty()) {
                throw new CurlParseException("URL rejected: no host part in the URL");
            }
            hostRaw = checkHost(percentDecode(hostRaw));
            hostRaw = normalizeIpv4(hostRaw);
        }
        int port = -1;
        if (guessed && portStr != null && portStr.isEmpty()) {
            // curl 8.7.1 quirk: an empty port is refused when the scheme was guessed ("1.2.3.4:/x")
            throw new CurlParseException("URL rejected: port number was not a decimal number between 0 and 65535");
        }
        if (portStr != null && !portStr.isEmpty()) {
            port = parsePort(portStr);
        }

        // path and query
        String path = encodePath(rawPath);
        if (path.isEmpty()) {
            path = "/";
        }
        if (!pathAsIs) {
            path = removeDotSegments(path);
        }
        String query = rawQuery == null ? null : rawQuery.replace(" ", "%20");
        return new CurlUrl(scheme, hostRaw, v6, port, user, password, path, query);
    }

    /** Index of the ':' ending a syntactically valid scheme at the start of s, or -1. */
    private static int schemeEnd(String s) {
        if (s.isEmpty() || !isAlpha(s.charAt(0))) {
            return -1;
        }
        for (int i = 1; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == ':') {
                return i;
            }
            if (!(isAlpha(c) || (c >= '0' && c <= '9') || c == '+' || c == '-' || c == '.')) {
                return -1;
            }
        }
        return -1;
    }

    private static boolean isAlpha(char c) {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
    }

    private static String guessScheme(String rest) {
        String lower = rest.toLowerCase(Locale.ROOT);
        for (String p : new String[] {"ftp", "dict", "ldap", "imap", "smtp", "pop3"}) {
            if (lower.startsWith(p + ".")) {
                return p;
            }
        }
        return "http";
    }

    private static String stripZone(String inner) throws CurlParseException {
        int pct = inner.indexOf('%');
        if (pct >= 0) {
            if (inner.length() - pct > 32) {
                throw new CurlParseException("URL rejected: bad range in URL (zone id too long)");
            }
            return inner.substring(0, pct);
        }
        return inner;
    }

    private static int parsePort(String p) throws CurlParseException {
        long v = 0;
        for (int i = 0; i < p.length(); i++) {
            char c = p.charAt(i);
            if (c < '0' || c > '9') {
                throw new CurlParseException("URL rejected: port number was not a decimal number between 0 and 65535");
            }
            v = v * 10 + (c - '0');
            if (v > 65535) {
                throw new CurlParseException("URL rejected: port number was not a decimal number between 0 and 65535");
            }
        }
        return (int) v;
    }

    private static String checkHost(String host) throws CurlParseException {
        if (host.isEmpty()) {
            throw new CurlParseException("URL rejected: no host part in the URL");
        }
        for (int i = 0; i < host.length(); i++) {
            char c = host.charAt(i);
            boolean ok = c >= 0x80 || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
                    || c == '-' || c == '.' || c == '_' || c == '~' || c == '|';
            if (!ok) {
                throw new CurlParseException("URL rejected: bad hostname");
            }
        }
        return host;
    }

    // ---- percent handling ----

    /** Percent-decodes; invalid escapes stay literal. The decoded bytes become a wire text ({@link ByteText}). */
    static String percentDecode(String s) {
        if (s.indexOf('%') < 0) {
            return s;
        }
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
        int plain = 0;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '%' && i + 2 < s.length() && hex(s.charAt(i + 1)) >= 0 && hex(s.charAt(i + 2)) >= 0) {
                out.writeBytes(ByteText.encode(s.substring(plain, i)));
                out.write(hex(s.charAt(i + 1)) * 16 + hex(s.charAt(i + 2)));
                i += 2;
                plain = i + 1;
            }
        }
        out.writeBytes(ByteText.encode(s.substring(plain)));
        return ByteText.decode(out.toByteArray());
    }

    private static int hex(char c) {
        if (c >= '0' && c <= '9') {
            return c - '0';
        }
        if (c >= 'a' && c <= 'f') {
            return c - 'a' + 10;
        }
        if (c >= 'A' && c <= 'F') {
            return c - 'A' + 10;
        }
        return -1;
    }

    private static String encodePath(String p) {
        StringBuilder sb = null;
        for (int i = 0; i < p.length(); i++) {
            char c = p.charAt(i);
            if (c == ' ' || c >= 0x80) {
                if (sb == null) {
                    sb = new StringBuilder(p.substring(0, i));
                }
                if (c == ' ') {
                    sb.append("%20");
                } else if (ByteText.isEscape(c)) {
                    sb.append('%').append(HEX_LOWER[(c >> 4) & 15]).append(HEX_LOWER[c & 15]);
                } else {
                    int cp = p.codePointAt(i);
                    if (Character.charCount(cp) == 2) {
                        i++;
                    }
                    for (byte b : new String(Character.toChars(cp)).getBytes(StandardCharsets.UTF_8)) {
                        sb.append('%').append(HEX_LOWER[(b >> 4) & 15]).append(HEX_LOWER[b & 15]);
                    }
                }
            } else if (sb != null) {
                sb.append(c);
            }
        }
        return sb == null ? p : sb.toString();
    }

    private static final char[] HEX_LOWER = "0123456789abcdef".toCharArray();

    /** RFC 3986 section 5.2.4, applied to a path that starts with "/". */
    static String removeDotSegments(String in) {
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
                popSegment(out);
            } else if (input.equals("/..")) {
                input = "/";
                popSegment(out);
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

    private static void popSegment(StringBuilder out) {
        int slash = out.lastIndexOf("/");
        out.setLength(Math.max(slash, 0));
    }

    // ---- IPv4 / IPv6 ----

    /** curl rewrites numeric hosts (1-4 parts, decimal/hex/octal) to dotted quad; others are left alone. */
    static String normalizeIpv4(String host) {
        String[] parts = host.split("\\.", -1);
        if (parts.length > 4) {
            return host;
        }
        long[] v = new long[parts.length];
        for (int i = 0; i < parts.length; i++) {
            long n = parseNumber(parts[i]);
            if (n < 0) {
                return host;
            }
            v[i] = n;
        }
        long value = 0;
        for (int i = 0; i < v.length - 1; i++) {
            if (v[i] > 255) {
                return host;
            }
            value |= v[i] << (24 - 8 * i);
        }
        long last = v[v.length - 1];
        long max = (1L << (8 * (5 - v.length))) - 1;
        if (last > max) {
            return host;
        }
        value |= last;
        return ((value >> 24) & 255) + "." + ((value >> 16) & 255) + "." + ((value >> 8) & 255) + "." + (value & 255);
    }

    /** @return the value, or -1 when not a (valid) decimal/hex/octal number */
    private static long parseNumber(String p) {
        if (p.isEmpty()) {
            return -1;
        }
        int radix = 10;
        String digits = p;
        if (p.length() > 2 && (p.startsWith("0x") || p.startsWith("0X"))) {
            radix = 16;
            digits = p.substring(2);
        } else if (p.length() > 1 && p.charAt(0) == '0') {
            radix = 8;
            digits = p.substring(1);
        }
        long n = 0;
        for (int i = 0; i < digits.length(); i++) {
            int d = Character.digit(digits.charAt(i), radix);
            if (d < 0 || digits.charAt(i) > 'f') {
                return -1;
            }
            n = n * radix + d;
            if (n > 0xFFFFFFFFL) {
                return 0x1_0000_0000L;
            }
        }
        return n;
    }

    /** Validates an IPv6 literal and returns curl's rendering: inet_ntop form, unless already equal ignoring case. */
    static String canonicalIpv6(String text) throws CurlParseException {
        int[] w = parseIpv6(text);
        if (w == null) {
            throw new CurlParseException("URL rejected: bad range in URL (invalid IPv6 address)");
        }
        String canon = ntop(w);
        return canon.equalsIgnoreCase(text) ? text : canon;
    }

    private static int[] parseIpv6(String s) {
        int[] words = new int[8];
        int dbl = s.indexOf("::");
        if (dbl >= 0 && s.indexOf("::", dbl + 1) >= 0) {
            return null;
        }
        String left = dbl >= 0 ? s.substring(0, dbl) : s;
        String right = dbl >= 0 ? s.substring(dbl + 2) : "";
        List<Integer> l = new ArrayList<>();
        List<Integer> r = new ArrayList<>();
        if (!groups(left, l, dbl < 0) || !groups(right, r, true)) {
            return null;
        }
        // an embedded IPv4 can only be the very last group
        int total = l.size() + r.size();
        if (dbl < 0 ? total != 8 : total > 7) {
            return null;
        }
        for (int i = 0; i < l.size(); i++) {
            words[i] = l.get(i);
        }
        for (int i = 0; i < r.size(); i++) {
            words[8 - r.size() + i] = r.get(i);
        }
        return words;
    }

    /** Parses colon separated groups; ipv4 tail allowed only when allowTail. */
    private static boolean groups(String s, List<Integer> out, boolean allowTail) {
        if (s.isEmpty()) {
            return true;
        }
        String[] g = s.split(":", -1);
        for (int i = 0; i < g.length; i++) {
            String x = g[i];
            if (x.isEmpty()) {
                return false;
            }
            if (x.indexOf('.') >= 0) {
                if (i != g.length - 1 || !allowTail) {
                    return false;
                }
                String[] o = x.split("\\.", -1);
                if (o.length != 4) {
                    return false;
                }
                int[] b = new int[4];
                for (int k = 0; k < 4; k++) {
                    if (o[k].isEmpty() || o[k].length() > 3) {
                        return false;
                    }
                    for (char c : o[k].toCharArray()) {
                        if (c < '0' || c > '9') {
                            return false;
                        }
                    }
                    b[k] = Integer.parseInt(o[k]);
                    if (b[k] > 255) {
                        return false;
                    }
                }
                out.add(b[0] * 256 + b[1]);
                out.add(b[2] * 256 + b[3]);
            } else {
                if (x.length() > 4) {
                    return false;
                }
                int v = 0;
                for (char c : x.toCharArray()) {
                    int d = hex(c);
                    if (d < 0) {
                        return false;
                    }
                    v = v * 16 + d;
                }
                out.add(v);
            }
        }
        return true;
    }

    /** BIND-style inet_ntop for IPv6 (what curl's Curl_inet_ntop uses). */
    private static String ntop(int[] w) {
        int bestBase = -1;
        int bestLen = 0;
        int curBase = -1;
        int curLen = 0;
        for (int i = 0; i < 8; i++) {
            if (w[i] == 0) {
                if (curBase == -1) {
                    curBase = i;
                    curLen = 1;
                } else {
                    curLen++;
                }
            } else if (curBase != -1) {
                if (bestBase == -1 || curLen > bestLen) {
                    bestBase = curBase;
                    bestLen = curLen;
                }
                curBase = -1;
            }
        }
        if (curBase != -1 && (bestBase == -1 || curLen > bestLen)) {
            bestBase = curBase;
            bestLen = curLen;
        }
        if (bestBase != -1 && bestLen < 2) {
            bestBase = -1;
        }
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 8; i++) {
            if (bestBase != -1 && i >= bestBase && i < bestBase + bestLen) {
                if (i == bestBase) {
                    sb.append(':');
                }
                continue;
            }
            if (i != 0) {
                sb.append(':');
            }
            if (i == 6 && bestBase == 0 && (bestLen == 6 || (bestLen == 5 && w[5] == 0xffff))) {
                sb.append(w[6] >> 8).append('.').append(w[6] & 255).append('.').append(w[7] >> 8).append('.')
                        .append(w[7] & 255);
                break;
            }
            sb.append(Integer.toHexString(w[i]));
        }
        if (bestBase != -1 && bestBase + bestLen == 8) {
            sb.append(':');
        }
        return sb.toString();
    }

    // ---- accessors ----

    /** @return "http" or "https" */
    public String scheme() {
        return scheme;
    }

    /** @return true for https */
    public boolean secure() {
        return scheme.equals("https");
    }

    /** @return host for connecting: ASCII (IDN as punycode), IPv6 without brackets or zone */
    public String host() {
        if (ipv6) {
            return hostText;
        }
        for (int i = 0; i < hostText.length(); i++) {
            if (hostText.charAt(i) >= 0x80) {
                try {
                    return IDN.toASCII(hostText, IDN.ALLOW_UNASSIGNED);
                } catch (IllegalArgumentException e) {
                    return hostText;
                }
            }
        }
        return hostText;
    }

    private int defaultPort() {
        return secure() ? 443 : 80;
    }

    /** @return effective port: explicit, else 80/443 */
    public int port() {
        return explicitPort >= 0 ? explicitPort : defaultPort();
    }

    /** @return the Host header value: brackets for IPv6, ":port" only when explicit and not the scheme default */
    public String hostHeader() {
        String h = ipv6 ? "[" + hostText + "]" : host();
        if (explicitPort >= 0 && explicitPort != defaultPort()) {
            return h + ":" + explicitPort;
        }
        return h;
    }

    /** @return percent-decoded user, or null without userinfo */
    public String user() {
        return user;
    }

    /** @return percent-decoded password, or null when absent ({@code user@host}) */
    public String password() {
        return password;
    }

    /** @return path, always starting with "/" */
    public String path() {
        return path;
    }

    /** @return query without "?", null when there is none ("" for a bare "?") */
    public String query() {
        return query;
    }

    /** @return path plus "?query" when a query is present. Non-ASCII in the query must be sent as UTF-8. */
    public String requestTarget() {
        return query == null ? path : path + "?" + query;
    }

    /**
     * curl's rule for {@code -G} data and {@code --url-query}: the piece becomes the query when there is none (or it
     * is empty); otherwise it is added after "&" (no extra "&" when the query already ends with one). An empty
     * piece on a URL without query changes nothing. The path is dot-squashed again, as curl 8.7.1 does even with
     * {@code --path-as-is}.
     *
     * @param piece already encoded query text
     * @return the new URL
     */
    public CurlUrl withAppendedQuery(String piece) {
        String p = piece == null ? "" : piece;
        int hash = p.indexOf('#');
        if (hash >= 0) {
            p = p.substring(0, hash); // a fragment in the appended text is dropped, like in the URL itself
        }
        p = lowerPercentHex(p).replace(" ", "%20");
        if (p.isEmpty() && query == null) {
            return this;
        }
        String nq;
        if (query == null || query.isEmpty()) {
            nq = p;
        } else if (query.endsWith("&")) {
            nq = query + p;
        } else {
            nq = query + "&" + p;
        }
        return new CurlUrl(scheme, hostText, ipv6, explicitPort, user, password, removeDotSegments(path), nq);
    }

    /** curl's URL API writes the hex digits of every valid {@code %XX} in appended query text in lower case. */
    private static String lowerPercentHex(String s) {
        StringBuilder sb = null;
        for (int i = 0; i + 2 < s.length(); i++) {
            if (s.charAt(i) == '%' && isHex(s.charAt(i + 1)) && isHex(s.charAt(i + 2))) {
                if (sb == null) {
                    sb = new StringBuilder(s);
                }
                sb.setCharAt(i + 1, Character.toLowerCase(s.charAt(i + 1)));
                sb.setCharAt(i + 2, Character.toLowerCase(s.charAt(i + 2)));
                i += 2;
            }
        }
        return sb == null ? s : sb.toString();
    }

    private static boolean isHex(char c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
    }

    /**
     * For {@code -T}: when there is no query and the path ends with "/", appends the file name (everything except
     * {@code A-Za-z0-9-._~} is percent-escaped with lower-case hex, like curl_easy_escape) and squashes dot
     * segments. Otherwise returns this unchanged.
     *
     * @param name file name (not a path)
     * @return the new URL
     */
    public CurlUrl withPathSuffix(String name) {
        if (query != null || !path.endsWith("/") || name == null) {
            return this;
        }
        StringBuilder sb = new StringBuilder(path);
        for (byte b : name.getBytes(StandardCharsets.UTF_8)) {
            int c = b & 0xff;
            if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '.'
                    || c == '_' || c == '~') {
                sb.append((char) c);
            } else {
                sb.append('%').append(HEX_LOWER[c >> 4]).append(HEX_LOWER[c & 15]);
            }
        }
        return new CurlUrl(scheme, hostText, ipv6, explicitPort, user, password, removeDotSegments(sb.toString()),
                null);
    }

    /** @return normalised absolute URL without userinfo and fragment */
    @Override
    public String toString() {
        return scheme + "://" + hostHeader() + requestTarget();
    }
}
