package burp.curl;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;

/**
 * The part of curl's cookie engine that matters for one outgoing request: reading a cookie file ({@code -b file}, in
 * Netscape format or as {@code Set-Cookie:} lines) and selecting the cookies that curl 8.7.1 sends for a URL, in
 * the order it sends them (longest path first, then longest domain, longest name, newest first).
 */
final class CookieJar {

    /** One stored cookie. */
    static final class Cookie {
        String domain;
        boolean tailMatch;
        String path;
        boolean secure;
        /** seconds since the epoch; 0 for a session cookie */
        long expires;
        String name;
        String value = "";
        long created;
    }

    private final List<Cookie> cookies = new ArrayList<>();
    private final List<String> placeholders = new ArrayList<>();
    private long counter;

    /** Remembers text that stands for a cookie file that could not be read; it is sent before the cookies. */
    void addPlaceholder(String text) {
        placeholders.add(text);
    }

    /** @return the placeholders of unreadable cookie files */
    List<String> placeholders() {
        return placeholders;
    }

    /** Reads the whole text of a cookie file. */
    void load(byte[] file, long now) {
        String text = new String(file, StandardCharsets.UTF_8);
        for (String raw : text.split("\n", -1)) {
            String line = raw;
            while (line.endsWith("\r")) {
                line = line.substring(0, line.length() - 1);
            }
            int s = 0;
            while (s < line.length() && (line.charAt(s) == ' ' || line.charAt(s) == '\t')) {
                s++;
            }
            line = line.substring(s);
            if (line.regionMatches(true, 0, "Set-Cookie:", 0, 11)) {
                addHeaderCookie(line.substring(11).strip(), now);
            } else if (!line.isEmpty() && (line.charAt(0) != '#' || line.startsWith("#HttpOnly_"))) {
                addNetscapeCookie(line.startsWith("#HttpOnly_") ? line.substring(10) : line, now);
            }
        }
    }

    private void addNetscapeCookie(String line, long now) {
        List<String> f = new ArrayList<>();
        for (String t : line.split("\t")) {
            if (!t.isEmpty()) {
                f.add(t);
            }
        }
        if (f.size() < 6) {
            return;
        }
        Cookie c = new Cookie();
        String d = f.get(0);
        c.domain = d.startsWith(".") ? d.substring(1) : d;
        c.tailMatch = f.get(1).equalsIgnoreCase("TRUE");
        c.path = sanitizePath(f.get(2));
        c.secure = f.get(3).equalsIgnoreCase("TRUE");
        try {
            c.expires = Long.parseLong(f.get(4).strip());
        } catch (NumberFormatException e) {
            return;
        }
        c.name = f.get(5);
        c.value = f.size() > 6 ? f.get(6) : "";
        store(c, now);
    }

    private void addHeaderCookie(String text, long now) {
        String[] parts = text.split(";", -1);
        String first = parts[0].strip();
        int eq = first.indexOf('=');
        if (eq <= 0) {
            return;
        }
        Cookie c = new Cookie();
        c.name = first.substring(0, eq).strip();
        c.value = first.substring(eq + 1).strip();
        Long maxAge = null;
        for (int i = 1; i < parts.length; i++) {
            String a = parts[i].strip();
            if (a.isEmpty()) {
                continue;
            }
            int e = a.indexOf('=');
            String k = (e < 0 ? a : a.substring(0, e)).strip().toLowerCase(Locale.ROOT);
            String v = e < 0 ? "" : a.substring(e + 1).strip();
            switch (k) {
                case "path" -> c.path = sanitizePath(v);
                case "domain" -> {
                    if (!v.isEmpty()) {
                        c.domain = v.startsWith(".") ? v.substring(1) : v;
                        c.tailMatch = true;
                    }
                }
                case "secure" -> c.secure = true;
                case "max-age" -> {
                    try {
                        maxAge = Long.parseLong(v.replace("\"", ""));
                    } catch (NumberFormatException ex) {
                        // ignored, like curl
                    }
                }
                case "expires" -> {
                    Long t = CurlDate.parse(v);
                    if (t != null) {
                        c.expires = t == 0 ? 1 : t;
                    }
                }
                default -> { }
            }
        }
        if (maxAge != null) {
            c.expires = maxAge > 0 ? now + maxAge : 1;
        }
        store(c, now);
    }

    private static String sanitizePath(String p) {
        String s = p;
        if (s.length() >= 2 && s.startsWith("\"") && s.endsWith("\"")) {
            s = s.substring(1, s.length() - 1);
        }
        if (!s.startsWith("/")) {
            return "/";
        }
        if (s.length() > 1 && s.endsWith("/")) {
            s = s.substring(0, s.length() - 1);
        }
        return s;
    }

    private static boolean same(String a, String b) {
        return a == null ? b == null : b != null && a.equalsIgnoreCase(b);
    }

    private void store(Cookie c, long now) {
        boolean expired = c.expires > 0 && c.expires <= now;
        for (int i = 0; i < cookies.size(); i++) {
            Cookie o = cookies.get(i);
            if (o.name.equals(c.name) && same(o.domain, c.domain)
                    && (o.path == null ? c.path == null : o.path.equals(c.path))) {
                if (expired) {
                    cookies.remove(i);
                } else {
                    c.created = o.created;
                    cookies.set(i, c);
                }
                return;
            }
        }
        if (!expired) {
            c.created = ++counter;
            cookies.add(c);
        }
    }

    private static boolean isIp(String host) {
        return host.indexOf(':') >= 0 || host.matches("[0-9]+(\\.[0-9]+){3}");
    }

    private static boolean pathMatch(String cookiePath, String uriPath) {
        if (cookiePath.length() == 1) {
            return true;
        }
        String uri = uriPath.isEmpty() || uriPath.charAt(0) != '/' ? "/" : uriPath;
        if (uri.length() > 1 && uri.endsWith("/")) {
            uri = uri.substring(0, uri.length() - 1);
        }
        int cl = cookiePath.length();
        if (cookiePath.endsWith("/")) {
            cl--;
        }
        if (cl > uri.length() || !uri.startsWith(cookiePath.substring(0, cl))) {
            return false;
        }
        return cl == uri.length() || uri.charAt(cl) == '/';
    }

    /**
     * @param host host of the request (IPv6 without brackets)
     * @param path request path without query
     * @param https true for https
     * @param now seconds since the epoch
     * @return the matching cookies in sending order
     */
    List<Cookie> matching(String host, String path, boolean https, long now) {
        boolean secureContext = https || host.equalsIgnoreCase("localhost") || host.toLowerCase(Locale.ROOT)
                .endsWith(".localhost") || host.equals("127.0.0.1") || host.equals("::1");
        boolean ip = isIp(host);
        List<Cookie> out = new ArrayList<>();
        for (Cookie c : cookies) {
            if (c.expires > 0 && c.expires <= now) {
                continue;
            }
            if (c.secure && !secureContext) {
                continue;
            }
            boolean domainOk;
            if (c.domain == null) {
                domainOk = true;
            } else if (c.tailMatch && !ip) {
                domainOk = tailMatch(c.domain, host);
            } else {
                domainOk = host.equalsIgnoreCase(c.domain);
            }
            if (domainOk && (c.path == null || pathMatch(c.path, path))) {
                out.add(c);
            }
        }
        out.sort(Comparator
                .comparingInt((Cookie c) -> c.path == null ? 0 : c.path.length()).reversed()
                .thenComparing(Comparator.comparingInt((Cookie c) -> c.domain == null ? 0 : c.domain.length())
                        .reversed())
                .thenComparing(Comparator.comparingInt((Cookie c) -> c.name.length()).reversed())
                .thenComparing(Comparator.comparingLong((Cookie c) -> c.created).reversed()));
        return out;
    }

    private static boolean tailMatch(String domain, String host) {
        if (host.length() < domain.length()) {
            return false;
        }
        if (!host.regionMatches(true, host.length() - domain.length(), domain, 0, domain.length())) {
            return false;
        }
        return host.length() == domain.length() || host.charAt(host.length() - domain.length() - 1) == '.';
    }
}
