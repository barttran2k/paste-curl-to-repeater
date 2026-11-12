package burp.curl.browser;

import burp.curl.browser.BrowserGenerators.Flavor;
import burp.curl.browser.BrowserGenerators.Hdr;
import burp.curl.browser.BrowserGenerators.Req;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Random;
import java.util.Set;

/** Logical requests: the hand-written nasty set and seeded random generators. */
final class Samples {
    private Samples() {
    }

    /** A named logical request. */
    record Named(String name, Req req) {
    }

    static Hdr h(String n, String v) {
        return new Hdr(n, v);
    }

    private static Named n(String name, String method, String url, String body, Hdr... headers) {
        return new Named(name, new Req(method, url, List.of(headers), body, false, false, null).withBody(body));
    }

    static final String UA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) "
            + "Chrome/124.0.0.0 Safari/537.36";
    static final String SEC_CH_UA = "\"Chromium\";v=\"124\", \"Google Chrome\";v=\"124\", \"Not-A.Brand\";v=\"99\"";
    static final String JSON_CT = "application/json";
    static final String FORM_CT = "application/x-www-form-urlencoded";

    static String repeat(String s, int n) {
        return s.repeat(n);
    }

    /** The hand-written set: at least 60 requests whose strings are nasty for one shell or another. */
    static List<Named> nasty() {
        List<Named> l = new ArrayList<>();
        String u = "https://api.example.test/v1/items";
        l.add(n("get-plain", "GET", "https://example.test/", null));
        l.add(n("get-query-fragment", "GET", "https://example.test/a?b=c&d=%20e#frag", null, h("Accept", "*/*")));
        l.add(n("get-no-path-query", "GET", "https://example.test?x=1&y=2", null));
        l.add(n("get-no-path-fragment", "GET", "https://example.test#top", null));
        l.add(n("get-ipv6-port", "GET", "http://[2001:db8::1]:8080/path?x=1", null, h("Accept", "text/html")));
        l.add(n("get-ipv6-loopback", "GET", "http://[::1]/", null));
        l.add(n("get-port", "GET", "https://example.test:8443/a/b/", null));
        l.add(n("get-brackets", "GET", "https://example.test/a[0]/b?x[]=1&x[]=2", null));
        l.add(n("get-braces", "GET", "https://example.test/a?x={y}&z={\"k\":1}", null));
        l.add(n("get-percent-encodings", "GET", "https://example.test/a%20b/%2F%25/%7Efoo?q=%E3%81%82", null));
        l.add(n("get-quotes-in-url", "GET", "https://example.test/it's/a\"b?c='d'&e=\"f\"", null));
        l.add(n("get-shell-metachars-in-url", "GET",
                "https://example.test/p?q=$HOME&r=`id`&s=$(whoami)&t=!bang&u=%PATH%&v=^caret&w=a|b&x=a<b>c;y=(z)", null));
        l.add(n("get-cmd-env-in-url", "GET", "https://example.test/%USERNAME%/%1/%a%/100%", null));
        l.add(n("get-semicolons-commas", "GET", "https://example.test/a;b=c/d,e/f:g@h/i+j~k*l", null));
        l.add(n("get-upper-case-host", "GET", "https://EXAMPLE.test/Path/CASE", null));
        l.add(n("get-long-query", "GET", "https://example.test/search?q=" + repeat("abc%20def&p=", 250) + "end", null,
                h("Accept", "*/*")));
        l.add(n("get-loopback-ip-port", "GET", "http://127.0.0.1:8080/x", null));
        l.add(n("get-hash-in-query-encoded", "GET", "https://example.test/a?b=%23c#d", null));
        l.add(n("get-double-slash", "GET", "https://example.test//a//b?c=//d", null));
        l.add(n("get-all-sec-headers", "GET", "https://example.test/dashboard", null,
                h("accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"),
                h("accept-encoding", "gzip, deflate, br"), h("accept-language", "en-US,en;q=0.9"),
                h("cache-control", "max-age=0"), h("cookie", "sid=abc123; theme=dark; _ga=GA1.2.123456789.1700000000"),
                h("sec-ch-ua", SEC_CH_UA), h("sec-ch-ua-mobile", "?0"), h("sec-ch-ua-platform", "\"macOS\""),
                h("sec-fetch-dest", "document"), h("sec-fetch-mode", "navigate"), h("sec-fetch-site", "none"),
                h("sec-fetch-user", "?1"), h("upgrade-insecure-requests", "1"), h("user-agent", UA)));
        l.add(n("chrome-pseudo-headers", "GET", "https://example.test/h2", null, h(":authority", "example.test"),
                h(":method", "GET"), h(":path", "/h2"), h(":scheme", "https"), h("accept", "*/*"), h("host", "example.test")));
        l.add(n("long-cookie", "GET", "https://example.test/c", null,
                h("Cookie", "a=" + repeat("x", 1500) + "; b=\"quoted value\"; c=%7B%22k%22%3A1%7D; d=a%20b; e=1&f=2")));
        l.add(n("cookie-without-equals", "GET", "https://example.test/c2", null, h("Cookie", "justatoken")));
        l.add(n("cookie-with-quotes-and-bang", "GET", "https://example.test/c3", null,
                h("Cookie", "k=\"v!\"; j='w'; p=$HOME; q=`id`; r=100%; s=^t; u=a\\b")));
        // header value classes
        l.add(n("hdr-single-and-double-quotes", "GET", "https://example.test/h", null,
                h("X-Quotes", "it's \"quoted\" and 'single'")));
        l.add(n("hdr-backslashes", "GET", "https://example.test/h", null, h("X-Bs", "a\\b\\\\c\\"), h("X-Bs2", "\\\"")));
        l.add(n("hdr-bang", "GET", "https://example.test/h", null, h("X-Bang", "hi! !x! !!")));
        l.add(n("hdr-dollar-backtick", "GET", "https://example.test/h", null,
                h("X-Dollar", "$HOME ${PATH} $(id) `id` $'x' $\"y\"")));
        l.add(n("hdr-percent-env", "GET", "https://example.test/h", null,
                h("X-Pct", "100% %PATH% %USERNAME% %1 %_x% %a% %"), h("X-Pct2", "%%")));
        l.add(n("hdr-caret", "GET", "https://example.test/h", null, h("X-Caret", "a^b ^ ^^ ^\" \"^"), h("X-C2", "^")));
        l.add(n("hdr-metachars", "GET", "https://example.test/h", null,
                h("X-Meta", "a&b|c<d>e;f(g)h{i}j[k]l*m?n~o#p@q=r+s,t:u")));
        l.add(n("hdr-tab", "GET", "https://example.test/h", null, h("X-Tab", "a\tb\t\tc")));
        l.add(n("hdr-leading-trailing-space", "GET", "https://example.test/h", null, h("X-Lead", "   v"),
                h("X-Trail", "v   ")));
        l.add(n("hdr-unicode", "GET", "https://example.test/h", null, h("X-Uni", "é ñ ü 日本語 Ω ж ا 한"),
                h("X-Emoji", "😀 a😀b 👨\u200d👩\u200d👧")));
        l.add(n("hdr-latin1-range", "GET", "https://example.test/h", null, h("X-Latin1", "caf\u00e9 \u00ff \u00a0 \u00ad \u0080 \u009f")));
        l.add(n("hdr-bmp-high", "GET", "https://example.test/h", null,
                h("X-Bmp", "\u0100 \u20ac \u2028 \u2029 \u3000 \uFEFF \u200b \ue000")));
        l.add(n("hdr-control-chars", "GET", "https://example.test/h", null,
                h("X-Ctl", "a\u0001b\u001fc\u007fd\u001be")));
        l.add(n("hdr-cr-lf-in-value", "GET", "https://example.test/h", null, h("X-Nl", "a\nb"), h("X-Cr", "c\rd"),
                h("X-Crlf", "e\r\nf")));
        l.add(n("hdr-empty-value", "GET", "https://example.test/h", null, h("X-Empty", ""), h("X-Blank", "   "),
                h("X-After", "v")));
        l.add(n("hdr-json-value", "GET", "https://example.test/h", null, h("X-Json", "{\"a\":[1,2,{\"b\":null}],\"c\":\"d\"}")));
        l.add(n("hdr-etag-weak", "GET", "https://example.test/h", null, h("If-None-Match", "W/\"33a64df551425fcc55e4d42a148795d9f25f89d4\"")));
        l.add(n("hdr-authorization", "GET", "https://example.test/h", null,
                h("Authorization", "Bearer FAKE_JWT_FOR_TESTS")));
        l.add(n("hdr-basic-auth-colon", "GET", "https://example.test/h", null, h("Authorization", "Basic dXNlcjpwYXNz"),
                h("X-Url", "https://a.test:8080/x?y=1")));
        l.add(n("hdr-referer-origin", "GET", "https://example.test/h", null, h("Referer", "https://example.test/a?b=c&d=e#f"),
                h("Origin", "https://example.test")));
        l.add(n("hdr-name-case", "GET", "https://example.test/h", null, h("X-MiXeD-CaSe", "v"), h("x-lower", "v"), h("X-UPPER", "V")));
        l.add(n("hdr-very-long", "GET", "https://example.test/h", null, h("X-Long", repeat("0123456789abcdef", 400))));
        l.add(n("hdr-accept-encoding", "GET", "https://example.test/h", null, h("Accept-Encoding", "gzip, deflate, br, zstd")));
        l.add(n("head-request", "HEAD", "https://example.test/h", null, h("Accept", "*/*")));
        l.add(n("delete-request", "DELETE", "https://example.test/items/42", null, h("Authorization", "Bearer t")));
        l.add(n("options-request", "OPTIONS", "https://example.test/items", null, h("Access-Control-Request-Method", "PUT")));
        l.add(n("get-with-body", "GET", "https://example.test/search", "{\"q\":\"x\"}", h("Content-Type", JSON_CT)));
        // bodies
        l.add(n("post-json-simple", "POST", u, "{\"name\":\"Widget\",\"price\":9.99}", h("Content-Type", JSON_CT)));
        l.add(n("post-json-nested-escapes", "POST", u,
                "{\"s\":\"line1\\nline2\",\"p\":\"C:\\\\dir\\\\f\",\"q\":\"say \\\"hi\\\"\",\"u\":\"\\u00e9\",\"a\":[1,2,{\"d\":null}]}",
                h("Content-Type", JSON_CT)));
        l.add(n("post-json-pretty-lf", "POST", u, "{\n  \"a\": 1,\n  \"b\": [\n    2,\n    3\n  ]\n}", h("Content-Type", JSON_CT)));
        l.add(n("post-json-pretty-crlf", "POST", u, "{\r\n  \"a\": 1\r\n}", h("Content-Type", JSON_CT)));
        l.add(n("post-json-single-quote-and-bang", "POST", u, "{\"msg\":\"it's done!\"}", h("Content-Type", JSON_CT)));
        l.add(n("post-json-unicode", "POST", u, "{\"name\":\"日本語 é ñ\",\"emoji\":\"😀\"}", h("Content-Type", "application/json; charset=utf-8")));
        l.add(n("post-xml", "POST", "https://example.test/soap", "<?xml version=\"1.0\"?><a b='c'>&amp;<![CDATA[<x>]]></a>",
                h("Content-Type", "text/xml; charset=utf-8"), h("SOAPAction", "\"urn:Do\"")));
        l.add(n("post-form-simple", "POST", "https://example.test/login", "user=alice&pass=s3cret%21&remember=on",
                h("Content-Type", FORM_CT)));
        l.add(n("post-form-encoded-specials", "POST", "https://example.test/login",
                "a=1&b=%20&c=%26&d=!&e=%25&f=%7E&g=a+b&h=%E3%81%82&i=%00", h("Content-Type", FORM_CT)));
        l.add(n("post-form-charset", "POST", "https://example.test/login", "k=v", h("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")));
        l.add(n("post-text-shell-metachars", "POST", u, "$HOME `id` $(id) ${PATH} %PATH% %USERNAME% ^ ! !x! \\ \\\\ \" ' & | < > ; ( ) [ ] { }",
                h("Content-Type", "text/plain")));
        l.add(n("post-text-quotes-only", "POST", u, "\"'\"'\"'", h("Content-Type", "text/plain")));
        l.add(n("post-text-trailing-backslash", "POST", u, "path\\", h("Content-Type", "text/plain")));
        l.add(n("post-text-backslash-quote", "POST", u, "a\\\"b\\\\\"c", h("Content-Type", "text/plain")));
        l.add(n("post-text-tabs", "POST", u, "a\tb\t\tc", h("Content-Type", "text/plain")));
        l.add(n("post-text-newlines", "POST", u, "l1\nl2\n\nl4\n", h("Content-Type", "text/plain")));
        l.add(n("post-text-crlf", "POST", u, "l1\r\nl2\r\n\r\nl4\r\n", h("Content-Type", "text/plain")));
        l.add(n("post-text-cr-only", "POST", u, "a\rb", h("Content-Type", "text/plain")));
        l.add(n("post-text-unicode", "POST", u, "é ñ 日本語 😀 Ω", h("Content-Type", "text/plain; charset=utf-8")));
        l.add(n("post-text-control-chars", "POST", u, "a\u0001b\u007fc\u001fd", h("Content-Type", "text/plain")));
        l.add(n("post-text-latin1-range", "POST", u, "caf\u00e9 \u00a0 \u0080\u009f\u00ff", h("Content-Type", "text/plain")));
        l.add(n("post-text-bmp-high", "POST", u, "\u0100\u20ac\u2028\u3000\uFEFF\u200b", h("Content-Type", "text/plain")));
        l.add(n("post-body-zero", "POST", u, "0", h("Content-Type", "text/plain")));
        l.add(n("post-body-space", "POST", u, " ", h("Content-Type", "text/plain")));
        l.add(n("post-body-percent-env", "POST", u, "100% done %1 %a% %_ %", h("Content-Type", "text/plain")));
        l.add(n("post-body-long-8k", "POST", u, repeat("0123456789", 800), h("Content-Type", "text/plain")));
        l.add(n("post-body-at-sign-inside", "POST", u, "a@b.test", h("Content-Type", "text/plain")));
        l.add(n("post-body-graphql", "POST", "https://example.test/graphql",
                "{\"operationName\":\"Q\",\"variables\":{\"id\":\"1\"},\"query\":\"query Q($id: ID!) {\\n  user(id: $id) { name }\\n}\"}",
                h("Content-Type", JSON_CT), h("Accept", "application/json")));
        l.add(n("put-json-with-cookies-and-sec", "PUT", "https://example.test/api/v2/users/42?notify=true",
                "{\"email\":\"a@b.test\",\"roles\":[\"admin\",\"dev\"]}",
                h("Accept", "application/json, text/plain, */*"), h("Content-Type", JSON_CT),
                h("Cookie", "session=s3ss10n; csrf=t0k3n"), h("sec-ch-ua", SEC_CH_UA), h("sec-ch-ua-mobile", "?0"),
                h("sec-ch-ua-platform", "\"Windows\""), h("User-Agent", UA), h("X-CSRF-Token", "t0k3n")));
        l.add(n("patch-json", "PATCH", u + "/7", "[{\"op\":\"replace\",\"path\":\"/a\",\"value\":\"b\"}]",
                h("Content-Type", "application/json-patch+json")));
        l.add(n("delete-with-body", "DELETE", u + "/7", "{\"force\":true}", h("Content-Type", JSON_CT)));
        l.add(n("post-multipart-text-only", "POST", "https://example.test/upload",
                "------WebKitFormBoundary7MA4YWxkTrZu0gW\r\nContent-Disposition: form-data; name=\"title\"\r\n\r\nHello \"world\"\r\n"
                        + "------WebKitFormBoundary7MA4YWxkTrZu0gW--\r\n",
                h("Content-Type", "multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW")));
        l.add(n("post-multipart-file", "POST", "https://example.test/upload",
                "-----------------------------12345678901234567890123456\r\nContent-Disposition: form-data; name=\"f\"; filename=\"a.txt\"\r\n"
                        + "Content-Type: text/plain\r\n\r\nfile content line 1\r\nline 2\r\n"
                        + "-----------------------------12345678901234567890123456\r\nContent-Disposition: form-data; name=\"note\"\r\n\r\nhi\r\n"
                        + "-----------------------------12345678901234567890123456--\r\n",
                h("Content-Type", "multipart/form-data; boundary=---------------------------12345678901234567890123456")));
        l.add(n("post-header-blank-and-name-case", "POST", u, "x=1", h("Content-Type", FORM_CT), h("X-Blank", " "), h("x-Mixed", "m")));
        l.add(n("post-content-length-header", "POST", u, "abc", h("Content-Type", "text/plain"), h("Content-Length", "3")));
        l.add(n("post-crlf-and-quotes-everywhere", "POST", "https://example.test/it's?a=\"b\"&c=%d",
                "q=\"1\"\r\n'2'\r\n!3!\r\n%4%\r\n^5^", h("Content-Type", FORM_CT), h("X-Q", "\"'!%^\\"), h("Cookie", "a=\"b\"; c='d'")));
        return l;
    }

    // ------------------------------------------------------------------------------------ random

    static final String[] FRAGMENTS = {
        "\"", "\\", "%", "^", "&", "|", "<", ">", "!", "`", "'", "(", ")", " ", "  ", "\t", "\n", "\r\n", "\r", "%PATH%",
        "%a%", "%1", "%x_", "é", "日本", "😀", "\u0001", "\u00a0", "\u2028", "\u200b", "{\"a\":\"b\"}", "\\\"", "\\\\",
        "\"\"", "[", "]", "{", "}", ";", ",", ":", "=", "+", "~", "/", ".", "?", "*", "a", "Z", "0", "_", "-", "#", "$",
        "@", "bar", "http://x/", "\u007f", "\u0080", "\u00ff", "\u0100", "\u20ac", "$HOME", "$(id)", "${x}", "$'", "\\x41",
        "\\u0041", "\\n", "\\0", "''", "'\\''", "&&", "||", ";;", "2>&1", "%%", "!!", "^^", "^%", "%^", "\"^", "^\"",
        "ünï", "ж", "Ω", "\u0085", "\u00ad", "\ufeff",
    };

    private static final String[] METHODS = {"GET", "GET", "POST", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"};
    private static final String[] NAMES = {"X-A", "X-Token", "Accept", "Accept-Language", "User-Agent", "Referer", "Origin",
        "Authorization", "Cookie", "Content-Type", "X-Request-Id", "sec-ch-ua", "sec-fetch-mode", "If-Match", "X-Empty",
        "Accept-Encoding", "Cache-Control", "x-lower", "X-MIXED-case"};
    private static final String[] PATH_PIECES = {"a", "b", "items", "42", "v1", "%20", "%2F", "%25", "x-y", "z_w", "a;b", "c,d",
        "[0]", "{id}", "it's", "a\"b", "$HOME", "`id`", "!bang", "%PATH%", "^c", "a|b", "(p)", "~u", "*s", "+p", "=e", "@h", "a:b"};
    private static final String[] QUERY_PIECES = {"a=1", "b=%20", "c=%26", "q=hello+world", "x[]=1", "y={z}", "k='v'", "k=\"v\"",
        "u=$HOME", "e=`id`", "p=%PATH%", "pct=100%", "n=!", "c=^", "pi=a|b", "lt=<>", "s=;", "r=(1)", "t=~", "h=%23", "f=a/b?c"};

    static String randomString(Random r) {
        int n = r.nextInt(14);
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < n; i++) {
            if (r.nextInt(5) == 0) {
                sb.append((char) (0x20 + r.nextInt(0x5f)));
            } else {
                sb.append(FRAGMENTS[r.nextInt(FRAGMENTS.length)]);
            }
        }
        return sb.toString();
    }

    static String randomUrl(Random r) {
        StringBuilder u = new StringBuilder(r.nextInt(4) == 0 ? "http://" : "https://");
        switch (r.nextInt(6)) {
            case 0 -> u.append("[2001:db8::").append(r.nextInt(100)).append("]:").append(1 + r.nextInt(65000));
            case 1 -> u.append("h").append(r.nextInt(9)).append(".example.test:").append(1 + r.nextInt(65000));
            case 2 -> u.append("10.0.").append(r.nextInt(256)).append('.').append(r.nextInt(256));
            default -> u.append("h").append(r.nextInt(9)).append(".example.test");
        }
        int segs = r.nextInt(4);
        for (int i = 0; i < segs; i++) {
            u.append('/').append(PATH_PIECES[r.nextInt(PATH_PIECES.length)]);
        }
        if (segs > 0 && r.nextInt(5) == 0) {
            u.append('/');
        }
        int q = r.nextInt(4);
        for (int i = 0; i < q; i++) {
            u.append(i == 0 ? '?' : '&').append(QUERY_PIECES[r.nextInt(QUERY_PIECES.length)]);
        }
        if (r.nextInt(6) == 0) {
            u.append('#').append(r.nextBoolean() ? "frag" : "a=b");
        }
        return u.toString();
    }

    static String randomMultipart(Random r) {
        String b = "----geckoformboundary" + Long.toHexString(r.nextLong() & 0xffffffffL);
        StringBuilder sb = new StringBuilder();
        int parts = 1 + r.nextInt(3);
        for (int i = 0; i < parts; i++) {
            sb.append("--").append(b).append("\r\nContent-Disposition: form-data; name=\"").append(randomString(r).replace("\"", ""))
                    .append('"');
            if (r.nextBoolean()) {
                sb.append("; filename=\"f").append(i).append(".bin\"\r\nContent-Type: application/octet-stream");
            }
            sb.append("\r\n\r\n").append(randomString(r)).append("\r\n");
        }
        return sb.append("--").append(b).append("--\r\n").toString();
    }

    /** A random logical request: valid ASCII URL, unique ordinary header names, free-form values and bodies. */
    static Req random(Random r) {
        String method = METHODS[r.nextInt(METHODS.length)];
        String url = randomUrl(r);
        List<Hdr> hs = new ArrayList<>();
        Set<String> used = new HashSet<>();
        int nh = r.nextInt(6);
        for (int k = 0; k < nh; k++) {
            String name = NAMES[r.nextInt(NAMES.length)];
            if (!used.add(name.toLowerCase(Locale.ROOT))) {
                continue;
            }
            String value;
            int c = r.nextInt(12);
            if (c == 0) {
                value = "";
            } else if (c == 1) {
                value = " ";
            } else if (name.equalsIgnoreCase("Cookie") && r.nextInt(3) > 0) {
                value = "k" + r.nextInt(9) + "=" + randomString(r);
            } else {
                value = randomString(r);
            }
            hs.add(new Hdr(name, value));
        }
        String body = null;
        int b = r.nextInt(10);
        if (b >= 5) {
            body = randomString(r);
        } else if (b == 4) {
            body = randomMultipart(r);
            hs.removeIf(x -> x.name().equalsIgnoreCase("content-type"));
            hs.add(new Hdr("Content-Type", "multipart/form-data; boundary=" + body.substring(2, body.indexOf("\r\n"))));
        } else if (b == 3) {
            body = "k=" + randomString(r).replace("\r", "").replace("\n", "") + "&" + randomString(r).replace("&", "");
            hs.removeIf(x -> x.name().equalsIgnoreCase("content-type"));
            hs.add(new Hdr("Content-Type", FORM_CT));
        }
        boolean insecure = r.nextInt(5) == 0;
        boolean enc = r.nextInt(3) == 0;
        return new Req(method, url, hs, body, insecure, enc, null).withBody(body);
    }

    /**
     * Removes what no browser/curl pair can carry or what is outside the realistic domain (NUL, lone surrogates,
     * header names curl treats specially).
     */
    static String stripUnsendable(String s) {
        if (s == null) {
            return null;
        }
        StringBuilder b = new StringBuilder();
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == 0) {
                continue;
            }
            if (Character.isHighSurrogate(c) && i + 1 < s.length() && Character.isLowSurrogate(s.charAt(i + 1))) {
                b.append(c).append(s.charAt(++i));
            } else if (!Character.isSurrogate(c)) {
                b.append(c);
            }
        }
        return b.toString();
    }

    /** @return a request without NUL and lone surrogates anywhere */
    static Req clean(Req r) {
        List<Hdr> hs = new ArrayList<>();
        for (Hdr h : r.headers()) {
            hs.add(new Hdr(stripUnsendable(h.name()), stripUnsendable(h.value())));
        }
        return new Req(r.method(), stripUnsendable(r.url()), hs, stripUnsendable(r.body()), r.insecure(), r.respEncoded(),
                stripUnsendable(r.safariContentType()));
    }

    /** @return true when the bytes are well-formed UTF-8 */
    static boolean validUtf8(byte[] b) {
        try {
            java.nio.charset.StandardCharsets.UTF_8.newDecoder().decode(java.nio.ByteBuffer.wrap(b));
            return true;
        } catch (java.nio.charset.CharacterCodingException e) {
            return false;
        }
    }

    /**
     * Inputs excluded from the general round trip because the generator output is something real curl refuses.
     * @return null when fine, otherwise the reason
     */
    static String generatorOutputUnusable(Flavor f, BrowserGenerators.Gen g) {
        List<String> a = g.argv();
        boolean hasData = a.contains("--data-raw") || a.contains("--data-binary") || a.contains("--data");
        if (a.contains("-I") && hasData) {
            return "curl refuses -I together with a body (exit 2): Firefox emits both for HEAD + urlencoded body";
        }
        return null;
    }

    /**
     * A header value that ends with CRLF or holds CRLF CRLF ends the request head early on the wire: the rest of the
     * request is then a second, malformed request for any server. Real-curl comparisons skip these.
     * @return true when the flavour's clipboard text sends such a header
     */
    static boolean splitsTheRequestOnTheWire(Flavor f, BrowserGenerators.Gen g) {
        List<String> a = g.argv();
        for (int i = 0; i + 1 < a.size(); i++) {
            if (a.get(i).equals("-H") || a.get(i).equals("-b")) {
                String v = new String(Expectation.loss(f, a.get(i + 1)), java.nio.charset.StandardCharsets.ISO_8859_1);
                if (v.endsWith("\r\n") || v.contains("\r\n\r\n")) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * Whether a logical request is inside the domain a flavour can express at all.
     * @return null when applicable, otherwise the reason
     */
    static String notApplicable(Flavor f, Req r) {
        boolean firefox = f == Flavor.FIREFOX_BASH || f == Flavor.FIREFOX_CMD;
        if (firefox && (r.url().contains("{") || r.url().contains("}"))) {
            return "Firefox does not escape { } in the URL, curl would glob them";
        }
        if (f == Flavor.SAFARI_BASH && r.body() != null && r.body().startsWith("@")) {
            return "Safari --data @... reads a file";
        }
        return null;
    }
}
