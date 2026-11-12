package burp.curl.browser;

import burp.curl.browser.BrowserGenerators.Hdr;
import burp.curl.browser.BrowserGenerators.Req;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Realistic logical requests, as each browser's network panel would list them. Fake credentials only. The host is the
 * placeholder {@code __HOSTPORT__}, replaced by a loopback address at test time.
 */
final class FixtureRequests {
    private FixtureRequests() {
    }

    static final String HP = "__HOSTPORT__";
    private static final String BASE = "http://" + HP;

    private static final String CHROME_UA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36";
    private static final String FIREFOX_UA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:125.0) Gecko/20100101 Firefox/125.0";
    private static final String SAFARI_UA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15";
    private static final String SEC_CH_UA = "\"Chromium\";v=\"124\", \"Google Chrome\";v=\"124\", \"Not-A.Brand\";v=\"99\"";
    private static final String JWT = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJmYWtlLXVzZXIifQ.ZmFrZS1zaWduYXR1cmU";
    private static final String GQL = "{\"operationName\":\"GetUser\",\"variables\":{\"id\":\"42\",\"withPosts\":true},"
            + "\"query\":\"query GetUser($id: ID!, $withPosts: Boolean!) {\\n  user(id: $id) {\\n    id\\n    name\\n"
            + "    posts @include(if: $withPosts) { title }\\n  }\\n}\"}";

    /** A named logical request. */
    record Fx(String name, Req req) {
    }

    private static Hdr h(String n, String v) {
        return new Hdr(n, v);
    }

    private static Fx fx(String name, String method, String path, String body, Hdr... hs) {
        return new Fx(name, new Req(method, BASE + path, List.of(hs), body, false, false, null).withBody(body));
    }

    private static Hdr[] cat(List<Hdr> a, Hdr... b) {
        List<Hdr> l = new ArrayList<>(a);
        l.addAll(List.of(b));
        return l.toArray(new Hdr[0]);
    }

    // ------------------------------------------------------------------------------------ Chrome

    private static List<Hdr> chromeXhr(String referer) {
        return List.of(h("accept", "application/json, text/plain, */*"), h("accept-encoding", "gzip, deflate, br, zstd"),
                h("accept-language", "en-US,en;q=0.9"), h("cookie", "session=fake-session-id; csrftoken=fake-csrf-token; theme=dark"),
                h("origin", BASE), h("priority", "u=1, i"), h("referer", referer), h("sec-ch-ua", SEC_CH_UA),
                h("sec-ch-ua-mobile", "?0"), h("sec-ch-ua-platform", "\"macOS\""), h("sec-fetch-dest", "empty"),
                h("sec-fetch-mode", "cors"), h("sec-fetch-site", "same-origin"), h("user-agent", CHROME_UA));
    }

    static List<Fx> chrome() {
        List<Fx> l = new ArrayList<>();
        List<Hdr> xhr = chromeXhr(BASE + "/app/users/42");
        l.add(fx("rest-json-put-cookies-sec", "PUT", "/api/v2/users/42?notify=true",
                "{\"email\":\"alice@example.test\",\"roles\":[\"admin\",\"dev\"],\"profile\":{\"name\":\"Alice \\\"Al\\\" O'Neil\",\"bio\":null}}",
                cat(xhr, h("authorization", JWT), h("content-type", "application/json"), h("content-length", "117"),
                        h("host", HP))));
        l.add(fx("form-login-post", "POST", "/login",
                "username=alice&password=s3cret-fake%21&remember=on&next=%2Fdashboard%3Ftab%3Dsettings",
                h("accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"),
                h("accept-language", "en-US,en;q=0.9"), h("cache-control", "max-age=0"),
                h("content-type", "application/x-www-form-urlencoded"), h("cookie", "csrftoken=fake-csrf-token"),
                h("origin", BASE), h("referer", BASE + "/login"), h("sec-ch-ua", SEC_CH_UA), h("sec-ch-ua-mobile", "?0"),
                h("sec-ch-ua-platform", "\"Windows\""), h("sec-fetch-dest", "document"), h("sec-fetch-mode", "navigate"),
                h("sec-fetch-site", "same-origin"), h("sec-fetch-user", "?1"), h("upgrade-insecure-requests", "1"),
                h("user-agent", CHROME_UA)));
        l.add(fx("graphql-post", "POST", "/graphql", GQL,
                cat(chromeXhr(BASE + "/app"), h("content-type", "application/json"), h("x-apollo-operation-name", "GetUser"))));
        String b = "----WebKitFormBoundaryx2jK9fLq0Zr3TnVb";
        l.add(fx("multipart-upload", "POST", "/api/upload",
                "--" + b + "\r\nContent-Disposition: form-data; name=\"title\"\r\n\r\nQuarterly report\r\n--" + b
                        + "\r\nContent-Disposition: form-data; name=\"file\"; filename=\"report.txt\"\r\nContent-Type: text/plain\r\n\r\n"
                        + "line one\r\nline two with \"quotes\" and 'apostrophes'\r\n--" + b + "--\r\n",
                cat(chromeXhr(BASE + "/app/upload"), h("content-type", "multipart/form-data; boundary=" + b))));
        StringBuilder q = new StringBuilder("/search?q=curl+to+repeater");
        for (int i = 1; i <= 12; i++) {
            q.append("&filter%5B").append(i).append("%5D=value-").append(i).append("&sort=name%2Casc");
        }
        l.add(fx("get-long-query", "GET", q.toString(), null, cat(chromeXhr(BASE + "/search"))));
        l.add(fx("navigation-get-cookie", "GET", "/dashboard", null,
                h("accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8"),
                h("accept-encoding", "gzip, deflate, br"), h("accept-language", "en-US,en;q=0.9"),
                h("cookie", "session=fake-session-id; _ga=GA1.1.123456789.1700000000; consent=%7B%22a%22%3Atrue%7D"),
                h("sec-ch-ua", SEC_CH_UA), h("sec-ch-ua-mobile", "?0"), h("sec-ch-ua-platform", "\"macOS\""),
                h("sec-fetch-dest", "document"), h("sec-fetch-mode", "navigate"), h("sec-fetch-site", "none"),
                h("sec-fetch-user", "?1"), h("upgrade-insecure-requests", "1"), h("user-agent", CHROME_UA)));
        l.add(fx("delete-bearer", "DELETE", "/api/v2/items/7", null, cat(xhr, h("authorization", JWT))));
        l.add(fx("patch-json-patch", "PATCH", "/api/v2/items/7", "[{\"op\":\"replace\",\"path\":\"/name\",\"value\":\"New name\"}]",
                cat(xhr, h("authorization", JWT), h("content-type", "application/json-patch+json"))));
        l.add(fx("post-json-unicode-escapes", "POST", "/api/messages", "{\"text\":\"caf\\u00e9 \\ud83d\\ude00 \\n done\",\"lang\":\"fr\"}",
                cat(xhr, h("content-type", "application/json;charset=UTF-8"))));
        l.add(fx("cors-preflight-options", "OPTIONS", "/api/v2/users/42", null,
                h("accept", "*/*"), h("access-control-request-headers", "authorization,content-type"),
                h("access-control-request-method", "PUT"), h("origin", "http://app.example.test"), h("referer", "http://app.example.test/"),
                h("sec-fetch-dest", "empty"), h("sec-fetch-mode", "cors"), h("sec-fetch-site", "cross-site"),
                h("user-agent", CHROME_UA)));
        l.add(fx("post-csrf-xhr-text", "POST", "/api/track", "event=click&target=%23buy-now&ts=1700000000000",
                cat(xhr, h("content-type", "application/x-www-form-urlencoded; charset=UTF-8"), h("x-csrf-token", "fake-csrf-token"),
                        h("x-requested-with", "XMLHttpRequest"))));
        l.add(fx("get-empty-header-and-json-accept", "GET", "/api/v2/me", null,
                h("accept", "application/json"), h("authorization", JWT), h("if-none-match", "W/\"33a64df551425fcc55e4d42a148795d9f25f89d4\""),
                h("x-empty", ""), h("user-agent", CHROME_UA)));
        return l;
    }

    // ------------------------------------------------------------------------------------ Firefox

    private static List<Hdr> firefoxXhr(String referer) {
        return List.of(h("Host", HP), h("User-Agent", FIREFOX_UA), h("Accept", "application/json, text/plain, */*"),
                h("Accept-Language", "en-US,en;q=0.5"), h("Accept-Encoding", "gzip, deflate, br, zstd"), h("Origin", BASE),
                h("Connection", "keep-alive"), h("Referer", referer), h("Cookie", "session=fake-session-id; csrftoken=fake-csrf-token"),
                h("Sec-Fetch-Dest", "empty"), h("Sec-Fetch-Mode", "cors"), h("Sec-Fetch-Site", "same-origin"), h("Priority", "u=0"));
    }

    static List<Fx> firefox() {
        List<Fx> l = new ArrayList<>();
        List<Hdr> xhr = firefoxXhr(BASE + "/app/users/42");
        l.add(fx("rest-json-put-cookies", "PUT", "/api/v2/users/42?notify=true",
                "{\"email\":\"alice@example.test\",\"roles\":[\"admin\",\"dev\"],\"profile\":{\"name\":\"Alice \\\"Al\\\" O'Neil\",\"bio\":null}}",
                cat(xhr, h("Authorization", JWT), h("Content-Type", "application/json"), h("Content-Length", "117"))));
        l.add(fx("form-login-post", "POST", "/login",
                "username=alice&password=s3cret-fake%21&remember=on&next=%2Fdashboard%3Ftab%3Dsettings",
                h("Host", HP), h("User-Agent", FIREFOX_UA), h("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"),
                h("Accept-Language", "en-US,en;q=0.5"), h("Accept-Encoding", "gzip, deflate, br, zstd"),
                h("Content-Type", "application/x-www-form-urlencoded"), h("Content-Length", "84"), h("Origin", BASE),
                h("Connection", "keep-alive"), h("Referer", BASE + "/login"), h("Cookie", "csrftoken=fake-csrf-token"),
                h("Upgrade-Insecure-Requests", "1"), h("Sec-Fetch-Dest", "document"), h("Sec-Fetch-Mode", "navigate"),
                h("Sec-Fetch-Site", "same-origin"), h("Sec-Fetch-User", "?1"), h("Priority", "u=0, i")));
        l.add(fx("graphql-post", "POST", "/graphql", GQL, cat(firefoxXhr(BASE + "/app"), h("Content-Type", "application/json"))));
        String b = "----geckoformboundary4c7e91ab2d3f50168e9a7b6c5d4e3f21";
        // Firefox hands the generator the whole body; the file part carries (here, short) binary content it will strip
        l.add(fx("multipart-upload", "POST", "/api/upload",
                "--" + b + "\r\nContent-Disposition: form-data; name=\"title\"\r\n\r\nQuarterly report\r\n--" + b
                        + "\r\nContent-Disposition: form-data; name=\"file\"; filename=\"report.bin\"\r\nContent-Type: application/octet-stream\r\n\r\n"
                        + "BINARYDATA\r\n--" + b + "--\r\n",
                cat(firefoxXhr(BASE + "/app/upload"), h("Content-Type", "multipart/form-data; boundary=" + b))));
        StringBuilder q = new StringBuilder("/search?q=curl+to+repeater");
        for (int i = 1; i <= 12; i++) {
            q.append("&filter%5B").append(i).append("%5D=value-").append(i).append("&sort=name%2Casc");
        }
        l.add(fx("get-long-query", "GET", q.toString(), null, cat(firefoxXhr(BASE + "/search"))));
        l.add(fx("navigation-get-cookie", "GET", "/dashboard", null,
                h("Host", HP), h("User-Agent", FIREFOX_UA), h("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"),
                h("Accept-Language", "en-US,en;q=0.5"), h("Accept-Encoding", "gzip, deflate, br, zstd"), h("Connection", "keep-alive"),
                h("Cookie", "session=fake-session-id; _ga=GA1.1.123456789.1700000000"), h("Upgrade-Insecure-Requests", "1"),
                h("Sec-Fetch-Dest", "document"), h("Sec-Fetch-Mode", "navigate"), h("Sec-Fetch-Site", "none"),
                h("Sec-Fetch-User", "?1"), h("Priority", "u=0, i"), h("TE", "trailers")));
        l.add(fx("delete-bearer", "DELETE", "/api/v2/items/7", null, cat(xhr, h("Authorization", JWT))));
        l.add(fx("patch-json-patch", "PATCH", "/api/v2/items/7", "[{\"op\":\"replace\",\"path\":\"/name\",\"value\":\"New name\"}]",
                cat(xhr, h("Authorization", JWT), h("Content-Type", "application/json-patch+json"))));
        l.add(fx("post-json-unicode-escapes", "POST", "/api/messages", "{\"text\":\"caf\\u00e9 \\ud83d\\ude00 \\n done\",\"lang\":\"fr\"}",
                cat(xhr, h("Content-Type", "application/json;charset=UTF-8"))));
        l.add(fx("cors-preflight-options", "OPTIONS", "/api/v2/users/42", null,
                h("Host", HP), h("User-Agent", FIREFOX_UA), h("Accept", "*/*"), h("Accept-Language", "en-US,en;q=0.5"),
                h("Accept-Encoding", "gzip, deflate, br, zstd"), h("Access-Control-Request-Method", "PUT"),
                h("Access-Control-Request-Headers", "authorization,content-type"), h("Referer", "http://app.example.test/"),
                h("Origin", "http://app.example.test"), h("Connection", "keep-alive"), h("Sec-Fetch-Dest", "empty"),
                h("Sec-Fetch-Mode", "cors"), h("Sec-Fetch-Site", "cross-site"), h("Priority", "u=4")));
        l.add(fx("head-request", "HEAD", "/assets/app.js", null, h("Host", HP), h("User-Agent", FIREFOX_UA), h("Accept", "*/*"),
                h("Accept-Language", "en-US,en;q=0.5"), h("Accept-Encoding", "gzip, deflate, br, zstd"), h("Connection", "keep-alive")));
        l.add(fx("post-csrf-xhr-form", "POST", "/api/track", "event=click&target=%23buy-now&ts=1700000000000",
                cat(xhr, h("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8"), h("X-CSRF-Token", "fake-csrf-token"),
                        h("X-Requested-With", "XMLHttpRequest"))));
        return l;
    }

    // ------------------------------------------------------------------------------------ Safari

    private static List<Hdr> safariXhr(String referer) {
        return List.of(h("Accept", "application/json, text/plain, */*"), h("Accept-Language", "en-US,en;q=0.9"), h("Origin", BASE),
                h("Referer", referer), h("User-Agent", SAFARI_UA), h("Cookie", "session=fake-session-id; csrftoken=fake-csrf-token"),
                h("Host", HP));
    }

    static List<Fx> safari() {
        List<Fx> l = new ArrayList<>();
        List<Hdr> xhr = safariXhr(BASE + "/app/users/42");
        l.add(fx("rest-json-put-cookies", "PUT", "/api/v2/users/42?notify=true",
                "{\"email\":\"alice@example.test\",\"roles\":[\"admin\",\"dev\"],\"profile\":{\"name\":\"Alice \\\"Al\\\" O'Neil\",\"bio\":null}}",
                cat(xhr, h("Authorization", JWT), h("Content-Type", "application/json"))));
        l.add(fx("form-login-post", "POST", "/login",
                "username=alice&password=s3cret-fake%21&remember=on&next=%2Fdashboard%3Ftab%3Dsettings",
                h("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"), h("Accept-Language", "en-US,en;q=0.9"),
                h("Content-Type", "application/x-www-form-urlencoded"), h("Origin", BASE), h("Referer", BASE + "/login"),
                h("User-Agent", SAFARI_UA), h("Cookie", "csrftoken=fake-csrf-token"), h("Host", HP)));
        l.add(fx("graphql-post", "POST", "/graphql", GQL, cat(safariXhr(BASE + "/app"), h("Content-Type", "application/json"))));
        String b = "----WebKitFormBoundaryx2jK9fLq0Zr3TnVb";
        l.add(fx("multipart-upload", "POST", "/api/upload",
                "--" + b + "\r\nContent-Disposition: form-data; name=\"title\"\r\n\r\nQuarterly report\r\n--" + b
                        + "\r\nContent-Disposition: form-data; name=\"file\"; filename=\"report.txt\"\r\nContent-Type: text/plain\r\n\r\n"
                        + "line one\r\nline two\r\n--" + b + "--\r\n",
                cat(safariXhr(BASE + "/app/upload"), h("Content-Type", "multipart/form-data; boundary=" + b))));
        StringBuilder q = new StringBuilder("/search?q=curl+to+repeater");
        for (int i = 1; i <= 12; i++) {
            q.append("&filter%5B").append(i).append("%5D=value-").append(i).append("&sort=name%2Casc");
        }
        l.add(fx("get-long-query", "GET", q.toString(), null, cat(safariXhr(BASE + "/search"))));
        l.add(fx("navigation-get-cookie", "GET", "/dashboard", null,
                h("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"), h("Accept-Language", "en-US,en;q=0.9"),
                h("User-Agent", SAFARI_UA), h("Cookie", "session=fake-session-id; _ga=GA1.1.123456789.1700000000"), h("Host", HP)));
        l.add(fx("delete-bearer", "DELETE", "/api/v2/items/7", null, cat(xhr, h("Authorization", JWT))));
        l.add(fx("patch-json-patch", "PATCH", "/api/v2/items/7", "[{\"op\":\"replace\",\"path\":\"/name\",\"value\":\"New name\"}]",
                cat(xhr, h("Authorization", JWT), h("Content-Type", "application/json-patch+json"))));
        l.add(fx("post-json-unicode-escapes", "POST", "/api/messages", "{\"text\":\"caf\\u00e9 \\ud83d\\ude00 \\n done\",\"lang\":\"fr\"}",
                cat(xhr, h("Content-Type", "application/json;charset=UTF-8"))));
        l.add(fx("cors-preflight-options", "OPTIONS", "/api/v2/users/42", null,
                h("Accept", "*/*"), h("Access-Control-Request-Headers", "authorization, content-type"),
                h("Access-Control-Request-Method", "PUT"), h("Origin", "http://app.example.test"),
                h("Referer", "http://app.example.test/"), h("User-Agent", SAFARI_UA), h("Host", HP)));
        l.add(fx("post-csrf-xhr-form-bang", "POST", "/api/track", "event=click!&target=%23buy-now&ts=1700000000000",
                cat(xhr, h("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8"), h("X-CSRF-Token", "fake-csrf-token"),
                        h("X-Requested-With", "XMLHttpRequest"))));
        l.add(fx("head-request", "HEAD", "/assets/app.js", null, h("Accept", "*/*"), h("User-Agent", SAFARI_UA), h("Host", HP)));
        return l;
    }

    static Map<String, List<Fx>> all() {
        Map<String, List<Fx>> m = new LinkedHashMap<>();
        m.put("chrome", chrome());
        m.put("firefox", firefox());
        m.put("safari", safari());
        return m;
    }
}
