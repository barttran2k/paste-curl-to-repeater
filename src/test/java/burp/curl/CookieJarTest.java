package burp.curl;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Test;

/** The expected cookie lists were measured with the real curl 8.7.1 against a loopback server. */
class CookieJarTest {
    private static final String T = "\t";
    private static final long NOW = 1_700_000_000L;

    private static String send(String file, String host, String path, boolean https) {
        CookieJar jar = new CookieJar();
        jar.load(file.getBytes(StandardCharsets.UTF_8), NOW, false);
        List<CookieJar.Cookie> list = jar.matching(host, path, https, NOW);
        return list.stream().map(c -> c.name + "=" + c.value).collect(Collectors.joining("; "));
    }

    private static String net(String domain, String path, String expires, String name, String value) {
        return domain + T + "FALSE" + T + path + T + "FALSE" + T + expires + T + name + T + value + "\n";
    }

    @Test
    void longerNamesFirstThenNewestFirst() {
        assertEquals("bb=1; a=2", send(net("127.0.0.1", "/", "0", "bb", "1") + net("127.0.0.1", "/", "0", "a", "2"),
                "127.0.0.1", "/x", false));
        assertEquals("pref=dark; sid=abc123", send(net("127.0.0.1", "/", "0", "sid", "abc123")
                + net("127.0.0.1", "/", "0", "pref", "dark"), "127.0.0.1", "/c", false));
    }

    @Test
    void longestPathFirstAndPathsMustMatch() {
        String f = net("127.0.0.1", "/", "0", "a", "1") + net("127.0.0.1", "/", "0", "b", "2")
                + net("127.0.0.1", "/x", "0", "c", "3") + net("127.0.0.1", "/x/y", "0", "d", "4");
        assertEquals("d=4; c=3; b=2; a=1", send(f, "127.0.0.1", "/x/y/z", false));
        assertEquals("b=2; a=1", send(f, "127.0.0.1", "/other", false));
        assertEquals("c=3; b=2; a=1", send(f, "127.0.0.1", "/x/yy", false));
    }

    @Test
    void expiredSecureHttpOnlyEmptyAndForeignDomains() {
        String f = "127.0.0.1" + T + "FALSE" + T + "/" + T + "TRUE" + T + "0" + T + "sec" + T + "1\n"
                + net("127.0.0.1", "/", "1", "old", "1") + net("127.0.0.1", "/", "99999999999", "fut", "1")
                + "#HttpOnly_" + net("127.0.0.1", "/", "0", "ho", "1")
                + ".example.test" + T + "TRUE" + T + "/" + T + "FALSE" + T + "0" + T + "other" + T + "1\n"
                + "127.0.0.1" + T + "FALSE" + T + "/" + T + "FALSE" + T + "0" + T + "empty\n"
                + net("127.0.0.1", "/", "0", "empty2", "");
        assertEquals("empty2=; empty=; fut=1; sec=1; ho=1", send(f, "127.0.0.1", "/x", false));
        assertEquals("empty2=; empty=; fut=1; sec=1; ho=1", send(f, "127.0.0.1", "/x", true));
        assertEquals("other=1", send(f, "www.example.test", "/", true));
    }

    @Test
    void setCookieLinesWithoutDomainMatchEveryHost() {
        String f = "Set-Cookie: a=1\nSet-Cookie: b=2; Path=/x\nset-cookie: c=3; Domain=other.test\n"
                + "Set-Cookie: d=4; Secure\nSet-Cookie: e=5; Max-Age=0\nSet-Cookie: f=6; Expires=Thu, 01 Jan 1970 00:00:00 GMT\n"
                + "Set-Cookie: g=7; Expires=Fri, 01 Jan 2100 00:00:00 GMT\nSet-Cookie: a=9\n";
        assertEquals("b=2; g=7; d=4; a=9", send(f, "127.0.0.1", "/x/y/z", false));
    }

    @Test
    void duplicatesAreReplacedAndOtherPortsDoNotMatch() {
        String f = net("127.0.0.1", "/", "0", "a", "1") + net("127.0.0.1", "/", "0", "a", "2")
                + net("127.0.0.1:18999", "/", "0", "port", "2") + net("localhost", "/", "0", "lh", "2");
        assertEquals("a=2", send(f, "127.0.0.1", "/x/y/z", false));
    }

    @Test
    void junkSessionCookiesDropsCookiesWithoutExpiry() {
        CookieJar jar = new CookieJar();
        jar.load(("Set-Cookie: a=1\nSet-Cookie: g=7; Expires=Fri, 01 Jan 2100 00:00:00 GMT\n")
                .getBytes(StandardCharsets.UTF_8), NOW, true);
        assertEquals(1, jar.matching("h", "/", false, NOW).size());
    }

    @Test
    void aLineThatIsNotACookieIsIgnored() {
        assertEquals("", send("session=abc; theme=dark\n", "127.0.0.1", "/c", false));
        assertEquals("", send("# Netscape HTTP Cookie File\n\n", "127.0.0.1", "/c", false));
    }

    @Test
    void tailMatchOnlyAtLabelBoundaries() {
        String f = ".example.test" + T + "TRUE" + T + "/" + T + "FALSE" + T + "0" + T + "n" + T + "v\n";
        assertEquals("n=v", send(f, "www.example.test", "/", false));
        assertEquals("n=v", send(f, "example.test", "/", false));
        assertEquals("", send(f, "badexample.test", "/", false));
    }
}
