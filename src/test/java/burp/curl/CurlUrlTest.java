package burp.curl;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class CurlUrlTest {
    private static CurlUrl p(String u) throws CurlParseException {
        return CurlUrl.parse(u, null, false);
    }

    @Test
    void briefFactDotSegmentsFragmentAndPathAsIs() throws Exception {
        String u = "http://127.0.0.1:18765/a/../b/./c/%2e%2e/d?x=/../y#frag";
        assertEquals("/b/c/%2e%2e/d?x=/../y", p(u).requestTarget());
        assertEquals("/a/../b/./c/%2e%2e/d?x=/../y", CurlUrl.parse(u, null, true).requestTarget());
    }

    @Test
    void briefFactIpv6WithoutGlobbing() throws Exception {
        CurlUrl u = p("http://[::1]:18765/v6?x=[1]&y={a,b}");
        assertEquals("/v6?x=[1]&y={a,b}", u.requestTarget());
        assertEquals("[::1]:18765", u.hostHeader());
        assertEquals("::1", u.host());
        assertEquals(18765, u.port());
    }

    @Test
    void schemeLessIsHttpAndProtoDefaultWins() throws Exception {
        CurlUrl u = p("127.0.0.1:18765/search");
        assertEquals("http", u.scheme());
        assertFalse(u.secure());
        assertEquals("/search", u.path());
        CurlUrl s = CurlUrl.parse("example.com/x", "https", false);
        assertTrue(s.secure());
        assertEquals(443, s.port());
        assertEquals("example.com", s.hostHeader());
        assertEquals("https://example.com/x", s.toString());
    }

    @Test
    void guessedNonHttpSchemesAreErrors() {
        for (String u : new String[] {"ftp.example.com/x", "imap.example.com", "SMTP.a.b", "ldap.x", "ftp://a/", "file:///etc/passwd", "gopher://a"}) {
            CurlParseException e = assertThrows(CurlParseException.class, () -> p(u), u);
            assertTrue(e.getMessage().startsWith("unsupported protocol"), e.getMessage());
        }
        assertThrows(CurlParseException.class, () -> CurlUrl.parse("example.com", "ftp", false));
    }

    @Test
    void userinfoIsDecoded() throws Exception {
        CurlUrl u = p("http://usr:p%40ss@127.0.0.1:18765/u");
        assertEquals("usr", u.user());
        assertEquals("p@ss", u.password());
        assertEquals("/u", u.path());
        assertNull(p("http://h/").user());
        assertNull(p("http://u@h/").password());
        assertEquals("", p("http://u:@h/").password());
        assertEquals("", p("http://:p@h/").user());
    }

    @Test
    void defaultPathPortAndQuery() throws Exception {
        assertEquals("/", p("http://h").path());
        assertNull(p("http://h").query());
        assertEquals("/?x=1", p("http://h?x=1").requestTarget());
        assertEquals("", p("http://h/?").query());
        assertEquals("/?", p("http://h/?#f").requestTarget());
        assertEquals("h", p("http://h:80/").hostHeader());
        assertEquals("h:0", p("http://h:0/").hostHeader());
        assertEquals("h:8080", p("http://h:8080/").hostHeader());
        assertEquals("h", p("http://h:/").hostHeader());
        assertEquals(80, p("http://h:/").port());
        assertEquals("h:443", p("http://h:443/").hostHeader());
        assertEquals("h", CurlUrl.parse("https://h:443/", null, false).hostHeader());
        assertEquals("h:80", CurlUrl.parse("https://h:80/", null, false).hostHeader());
    }

    @Test
    void invalidPortsAreErrors() {
        for (String u : new String[] {"http://h:65536/", "http://h:-1/", "http://h:+1/", "http://h:abc/", "http://h:1:2/", "http://[::1]x/", "http://h: 80/"}) {
            assertThrows(CurlParseException.class, () -> p(u), u);
        }
    }

    @Test
    void hostRulesFollowCurl() throws Exception {
        assertEquals("EXAMPLE.com", p("http://EXAMPLE.com/").hostHeader());
        assertEquals("127.0.0.1", p("http://127.1/").hostHeader());
        assertEquals("127.0.0.1", p("http://0x7f.1/").hostHeader());
        assertEquals("256.1.1.1", p("http://256.1.1.1/").hostHeader());
        assertEquals("example.com", p("http://ex%61mple.com/").hostHeader());
        for (String u : new String[] {"http://", "http://:81/", "http:///", "http://a b/", "http://a!b/", "http://a.com%2fx/", "http://a@b@c.com/"}) {
            assertThrows(CurlParseException.class, () -> p(u), u);
        }
    }

    @Test
    void idnIsPunycode() throws Exception {
        CurlUrl u = p("http://b\u00fccher.de:81/");
        assertEquals("xn--bcher-kva.de", u.host());
        assertEquals("xn--bcher-kva.de:81", u.hostHeader());
    }

    @Test
    void ipv6Forms() throws Exception {
        assertEquals("[::1]", p("http://[0:0:0:0:0:0:0:1]/").hostHeader());
        assertEquals("[2001:db8::1]", p("http://[2001:DB8:0:0:0:0:0:1]/").hostHeader());
        assertEquals("[2001:DB8::1]", p("http://[2001:DB8::1]/").hostHeader());
        assertEquals("[::ffff:1.2.3.4]", p("http://[::ffff:0102:0304]/").hostHeader());
        assertEquals("[FE80::1]", p("http://[FE80::1%25en0]/").hostHeader());
        assertEquals("FE80::1", p("http://[FE80::1%25en0]/").host());
        assertEquals("[::1]:81", p("http://u:p@[::1]:81/").hostHeader());
        for (String u : new String[] {"http://[]/", "http://[zz]/", "http://[1.2.3.4]/", "http://[::1", "http://[1:2:3]/"}) {
            assertThrows(CurlParseException.class, () -> p(u), u);
        }
    }

    @Test
    void pathEncodingAndDotSegments() throws Exception {
        assertEquals("/%c3%a9", p("http://h/\u00e9").path());
        assertEquals("/?q=\u00e9", p("http://h/?q=\u00e9").requestTarget());
        assertEquals("/a\\b", p("http://h/a\\b").path());
        assertEquals("/", p("http://h/a/..").path());
        assertEquals("/a/", p("http://h/a/.").path());
        assertEquals("/x", p("http://h/../../x").path());
        assertEquals("/a/b", p("http://h/a//../b").path());
        assertEquals("/..a/a../.../b", p("http://h/..a/a../.../b").path());
    }

    @Test
    void lenientSpacesAndWhitespace() throws Exception {
        assertEquals("/a%20b?x=%201", p("http://h/a b?x= 1").requestTarget());
        assertEquals("/a%20b", p("  http://h/a b \n").path());
        assertThrows(CurlParseException.class, () -> p("http://h/a\tb"));
        assertThrows(CurlParseException.class, () -> p("http://h/a\u007fb"));
        assertThrows(CurlParseException.class, () -> p("http://us er@h/"));
    }

    @Test
    void appendedQueryFollowsCurl() throws Exception {
        assertEquals("/?x=1", p("http://h/").withAppendedQuery("x=1").requestTarget());
        assertEquals("/?x=1", p("http://h/?").withAppendedQuery("x=1").requestTarget());
        assertEquals("/?a&x=1", p("http://h/?a").withAppendedQuery("x=1").requestTarget());
        assertEquals("/?a&x=1", p("http://h/?a&").withAppendedQuery("x=1").requestTarget());
        assertEquals("/?a=1&&x=1", p("http://h/?a=1&&").withAppendedQuery("x=1").requestTarget());
        assertEquals("/?x=1&y=2", p("http://h/").withAppendedQuery("x=1").withAppendedQuery("y=2").requestTarget());
        assertEquals("/?a&", p("http://h/?a").withAppendedQuery("").requestTarget());
        CurlUrl none = p("http://h/");
        assertSame(none, none.withAppendedQuery(""));
        assertEquals("/b?x=1", CurlUrl.parse("http://h/a/../b", null, true).withAppendedQuery("x=1").requestTarget());
    }

    @Test
    void pathSuffixFollowsCurl() throws Exception {
        assertEquals("/dir/a.txt", p("http://h/dir/").withPathSuffix("a.txt").path());
        assertEquals("/dir/my%20f%c3%afle%2b1.txt", p("http://h/dir/").withPathSuffix("my f\u00efle+1.txt").path());
        assertEquals("/a.txt", p("http://h").withPathSuffix("a.txt").path());
        assertEquals("/dir/a.txt", p("http://h/dir/#f").withPathSuffix("a.txt").path());
        CurlUrl noSlash = p("http://h/dir");
        assertSame(noSlash, noSlash.withPathSuffix("a.txt"));
        CurlUrl withQuery = p("http://h/dir/?q=1");
        assertSame(withQuery, withQuery.withPathSuffix("a.txt"));
    }

    @Test
    void toStringIsNormalisedWithoutUserinfoAndFragment() throws Exception {
        assertEquals("http://h:8080/a?b", p("HTTP://u:p@h:8080/x/../a?b#f").toString());
    }
}
