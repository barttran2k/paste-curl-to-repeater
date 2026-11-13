package burp.curl;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class CurlSettingsTest {
    static String raw(BuiltRequest r) {
        return new String(r.raw(), StandardCharsets.ISO_8859_1);
    }

    static boolean hasUserAgentNote(BuiltRequest r) {
        return r.warnings().stream().anyMatch(w -> w.message().startsWith("User-Agent"));
    }

    static final String CHROME = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) "
            + "Chrome/156.0.0.0 Safari/537.36";
    static final CurlSettings BROWSER = new CurlSettings(CHROME, "User-Agent set to a browser value (test)");

    static boolean hasNote(BuiltRequest r) {
        return r.warnings().stream().anyMatch(w -> w.message().equals("User-Agent set to a browser value (test)"));
    }

    @Test
    void withoutSettingsTheCurlValueIsUsedAndNoNoteIsAdded() throws Exception {
        BuiltRequest r = Curl.parse("curl https://t.example/").build(FileAccess.DENY).get(0);
        assertTrue(raw(r).contains("\r\nUser-Agent: curl/8.7.1\r\n"));
        assertEquals("curl/8.7.1", CurlSettings.DEFAULT_USER_AGENT);
        assertFalse(hasUserAgentNote(r));
        assertEquals(raw(r), raw(Curl.parse("curl https://t.example/").build(FileAccess.DENY, CurlSettings.DEFAULTS).get(0)));
    }

    @Test
    void theInjectedValueChangesTheRequestAndAddsTheNote() throws Exception {
        BuiltRequest r = Curl.parse("curl https://t.example/").build(FileAccess.DENY, BROWSER).get(0);
        assertTrue(raw(r).contains("\r\nUser-Agent: " + CHROME + "\r\nAccept: */*\r\n"), raw(r));
        assertEquals(1, r.warnings().stream().filter(w -> w.message().startsWith("User-Agent")).count());
        assertTrue(hasNote(r));
        assertEquals(Warning.Severity.NOTE, r.warnings().stream().filter(w -> w.message().startsWith("User-Agent"))
                .findFirst().get().severity());
    }

    @Test
    void nothingChangesWhenTheCommandSetsOrRemovesTheUserAgent() throws Exception {
        for (String cmd : new String[] {"curl -A mine https://t.example/", "curl -H 'User-Agent: mine' https://t.example/",
                "curl -H 'user-agent: mine' https://t.example/", "curl -A '' https://t.example/",
                "curl -H 'User-Agent:' https://t.example/"}) {
            BuiltRequest withBrowser = Curl.parse(cmd).build(FileAccess.DENY, BROWSER).get(0);
            BuiltRequest plain = Curl.parse(cmd).build(FileAccess.DENY).get(0);
            assertEquals(raw(plain), raw(withBrowser), cmd);
            assertFalse(hasNote(withBrowser), cmd);
            assertFalse(raw(withBrowser).contains("Chrome/"), cmd);
        }
    }

    @Test
    void everyRequestWithoutAUserAgentGetsTheNote() throws Exception {
        List<BuiltRequest> rs = Curl.parse("curl https://a.example/ https://b.example/ --next -A x https://c.example/")
                .build(FileAccess.DENY, BROWSER);
        assertEquals(3, rs.size());
        assertTrue(hasNote(rs.get(0)));
        assertTrue(hasNote(rs.get(1)));
        assertFalse(hasNote(rs.get(2)));
    }

    @Test
    void anUnusableValueFallsBackToTheCurlValueWithoutANote() throws Exception {
        for (String bad : new String[] {"x\r\nEvil: 1", "", null, "caf\u00e9"}) {
            BuiltRequest r = Curl.parse("curl https://t.example/").build(FileAccess.DENY, new CurlSettings(bad, "n")).get(0);
            assertTrue(raw(r).contains("\r\nUser-Agent: curl/8.7.1\r\n"));
            assertFalse(raw(r).contains("Evil"));
            assertTrue(r.warnings().stream().noneMatch(w -> w.message().equals("n")));
        }
    }

    @Test
    void aNullSettingsObjectMeansTheDefaults() throws Exception {
        BuiltRequest r = Curl.parse("curl https://t.example/").build(FileAccess.DENY, null).get(0);
        assertTrue(raw(r).contains("User-Agent: curl/8.7.1"));
    }
}
