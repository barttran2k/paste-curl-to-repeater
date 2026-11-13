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
        return r.warnings().stream().anyMatch(w -> w.message().startsWith("User-Agent curl/"));
    }

    @Test
    void withoutSettingsTheBuiltInDefaultIsUsedAndNoNoteIsAdded() throws Exception {
        BuiltRequest r = Curl.parse("curl https://t.example/").build(FileAccess.DENY).get(0);
        assertTrue(raw(r).contains("\r\nUser-Agent: curl/8.7.1\r\n"));
        assertEquals("8.7.1", CurlSettings.DEFAULT_CURL_VERSION);
        assertFalse(hasUserAgentNote(r));
        assertEquals(raw(r), raw(Curl.parse("curl https://t.example/").build(FileAccess.DENY, CurlSettings.DEFAULTS).get(0)));
    }

    @Test
    void theInjectedVersionChangesTheRequestAndAddsANote() throws Exception {
        CurlSettings s = new CurlSettings("8.12.0-DEV", "version of the curl found at /usr/bin/curl");
        BuiltRequest r = Curl.parse("curl https://t.example/").build(FileAccess.DENY, s).get(0);
        assertTrue(raw(r).contains("\r\nUser-Agent: curl/8.12.0-DEV\r\n"), raw(r));
        List<Warning> notes = r.warnings().stream().filter(w -> w.message().startsWith("User-Agent")).toList();
        assertEquals(1, notes.size());
        assertEquals(Warning.Severity.NOTE, notes.get(0).severity());
        assertEquals("User-Agent curl/8.12.0-DEV: version of the curl found at /usr/bin/curl", notes.get(0).message());
    }

    @Test
    void theBuiltInReasonIsShown() throws Exception {
        CurlSettings s = new CurlSettings(CurlSettings.DEFAULT_CURL_VERSION, "built-in default, no curl binary was found");
        BuiltRequest r = Curl.parse("curl https://t.example/").build(FileAccess.DENY, s).get(0);
        assertTrue(r.warnings().stream().anyMatch(w -> w.message()
                .equals("User-Agent curl/8.7.1: built-in default, no curl binary was found")));
    }

    @Test
    void noNoteAndNoDefaultWhenTheUserAgentIsSetExplicitly() throws Exception {
        CurlSettings s = new CurlSettings("9.9.9", "src");
        for (String cmd : new String[] {"curl -A mine https://t.example/", "curl -H 'User-Agent: mine' https://t.example/",
                "curl -H 'user-agent: mine' https://t.example/", "curl -A '' https://t.example/",
                "curl -H 'User-Agent:' https://t.example/"}) {
            BuiltRequest r = Curl.parse(cmd).build(FileAccess.DENY, s).get(0);
            assertFalse(hasUserAgentNote(r), cmd);
            assertFalse(raw(r).contains("curl/9.9.9"), cmd);
            assertFalse(raw(r).contains("curl/8.7.1"), cmd);
        }
    }

    @Test
    void everyRequestOfACommandGetsTheNote() throws Exception {
        CurlSettings s = new CurlSettings("9.9.9", "src");
        List<BuiltRequest> rs = Curl.parse("curl https://a.example/ https://b.example/ --next -A x https://c.example/")
                .build(FileAccess.DENY, s);
        assertEquals(3, rs.size());
        assertTrue(hasUserAgentNote(rs.get(0)));
        assertTrue(hasUserAgentNote(rs.get(1)));
        assertFalse(hasUserAgentNote(rs.get(2)));
    }

    @Test
    void anUnusableVersionFallsBackToTheBuiltInDefault() throws Exception {
        CurlSettings s = new CurlSettings("8.7.1\r\nEvil: 1", "src");
        BuiltRequest r = Curl.parse("curl https://t.example/").build(FileAccess.DENY, s).get(0);
        assertTrue(raw(r).contains("\r\nUser-Agent: curl/8.7.1\r\n"));
        assertFalse(raw(r).contains("Evil"));
        assertTrue(r.warnings().stream().anyMatch(w -> w.message().startsWith("User-Agent curl/8.7.1: built-in default")));
    }

    @Test
    void aNullSettingsObjectMeansTheDefaults() throws Exception {
        BuiltRequest r = Curl.parse("curl https://t.example/").build(FileAccess.DENY, null).get(0);
        assertTrue(raw(r).contains("User-Agent: curl/8.7.1"));
    }
}
