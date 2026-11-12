package burp.curl;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * Which Authorization header a mix of authentication options sends. The Basic/Bearer/nothing cases are compared with
 * real curl byte for byte in the differential corpus ({@code extended/auth-*.curl}). The single-method NTLM cases are
 * unit tests only: real curl 8.7.1 sends the NTLM type-1 message there
 * ({@code Authorization: NTLM TlRMTVNTUAABAAAABoIIAAAAAAAAAAAAAAAAAAAAAAA=}), a token that is deliberately not
 * reproduced; we send no Authorization header and warn.
 */
class AuthCombinationTest {
    private static RequestDetails build(String args) throws CurlParseException {
        return Curl.parseAndBuild("curl http://h.test/ " + args, null).get(0);
    }

    private static String wire(String args) throws CurlParseException {
        return new String(build(args).request().raw(), StandardCharsets.ISO_8859_1);
    }

    private static List<String> messages(String args) throws CurlParseException {
        return build(args).request().warnings().stream().map(Warning::message).toList();
    }

    @Test
    void ntlmAloneSendsNoHeaderAndWarns() throws Exception {
        for (String o : List.of("--ntlm", "--negotiate")) {
            assertFalse(wire("-u user:pw " + o).contains("Authorization"), o);
            assertTrue(Curl.parse("curl http://h.test/ -u user:pw " + o).warnings().stream()
                    .anyMatch(m -> m.severity() == Warning.Severity.LOSSY && m.message().startsWith(o + ":")), o);
            // credentials in the URL, and a custom header which is still sent
            assertFalse(wire(o).contains("Authorization"));
        }
        String w = wire("-u user:pw --ntlm -H 'Authorization: X'");
        assertEquals(1, w.split("Authorization:", -1).length - 1, w);
        assertTrue(w.contains("Authorization: X\r\n"));
    }

    @Test
    void ntlmWithBasicHasNoHeaderEither() throws Exception {
        assertFalse(wire("-u user:pw --ntlm --basic").contains("Authorization"));
    }

    @Test
    void basicIsSentWhenTheHandshakeIsTakenBack() throws Exception {
        assertTrue(wire("-u user:pw --digest --no-digest").contains("Authorization: Basic dXNlcjpwdw==\r\n"));
        assertTrue(wire("-u user:pw --ntlm --no-ntlm").contains("Authorization: Basic "));
        assertFalse(wire("-u user:pw --anyauth --no-anyauth").contains("Authorization"));
    }

    @Test
    void digestWithCredentialsSaysSoAndSendsNoBasic() throws Exception {
        String w = wire("-u user:pw --digest");
        assertFalse(w.contains("Authorization"), w);
        List<String> m = messages("-u user:pw --digest");
        assertTrue(m.stream().anyMatch(x -> x.contains("--digest") && x.contains("not sent as Basic")), m.toString());
        assertFalse(m.stream().anyMatch(x -> x.contains("no Authorization header is added")), m.toString());
    }

    @Test
    void noWarningClaimsMissingHeaderWhenACustomOneIsSent() throws Exception {
        String w = wire("-u user:pw --digest -H 'Authorization: X'");
        assertTrue(w.contains("Authorization: X\r\n"), w);
        for (String m : messages("-u user:pw --digest -H 'Authorization: X'")) {
            assertFalse(m.contains("no Authorization header is added"), m);
            assertFalse(m.contains("not sent as Basic"), m); // nothing was suppressed: the custom header wins anyway
        }
    }

    @Test
    void bearerNeedsToBeTheOnlyMethod() throws Exception {
        assertTrue(wire("--oauth2-bearer tok --basic --no-basic").contains("Authorization: Bearer tok\r\n"));
        assertFalse(wire("--oauth2-bearer tok --digest").contains("Authorization"));
        assertFalse(wire("--oauth2-bearer tok --basic").contains("Authorization"));
    }
}
