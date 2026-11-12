package burp.curl;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import org.junit.jupiter.api.Test;

/** The lossy warnings of options that change how curl sends a request but not what it sends. */
class OptionWarningsTest {
    private static final String BURP_TLS = "Settings → Network → TLS → Client TLS certificates";
    private static final String BURP_CONN = "Settings → Network → Connections";

    private static List<String> lossy(String options) throws CurlParseException {
        return Curl.parse("curl " + options + " http://h.test/").warnings().stream()
                .filter(w -> w.severity() == Warning.Severity.LOSSY).map(Warning::message).toList();
    }

    private static String only(String options) throws CurlParseException {
        List<String> l = lossy(options);
        assertEquals(1, l.size(), l.toString());
        assertFalse(l.get(0).contains("\n"));
        return l.get(0);
    }

    @Test
    void proxyFamilyKeepsTheContentAndPointsToBurpUpstreamProxy() throws Exception {
        for (String o : List.of("-x http://u:secret@p.test:3128", "--proxy http://p.test:3128", "--preproxy socks5://p.test",
                "--socks5 p.test:1080", "--socks4 p.test:1080", "--socks4a p.test:1080", "--socks5-hostname p.test:1080")) {
            String m = only(o);
            assertTrue(m.contains("request content is unchanged"), m);
            assertTrue(m.contains("upstream proxy in Burp"), m);
            assertFalse(m.contains("secret"), m);
            assertFalse(m.contains("p.test"), m);
        }
        assertTrue(only("-x http://p.test").startsWith("--proxy:"));
        assertTrue(only("--preproxy socks5://p.test").startsWith("--preproxy:"));
        assertTrue(only("--socks5-hostname p.test:1080").startsWith("--socks5-hostname:"));
    }

    @Test
    void resolveAndConnectToNameTheirArgument() throws Exception {
        String m = only("--resolve h.test:80:10.0.0.1");
        assertTrue(m.startsWith("--resolve h.test:80:10.0.0.1"), m);
        assertTrue(m.contains("connect to a different address") && m.contains(BURP_CONN), m);
        m = only("--connect-to h.test:80:other.test:8080");
        assertTrue(m.startsWith("--connect-to h.test:80:other.test:8080"), m);
        assertTrue(m.contains("connect to a different address") && m.contains(BURP_CONN), m);
    }

    @Test
    void unixSockets() throws Exception {
        assertTrue(only("--unix-socket /tmp/s").contains("Burp cannot connect to a Unix socket"));
        assertTrue(only("--abstract-unix-socket name").contains("Burp cannot connect to a Unix socket"));
    }

    @Test
    void clientCertificates() throws Exception {
        for (String o : List.of("-E cert.pem:pw", "--cert cert.pem", "--key key.pem")) {
            String m = only(o);
            assertTrue(m.contains("client TLS certificate") && m.contains(BURP_TLS), m);
            assertFalse(m.contains("pw") || m.contains("pem"), m);
        }
    }

    @Test
    void authenticationHandshakes() throws Exception {
        for (String o : List.of("--digest", "--ntlm", "--ntlm-wb", "--negotiate", "--anyauth")) {
            String m = only(o + " -u a:topsecret");
            assertTrue(m.startsWith(o + ":"), m);
            assertTrue(m.contains("not precomputed") && m.contains("itself adds no Authorization header")
                    && m.contains("platform authentication in Burp"), m);
            assertFalse(m.contains("topsecret"), m);
        }
    }

    @Test
    void awsConfigNetrc() throws Exception {
        assertTrue(only("--aws-sigv4 aws:amz:r:s -u a:b").contains("AWS signature headers are not computed"));
        assertTrue(only("-K c.conf").contains("config file is not read") && only("--config c.conf").startsWith("--config:"));
        for (String o : List.of("-n", "--netrc", "--netrc-optional", "--netrc-file f")) {
            assertTrue(only(o).contains("credentials from .netrc are not read"), o);
        }
    }

    @Test
    void otherGroupBOptionsGetAGenericSentenceThatNamesThem() throws Exception {
        for (String o : List.of("-C 10", "--etag-compare e.txt", "--haproxy-protocol", "--upload-flags x",
                "--httpsig-key k", "--delegation always", "--service-name s")) {
            String name = "--" + CurlOptionTable.get().resolveLong(
                    o.startsWith("-C") ? "continue-at" : o.split(" ")[0].substring(2)).get().spec().longName();
            String m = only(o);
            assertTrue(m.startsWith(name + " "), m);
            assertTrue(m.contains("not reproduced"), m);
        }
    }
}
