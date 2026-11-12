package burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpHeader;
import burp.curl.Curl;
import burp.curl.CurlParseException;
import burp.curl.FileAccess;
import burp.curl.RequestDetails;
import burp.curl.Warning;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * Legacy facade over the {@code burp.curl} core: parses a pasted cURL command into the first request it
 * describes.
 *
 * @author August Detlefsen
 */
public class CurlParser {

    /**
     * @param curlCommand the pasted text
     * @return the first request, or null when the text cannot be parsed
     */
    public static CurlRequest parseCurlCommand(String curlCommand) {
        return parseCurlCommand(curlCommand, null);
    }

    /**
     * @param curlCommand the pasted text
     * @param api Burp API used for error and warning logging, may be null
     * @return the first request, or null when the text cannot be parsed
     */
    public static CurlRequest parseCurlCommand(String curlCommand, MontoyaApi api) {
        try {
            // local files are never read through this facade; @file data becomes a visible placeholder
            List<RequestDetails> all = Curl.parseAndBuild(curlCommand, FileAccess.DENY);
            RequestDetails d = all.get(0);
            if (api != null) {
                for (Warning w : d.request().warnings()) {
                    api.logging().logToOutput("curl warning: " + w.message());
                }
            }
            List<HttpHeader> headers = new ArrayList<>();
            for (String h : d.typedHeaders()) {
                int colon = h.indexOf(':');
                if (colon > 0) {
                    headers.add(new HttpHeaderImpl(h.substring(0, colon).trim(), h.substring(colon + 1).trim()));
                }
            }
            return new CurlRequest(d.request().method(), d.scheme(), d.host(), d.path(), d.query(),
                    d.explicitPort(), headers, new String(d.body(), StandardCharsets.UTF_8));
        } catch (CurlParseException e) {
            if (api != null) {
                api.logging().logToError("Could not parse the cURL command: " + e.getMessage());
            }
            return null;
        }
    }

    static class CurlRequest {
        private final String method;
        private final String protocol;
        private final String host;
        private final String path;
        private final String query;
        private final Integer port;
        private final List<HttpHeader> headers;
        private final String body;

        public CurlRequest(String method, String protocol, String host, String path, String query, Integer port, List<HttpHeader> headers, String body) {
            this.method = method;
            this.protocol = protocol;
            this.host = host;
            this.path = path;
            this.query = query;
            this.port = port;
            this.headers = headers;
            this.body = body;
        }

        public String getBaseUrl() {
            StringBuilder builder = new StringBuilder();
            builder.append(getProtocol())
                   .append("://");
            String h = getHost();
            builder.append(h.indexOf(':') >= 0 ? "[" + h + "]" : h);

            if (port != null && port != -1 && !isDefaultPort()) builder.append(":").append(getPort());

            builder.append(getPath());

            if (query != null && !"".equals(query)) builder.append("?").append(query);

            return builder.toString();
        }

        private boolean isDefaultPort() {
            return ("http".equalsIgnoreCase(protocol) && port == 80)
                    || ("https".equalsIgnoreCase(protocol) && port == 443);
        }

        public String getMethod() {
            return method;
        }
        public String getProtocol() {
            return protocol;
        }
        public String getHost() {
            return host;
        }

        public String getPath() {
            if (path == null || "".equals(path)) return "/";

            return path;
        }

        public String getQuery() {
            return query;
        }

        public Integer getPort() {
            return port;
        }

        public List<HttpHeader> getHeaders() {
            return headers;
        }

        public String getBody() {
            return body;
        }
    }
}
