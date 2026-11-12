package burp.curl;

import java.util.List;

/**
 * A built request together with the parts a caller (the legacy {@code burp.CurlParser} facade) needs without
 * re-parsing the raw bytes.
 *
 * @param request the finished request
 * @param scheme "http" or "https"
 * @param host host for connecting (IPv6 without brackets)
 * @param explicitPort the port when it differs from the scheme default, else -1
 * @param path request path, always starting with "/"
 * @param query query without "?", or null
 * @param typedHeaders the {@code -H} headers exactly as the user typed them, in order (not the ones curl adds)
 * @param body the body content as curl was given it: after {@code -d}/{@code -F}/{@code -T} processing but before
 *             {@code --crlf} conversion and chunk encoding (the raw request carries the bytes as sent), empty when the
 *             request has no body
 */
public record RequestDetails(BuiltRequest request, String scheme, String host, int explicitPort, String path,
                             String query, List<String> typedHeaders, byte[] body) {
    /** Canonical constructor; copies the mutable members. */
    public RequestDetails {
        typedHeaders = typedHeaders == null ? List.of() : List.copyOf(typedHeaders);
        body = body == null ? new byte[0] : body.clone();
    }

    /** @return a copy of the body bytes */
    @Override
    public byte[] body() {
        return body.clone();
    }
}
