package burp.curl;

import java.util.List;

/**
 * One finished HTTP request ready for Burp.
 * @param host target host
 * @param port target port
 * @param secure true for TLS
 * @param raw complete HTTP/1.x request bytes (request line, headers with CRLF, blank line, body)
 * @param method HTTP method
 * @param url the full URL
 * @param warnings warnings raised while building this request
 */
public record BuiltRequest(String host, int port, boolean secure, byte[] raw, String method, String url,
                           List<Warning> warnings) {
    /** Canonical constructor; copies raw and warnings (null warnings become empty). */
    public BuiltRequest {
        raw = raw == null ? new byte[0] : raw.clone();
        warnings = warnings == null ? List.of() : List.copyOf(warnings);
    }

    /** @return a copy of the raw request bytes */
    @Override
    public byte[] raw() {
        return raw.clone();
    }
}
