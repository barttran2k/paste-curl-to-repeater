package burp.curl;

/**
 * Settings the caller injects into request building; nothing here is read from the machine by the core.
 *
 * @param defaultUserAgent the value of the {@code User-Agent} header of a request whose command sets none
 *                         (printable ASCII only; anything else is replaced by {@link #DEFAULT_USER_AGENT})
 * @param note a note added to every request that received that default, or null for none
 */
public record CurlSettings(String defaultUserAgent, String note) {
    /** What curl 8.7.1 sends; the only place this value is defined. */
    public static final String DEFAULT_USER_AGENT = "curl/8.7.1";

    /** The curl value, no note. This is what callers that set nothing get. */
    public static final CurlSettings DEFAULTS = new CurlSettings(DEFAULT_USER_AGENT, null);

    /** Normalises: an unusable value (null, empty, control or non-ASCII characters) becomes the curl value. */
    public CurlSettings {
        if (!isUsableUserAgent(defaultUserAgent)) {
            defaultUserAgent = DEFAULT_USER_AGENT;
            note = null;
        }
    }

    /** @param ua a candidate value @return true if it can be written into a header line as is */
    public static boolean isUsableUserAgent(String ua) {
        if (ua == null || ua.isBlank() || ua.length() > 512) {
            return false;
        }
        for (int i = 0; i < ua.length(); i++) {
            char c = ua.charAt(i);
            if (c < 0x20 || c > 0x7e) {
                return false;
            }
        }
        return true;
    }
}
