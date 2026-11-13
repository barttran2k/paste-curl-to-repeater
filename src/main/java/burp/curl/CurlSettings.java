package burp.curl;

import java.util.regex.Pattern;

/**
 * Settings the caller injects into request building; nothing here is read from the machine by the core.
 *
 * @param curlVersion the version that appears in the default {@code User-Agent: curl/<version>}
 * @param versionSource why that version was chosen (shown as a note on requests that got the default User-Agent),
 *                      or null for no note
 */
public record CurlSettings(String curlVersion, String versionSource) {
    /** What a version looks like: {@code 8.7.1}, {@code 8.12.0-DEV}, {@code 7.81.0}. */
    private static final Pattern VERSION = Pattern.compile("\\d+\\.\\d+(\\.\\d+)?([-+~.][A-Za-z0-9._+~-]{0,30})?");

    /** The built-in default curl version; the only place it is defined. */
    public static final String DEFAULT_CURL_VERSION = "8.7.1";

    /** Built-in default, no note. This is what callers that set nothing get. */
    public static final CurlSettings DEFAULTS = new CurlSettings(DEFAULT_CURL_VERSION, null);

    /** Normalises: an unusable version (empty, odd characters) becomes the built-in default. */
    public CurlSettings {
        if (curlVersion == null || !VERSION.matcher(curlVersion).matches()) {
            curlVersion = DEFAULT_CURL_VERSION;
            versionSource = versionSource == null ? null : "built-in default, the detected version was unusable";
        }
    }

    /** @param version a version string as {@code curl --version} prints it @return true if it is usable */
    public static boolean isUsableVersion(String version) {
        return version != null && VERSION.matcher(version).matches();
    }

    /** @return the value of the default User-Agent header */
    public String defaultUserAgent() {
        return "curl/" + curlVersion;
    }
}
