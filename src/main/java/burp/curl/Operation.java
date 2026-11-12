package burp.curl;

import java.util.ArrayList;
import java.util.List;

/**
 * Everything one curl "operation" (the options between two {@code --next}) asks for. Filled by
 * {@link CurlCommandParser}, consumed by {@link CurlRequestBuilder}. It holds no file contents: files are only
 * named here and read at build time through {@link FileAccess}.
 *
 * <p>Strings that curl sends as they are (headers, cookies, user, URL, ...) are wire texts, see {@link ByteText}; file
 * paths are plain text.
 *
 * <p>Fields are package-private and mutable on purpose: adding an option means one field here, one case in
 * {@code CurlCommandParser.apply} and one use in {@code CurlRequestBuilder}.
 */
public final class Operation {

    /** Where the {@code @-} data of one shell command comes from (heredoc bytes or {@code < file}). */
    static final class StdinSource {
        final byte[] bytes;
        final String file;

        StdinSource(byte[] bytes, String file) {
            this.bytes = bytes;
            this.file = file;
        }
    }

    /** One body piece given by a data option. */
    static final class DataPiece {
        /** How the option treats its argument. */
        enum Kind {
            /** {@code -d}, {@code --data}, {@code --data-ascii}: {@code @file} loses CR and LF. */
            ASCII,
            /** {@code --data-binary}. */
            BINARY,
            /** {@code --data-raw}: never a file. */
            RAW,
            /** {@code --data-urlencode}. */
            URLENCODE,
            /** {@code --json}: like binary, but joined without {@code &}. */
            JSON
        }

        final Kind kind;
        /** literal bytes (the whole data, or the content for URLENCODE); null when the data comes from a file */
        final byte[] literal;
        /** path as written ({@code -} means stdin); null for literal data */
        final String file;
        /** URLENCODE only: the name that is sent verbatim in front of {@code =}, or null */
        final byte[] name;

        DataPiece(Kind kind, byte[] literal, String file, byte[] name) {
            this.kind = kind;
            this.literal = literal;
            this.file = file;
            this.name = name;
        }
    }

    // ---- URL and method ----
    final List<String> urls = new ArrayList<>();
    String method;
    boolean head;
    boolean get;
    boolean globoff;
    boolean pathAsIs;
    boolean http10;

    // ---- headers ----
    /** custom {@code -H} lines exactly as typed */
    final List<String> headers = new ArrayList<>();
    String userAgent;
    String referer;
    final List<String> cookies = new ArrayList<>();
    String user;
    String bearer;
    /**
     * The authentication methods curl is asked for, as curl's {@code CURLOPT_HTTPAUTH} bit mask (0 = never set,
     * which means Basic). {@code -u}/URL credentials and {@code --oauth2-bearer} are sent on the first request only
     * when the mask selects exactly that one method (Basic: 0 or {@link #AUTH_BASIC}); with several methods curl
     * waits for a challenge, and Digest, NTLM and Negotiate need one. Measured with curl 8.7.1.
     */
    int authMask;
    /** the authentication options given, for messages */
    final java.util.Set<String> authOptions = new java.util.LinkedHashSet<>();
    static final int AUTH_BASIC = 1;
    static final int AUTH_DIGEST = 2;
    static final int AUTH_NTLM = 4;
    static final int AUTH_NEGOTIATE = 8;
    static final int AUTH_NTLM_WB = 16;
    static final int AUTH_BEARER = 32;
    static final int AUTH_ANY = 63;
    String range;
    boolean compressed;

    // ---- body ----
    final List<DataPiece> data = new ArrayList<>();
    boolean json;

    // ---- forms, uploads, queries ----
    /** one entry per {@code -F} / {@code --form-string}, in order */
    final List<FormField> forms = new ArrayList<>();
    boolean formEscape;
    /** the {@code -T} paths in order ({@code -} is stdin); the i-th one belongs to the i-th URL */
    final List<String> uploads = new ArrayList<>();
    /** the {@code --url-query} arguments in order */
    final List<UrlQuery> urlQueries = new ArrayList<>();

    // ---- misc ----
    /** {@code -z} argument exactly as given (leading {@code + - =} included), or null */
    String timeCond;
    boolean trEncoding;
    boolean crlf;
    boolean disallowUsernameInUrl;
    String requestTarget;
    String protoDefault;
    /** {@code -b} arguments that name a cookie file */
    final List<String> cookieFiles = new ArrayList<>();
    /** {@code -j}: session cookies read from a cookie file are dropped */
    boolean junkSessionCookies;
    /** warnings that depend on file contents (variable files); added to every request built from this operation */
    final List<Warning> lateWarnings = new ArrayList<>();

    StdinSource stdin;

    /** One {@code --url-query} argument. */
    static final class UrlQuery {
        /** {@code +} prefix: the text is appended without encoding */
        final boolean raw;
        /** literal content (after the optional {@code name=}); null when it comes from a file */
        final byte[] literal;
        /** file path ({@code -} is stdin) or null */
        final String file;
        /** the name sent in front of {@code =} (encoded), or null */
        final byte[] name;

        UrlQuery(boolean raw, byte[] literal, String file, byte[] name) {
            this.raw = raw;
            this.literal = literal;
            this.file = file;
            this.name = name;
        }
    }

    /** Adds every local path this operation makes the builder read (stdin redirect included) to {@code refs}. */
    void collectFileRefs(java.util.Set<String> refs) {
        boolean stdinUsed = false;
        for (DataPiece p : data) {
            if (p.file == null) {
                continue;
            }
            if (p.file.equals("-")) {
                stdinUsed = true;
            } else if (!p.file.isEmpty()) {
                refs.add(p.file);
            }
        }
        for (UrlQuery q : urlQueries) {
            if (q.file != null) {
                if (q.file.equals("-")) {
                    stdinUsed = true;
                } else if (!q.file.isEmpty()) {
                    refs.add(q.file);
                }
            }
        }
        for (FormField f : forms) {
            for (String path : f.filePaths()) {
                if (path.equals("-")) {
                    stdinUsed = true;
                } else if (!path.isEmpty()) {
                    refs.add(path);
                }
            }
        }
        for (String u : uploads) {
            if (u.equals("-")) {
                stdinUsed = true;
            } else if (!u.isEmpty()) {
                refs.add(u);
            }
        }
        for (String h : headers) {
            if (h.startsWith("@")) {
                if (h.equals("@-")) {
                    stdinUsed = true;
                } else if (h.length() > 1) {
                    refs.add(h.substring(1));
                }
            }
        }
        for (String c : cookieFiles) {
            if (!c.isEmpty()) {
                refs.add(c);
            }
        }
        if (stdinUsed && stdin != null && stdin.bytes == null && stdin.file != null && !stdin.file.isEmpty()) {
            refs.add(stdin.file);
        }
    }

    /** @return the URLs given to this operation, in order */
    public List<String> urls() {
        return List.copyOf(urls);
    }

    /** @return the custom header lines ({@code -H}) exactly as typed, in order */
    public List<String> headers() {
        return List.copyOf(headers);
    }

    /** @return the {@code -X} method, or null */
    public String method() {
        return method;
    }
}
