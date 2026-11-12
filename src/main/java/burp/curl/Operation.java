package burp.curl;

import java.util.ArrayList;
import java.util.List;

/**
 * Everything one curl "operation" (the options between two {@code --next}) asks for. Filled by
 * {@link CurlCommandParser}, consumed by {@link CurlRequestBuilder}. It holds no file contents: files are only
 * named here and read at build time through {@link FileAccess}.
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
    boolean basic;
    String range;
    boolean compressed;

    // ---- body ----
    final List<DataPiece> data = new ArrayList<>();
    boolean json;

    StdinSource stdin;

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
