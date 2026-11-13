package burp.curl;

import java.util.List;

/** Result of parsing a pasted text, before any file is read. */
public interface ParsedCurl {
    /** @return local paths the command wants to read, in order, de-duplicated */
    List<String> fileRefs();

    /** @return tokenizer and parser warnings */
    List<Warning> warnings();

    /**
     * @param files access to local files
     * @return the finished requests
     * @throws CurlParseException if a request cannot be built
     */
    default List<BuiltRequest> build(FileAccess files) throws CurlParseException {
        return build(files, CurlSettings.DEFAULTS);
    }

    /**
     * @param files access to local files
     * @param settings injected settings (the default User-Agent)
     * @return the finished requests
     * @throws CurlParseException if a request cannot be built
     */
    List<BuiltRequest> build(FileAccess files, CurlSettings settings) throws CurlParseException;
}
