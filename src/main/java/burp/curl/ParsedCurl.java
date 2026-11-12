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
    List<BuiltRequest> build(FileAccess files) throws CurlParseException;
}
