package burp.curl;

import java.io.IOException;

/** Source of local file contents for options like -d @file. */
public interface FileAccess {
    /**
     * @param path the path as written in the curl command
     * @return the file bytes
     * @throws IOException if the file cannot be read
     */
    byte[] read(String path) throws IOException;

    /** Implementation that refuses every read with an IOException. */
    FileAccess DENY = path -> {
        throw new IOException("file access denied: " + path);
    };
}
