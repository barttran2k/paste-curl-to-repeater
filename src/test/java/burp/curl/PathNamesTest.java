package burp.curl;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** File names cut from local paths: -F follows curl.exe for Windows paths and libcurl for POSIX ones; -T cuts at both. */
class PathNamesTest {
    private static String multipart(String arg) throws Exception {
        FileAccess files = path -> "data".getBytes(StandardCharsets.UTF_8);
        BuiltRequest r = Curl.parse("curl -F '" + arg + "' http://h.test/").build(files).get(0);
        return new String(r.raw(), StandardCharsets.UTF_8);
    }

    @Test
    void recognisesWindowsPaths() {
        for (String p : new String[] {"C:\\Users\\me\\a.png", "c:/Users/me/a.png", "D:\\a.png", "\\\\server\\share\\a.png",
            "C:/a.png"}) {
            assertTrue(PathNames.isWindowsPath(p), p);
        }
        for (String p : new String[] {"a\\b.png", "dir\\sub/x.txt", "/abs/a.png", "C:a.png", "C:", "\\\\", "\\\\server",
            "1:\\a", "~\\a", "a:b\\c"}) {
            assertFalse(PathNames.isWindowsPath(p), p);
        }
    }

    @Test
    void windowsUploadPathsLoseTheirDirectoryInTheMultipartFilename() throws Exception {
        for (Map.Entry<String, String> e : Map.of("f=@C:\\Users\\me\\a.png", "a.png", "f=@c:/Users/me/b.png", "b.png",
                "f=@C:\\Users/me\\c.png", "c.png", "f=@\\\\srv\\share\\dir\\d.png", "d.png",
                "f=@\\\\srv\\share\\e.png;type=text/plain", "e.png").entrySet()) {
            String raw = multipart(e.getKey());
            assertTrue(raw.contains("filename=\"" + e.getValue() + "\""), e.getKey() + "\n" + raw);
        }
        // the content type is guessed from the name, not from the directory
        assertTrue(multipart("f=@C:\\Users\\me\\a.png").contains("Content-Type: image/png"));
    }

    @Test
    void posixPathsKeepBackslashesLikeRealCurl() throws Exception {
        assertTrue(multipart("f=@a\\b.png").contains("filename=\"a\\b.png\""));
        assertTrue(multipart("f=@dir\\sub/x.txt").contains("filename=\"x.txt\""));
        assertTrue(multipart("f=@/tmp/a\\b/c.txt").contains("filename=\"c.txt\""));
        assertTrue(multipart("f=@C:a.png").contains("filename=\"C:a.png\""));
    }

    @Test
    void windowsFilenameOptionStillWins() throws Exception {
        assertTrue(multipart("f=@C:\\x\\a.png;filename=z.txt").contains("filename=\"z.txt\""));
    }

    @Test
    void uploadFileCutsAtBothSeparators() throws Exception {
        FileAccess files = path -> "data".getBytes(StandardCharsets.UTF_8);
        for (String path : new String[] {"C:\\Users\\me\\a.txt", "a\\a.txt", "dir/a\\a.txt", "/x/y/a.txt"}) {
            BuiltRequest r = Curl.parse("curl -T '" + path + "' http://h.test/up/").build(files).get(0);
            assertTrue(new String(r.raw(), StandardCharsets.ISO_8859_1).startsWith("PUT /up/a.txt HTTP/1.1"), path);
        }
    }
}
