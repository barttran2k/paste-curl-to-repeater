package burp.curl;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;

class MultipartBuilderTest {
    private static final String B = "------------------------6t0bjXIpSIzCVlnmQhwnyY";

    private static FileAccess files(Map<String, String> m) {
        return path -> {
            String v = m.get(path);
            if (v == null) {
                throw new IOException("no such file: " + path);
            }
            return v.getBytes(StandardCharsets.UTF_8);
        };
    }

    private static String body(MultipartBuilder b) {
        return new String(b.build(), StandardCharsets.UTF_8);
    }

    private static MultipartBuilder add(MultipartBuilder b, FileAccess fa, String... specs) throws Exception {
        for (String s : specs) {
            b.add(FormField.parse(s), fa);
        }
        return b;
    }

    @Test
    void briefCapturedBody() throws Exception {
        Map<String, String> fs = new HashMap<>();
        fs.put("files/body.txt", "BODY");
        fs.put("files/data.json", "{\"k\":\"v\"}");
        MultipartBuilder b = new MultipartBuilder(B);
        add(b, files(fs), "name=John \"Q\" Doe", "file=@files/body.txt;type=text/plain", "x=<files/data.json",
                "j=@files/data.json;filename=renamed.json");
        b.add(FormField.parseString("raw=@notfile;type=x"), FileAccess.DENY);
        String d = "--" + B + "\r\n";
        String expected = d + "Content-Disposition: form-data; name=\"name\"\r\n\r\nJohn \"Q\" Doe\r\n"
                + d + "Content-Disposition: form-data; name=\"file\"; filename=\"body.txt\"\r\nContent-Type: text/plain\r\n\r\nBODY\r\n"
                + d + "Content-Disposition: form-data; name=\"x\"\r\n\r\n{\"k\":\"v\"}\r\n"
                + d + "Content-Disposition: form-data; name=\"j\"; filename=\"renamed.json\"\r\nContent-Type: application/octet-stream\r\n\r\n{\"k\":\"v\"}\r\n"
                + d + "Content-Disposition: form-data; name=\"raw\"\r\n\r\n@notfile;type=x\r\n"
                + "--" + B + "--\r\n";
        assertEquals(expected, body(b));
        assertEquals("multipart/form-data; boundary=" + B, b.contentType());
        assertEquals(B, b.boundary());
    }

    @Test
    void randomBoundaryIsCurlStyle() {
        String bd = new MultipartBuilder().boundary();
        assertTrue(bd.matches("-{24}[A-Za-z0-9]{22}"), bd);
        assertTrue(!bd.equals(new MultipartBuilder().boundary()));
    }

    @Test
    void emptyBodyHasOnlyClosingDelimiter() {
        assertEquals("--b--\r\n", body(new MultipartBuilder("b")));
    }

    @Test
    void escapingDefaultAndFormEscape() throws Exception {
        FileAccess fa = files(Map.of("f", "x"));
        MultipartBuilder d = add(new MultipartBuilder("b"), fa, "a\"b\\c\r\ndé=v", "p=@f;filename=q\"r");
        assertTrue(body(d).contains("name=\"a%22b\\c%0D%0Adé\""), body(d));
        assertTrue(body(d).contains("filename=\"q%22r\""));
        MultipartBuilder e = add(new MultipartBuilder("b").formEscape(true), fa, "a\"b\\c\r\nd=v", "p=@f;filename=q\"r\\s");
        assertTrue(body(e).contains("name=\"a\\\"b\\\\c\r\nd\""), body(e));
        assertTrue(body(e).contains("filename=\"q\\\"r\\\\s\""));
    }

    @Test
    void emptyNameOmitsName() throws Exception {
        assertEquals("--b\r\nContent-Disposition: form-data\r\n\r\nv\r\n--b--\r\n",
                body(add(new MultipartBuilder("b"), FileAccess.DENY, "=v")));
    }

    @Test
    void userHeadersAndPrecedence() throws Exception {
        FileAccess fa = files(Map.of("hdr", "X-File: yes\r\n\r\nX-Two: 2\n", "f", "F"));
        assertEquals("--b\r\nContent-Disposition: form-data; name=\"a\"\r\nX-A: 1\r\nX-B: 2\r\n\r\nv\r\n--b--\r\n",
                body(add(new MultipartBuilder("b"), fa, "a=v;headers=X-A: 1;headers=X-B: 2")));
        assertEquals("--b\r\nContent-Disposition: form-data; name=\"a\"\r\nX-File: yes\r\nX-Two: 2\r\n\r\nv\r\n--b--\r\n",
                body(add(new MultipartBuilder("b"), fa, "a=v;headers=@hdr")));
        // explicit type= wins over a user Content-Type header; a user header replaces the guessed one
        assertEquals("--b\r\nContent-Disposition: form-data; name=\"a\"\r\nContent-Type: t/t\r\n\r\nv\r\n--b--\r\n",
                body(add(new MultipartBuilder("b"), fa, "a=v;type=t/t;headers=Content-Type: z/z")));
        assertEquals("--b\r\nContent-Disposition: form-data; name=\"a\"; filename=\"f\"\r\nContent-Type: z/z\r\n\r\nF\r\n--b--\r\n",
                body(add(new MultipartBuilder("b"), fa, "a=@f;headers=Content-Type: z/z")));
        assertEquals("--b\r\nContent-Disposition: attachment\r\n\r\nv\r\n--b--\r\n",
                body(add(new MultipartBuilder("b"), fa, "a=v;headers=Content-Disposition: attachment")));
    }

    @Test
    void contentTypeGuessing() throws Exception {
        assertEquals("image/png", MultipartBuilder.guessContentType("x.PNG"));
        assertEquals("text/html", MultipartBuilder.guessContentType("a.htm"));
        assertEquals("text/plain", MultipartBuilder.guessContentType(".txt"));
        assertEquals("application/octet-stream", MultipartBuilder.guessContentType("a.html.bak"));
        assertEquals("application/octet-stream", MultipartBuilder.guessContentType("noext"));
        assertEquals("image/svg+xml", MultipartBuilder.guessContentType("a.svg"));
        FileAccess fa = files(Map.of("d/a.txt", "A", "-", "S"));
        // filename= with a known extension drives the guess, otherwise the path does
        assertTrue(body(add(new MultipartBuilder("b"), fa, "a=@d/a.txt;filename=x.json")).contains("Content-Type: text/plain"));
        assertTrue(body(add(new MultipartBuilder("b"), fa, "a=@d/a.txt;filename=x.png")).contains("Content-Type: image/png"));
        // literal with filename: guess only when known; stdin upload without type: none
        assertTrue(body(add(new MultipartBuilder("b"), fa, "a=v;filename=x.png")).contains("Content-Type: image/png"));
        assertTrue(!body(add(new MultipartBuilder("b"), fa, "a=v;filename=x.zz")).contains("Content-Type"));
        assertEquals("--b\r\nContent-Disposition: form-data; name=\"a\"; filename=\"-\"\r\n\r\nS\r\n--b--\r\n",
                body(add(new MultipartBuilder("b"), fa, "a=@-")));
    }

    @Test
    void angleBracketFileHasNoFilename() throws Exception {
        FileAccess fa = files(Map.of("f.txt", "T\n"));
        assertEquals("--b\r\nContent-Disposition: form-data; name=\"a\"\r\nContent-Type: text/x\r\n\r\nT\n\r\n--b--\r\n",
                body(add(new MultipartBuilder("b"), fa, "a=<f.txt;type=text/x;filename=ignored.txt")));
    }

    @Test
    void severalFilesAreNestedMixed() throws Exception {
        FileAccess fa = files(Map.of("a.txt", "A", "b.json", "B"));
        MultipartBuilder b = add(new MultipartBuilder("b"), fa, "f=@a.txt,b.json;type=x/y");
        String s = body(b);
        java.util.regex.Matcher m = java.util.regex.Pattern.compile("boundary=(-{24}[A-Za-z0-9]{22})").matcher(s);
        assertTrue(m.find(), s);
        String in = m.group(1);
        assertEquals("--b\r\nContent-Disposition: form-data; name=\"f\"\r\nContent-Type: multipart/mixed; boundary=" + in + "\r\n\r\n"
                + "--" + in + "\r\nContent-Disposition: attachment; filename=\"a.txt\"\r\nContent-Type: text/plain\r\n\r\nA\r\n"
                + "--" + in + "\r\nContent-Disposition: attachment; filename=\"b.json\"\r\nContent-Type: x/y\r\n\r\nB\r\n"
                + "--" + in + "--\r\n\r\n--b--\r\n", s);
        assertEquals(s, body(add(new MultipartBuilder("b"), fa, "f=@a.txt,b.json;type=x/y")), "deterministic with fixed boundary");
    }

    @Test
    void fileReadFailurePropagates() throws Exception {
        MultipartBuilder b = new MultipartBuilder("b");
        assertThrows(IOException.class, () -> b.add(FormField.parse("a=@nope"), FileAccess.DENY));
        assertThrows(IOException.class, () -> b.add(FormField.parse("a=<nope"), FileAccess.DENY));
        assertThrows(IOException.class, () -> b.add(FormField.parse("a=v;headers=@nope"), FileAccess.DENY));
        assertThrows(IOException.class, () -> b.add(FormField.parse("a=@x,y"), files(Map.of("x", "1"))));
        assertEquals("--b--\r\n", body(b), "failed adds leave no partial part");
    }

    @Test
    void binarySafeBodies() throws Exception {
        byte[] bin = {0, 1, (byte) 0xff, '\r', '\n'};
        MultipartBuilder b = new MultipartBuilder("b");
        b.add(FormField.parse("a=@f"), path -> bin);
        byte[] out = b.build();
        String head = "--b\r\nContent-Disposition: form-data; name=\"a\"; filename=\"f\"\r\nContent-Type: application/octet-stream\r\n\r\n";
        byte[] h = head.getBytes(StandardCharsets.UTF_8);
        for (int i = 0; i < bin.length; i++) {
            assertEquals(bin[i], out[h.length + i]);
        }
    }
}
