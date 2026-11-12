package burp.curl;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import burp.curl.FormField.Kind;
import java.util.List;
import org.junit.jupiter.api.Test;

class FormFieldTest {
    @Test
    void literal() throws Exception {
        FormField f = FormField.parse("name=John \"Q\" Doe");
        assertEquals(new FormField("name", Kind.LITERAL, "John \"Q\" Doe", null, null, List.of()), f);
        assertEquals("", FormField.parse("a=").value());
        assertEquals("x=y", FormField.parse("a=x=y").value());
        assertEquals("a ", FormField.parse("a = x").name());
        assertEquals("x", FormField.parse("a= x").value());
    }

    @Test
    void fileUploadWithOptions() throws Exception {
        FormField f = FormField.parse("file=@files/body.txt;type=text/plain;filename=n.txt;headers=X-A: 1");
        assertEquals(Kind.FILE_UPLOAD, f.kind());
        assertEquals("files/body.txt", f.value());
        assertEquals("text/plain", f.type());
        assertEquals("n.txt", f.filename());
        assertEquals(List.of("X-A: 1"), f.headers());
        assertEquals(List.of("files/body.txt"), f.filePaths());
    }

    @Test
    void fileContent() throws Exception {
        FormField f = FormField.parse("x=<files/data.json;type=application/json");
        assertEquals(Kind.FILE_CONTENT, f.kind());
        assertEquals("files/data.json", f.value());
        assertEquals("application/json", f.type());
    }

    @Test
    void formStringIsAlwaysLiteral() throws Exception {
        FormField f = FormString("raw=@notfile;type=x");
        assertEquals(Kind.LITERAL, f.kind());
        assertEquals("@notfile;type=x", f.value());
        assertNull(f.type());
        assertThrows(CurlParseException.class, () -> FormField.parseString("noequals"));
    }

    private static FormField FormString(String s) throws CurlParseException {
        return FormField.parseString(s);
    }

    @Test
    void quoting() throws Exception {
        assertEquals("x;y", FormField.parse("a=\"x;y\"").value());
        assertEquals("x\"y\\z", FormField.parse("a=\"x\\\"y\\\\z\"").value());
        assertEquals("@f.txt", FormField.parse("a=\"@f.txt\"").value());
        assertEquals(Kind.LITERAL, FormField.parse("a=\"@f.txt\"").kind());
        assertEquals(Kind.LITERAL, FormField.parse("a= @f.txt").kind());
        FormField f = FormField.parse("f=@\"my file.txt\";type=text/plain");
        assertEquals("my file.txt", f.value());
        assertEquals("\"x", FormField.parse("a=\"x").value());
        assertEquals("x", FormField.parse("a=\"x\"junk;type=t/t").value());
        assertEquals("a;b.txt", FormField.parse("a=@f;filename=\"a;b.txt\"").filename());
    }

    @Test
    void typeGluesUnknownParametersAndStopsAtFilename() throws Exception {
        assertEquals("text/plain;charset=utf-8", FormField.parse("a=x;type=text/plain;charset=utf-8").type());
        assertEquals("text/plain; charset=utf-8", FormField.parse("a=x;type=text/plain; charset=utf-8").type());
        FormField f = FormField.parse("a=x;type=t/t;foo=1;filename=z");
        assertEquals("t/t;foo=1", f.type());
        assertEquals("z", f.filename());
        assertEquals("t/t", FormField.parse("a=x;TYPE= t/t ;filename=q").type());
        assertEquals("t/t;", FormField.parse("a=x;filename=z;type=t/t;").type());
        assertEquals("t/t; ", FormField.parse("a=x;type=t/t; ;headers=H: 1").type());
    }

    @Test
    void unknownParameterWithoutTypeIsIgnored() throws Exception {
        FormField f = FormField.parse("a=x;y");
        assertEquals("x", f.value());
        assertNull(f.type());
        assertEquals("t/t", FormField.parse("a=x;y;type=t/t").type());
        assertEquals("z", FormField.parse("a=x;\"q;r\";filename=z").filename());
    }

    @Test
    void errors() {
        assertThrows(CurlParseException.class, () -> FormField.parse("noequals"));
        assertThrows(CurlParseException.class, () -> FormField.parse("a=x;type=a"));
        assertThrows(CurlParseException.class, () -> FormField.parse("a=x;type="));
        assertThrows(CurlParseException.class, () -> FormField.parse("a=@f;type=/"));
        assertThrows(CurlParseException.class, () -> FormField.parse("a=x;encoder=base64"));
    }

    @Test
    void headerFilesAndMultipleHeaders() throws Exception {
        FormField f = FormField.parse("a=v;headers=X-A: 1;headers=@hdr.txt;headers=\"X-B: a;b\"");
        assertEquals(List.of("X-A: 1", "@hdr.txt", "X-B: a;b"), f.headers());
        assertEquals(List.of("hdr.txt"), f.filePaths());
    }

    @Test
    void severalFilesInOneField() throws Exception {
        FormField f = FormField.parse("f=@a.txt;type=t/1,b.txt;filename=q.txt, c.png");
        assertEquals(Kind.FILE_LIST, f.kind());
        assertEquals(List.of("a.txt", "b.txt", "c.png"), f.filePaths());
        List<FormField> files = f.files();
        assertEquals("t/1", files.get(0).type());
        assertNull(files.get(1).type());
        assertEquals("q.txt", files.get(1).filename());
        assertEquals("f", files.get(2).name());
        assertEquals(List.of("a.txt", ""), FormField.parse("f=@a.txt,").filePaths());
        assertEquals(List.of("a.txt", "b.txt"), FormField.parse("f=@a.txt;foo,b.txt").filePaths());
    }

    @Test
    void angleBracketDoesNotSplitOnComma() throws Exception {
        assertEquals("a,b", FormField.parse("f=<a,b").value());
    }

    @Test
    void quotedHeadersValueIsNeverAFileReference() throws Exception {
        // measured with curl 8.7.1: the @ or < is a file marker only as the first character, unquoted
        for (String marker : new String[] {"@", "<"}) {
            FormField q = FormField.parse("a=b;headers=\"" + marker + "lit: x\"");
            assertEquals(List.of(marker + "lit: x"), q.headers());
            assertEquals(false, q.isHeaderFile(0));
            assertEquals(List.of(), q.filePaths());
            FormField f = FormField.parse("a=b;headers=" + marker + "hdr.txt");
            assertEquals(true, f.isHeaderFile(0));
            assertEquals(List.of("hdr.txt"), f.filePaths());
            FormField mq = FormField.parse("a=b;headers=" + marker + "\"hdr.txt\"");
            assertEquals(true, mq.isHeaderFile(0));
            assertEquals(List.of("hdr.txt"), mq.filePaths());
        }
    }
}
