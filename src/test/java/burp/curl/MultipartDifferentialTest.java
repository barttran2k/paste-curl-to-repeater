package burp.curl;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;
import org.junit.jupiter.api.io.TempDir;

/** Compares {@link MultipartBuilder} with the multipart body and Content-Type the real curl sends. */
class MultipartDifferentialTest {
    private static final Pattern BOUNDARY = Pattern.compile("-{24}[A-Za-z0-9]{22}");

    @TempDir
    Path dir;

    /** Each case is a list of curl arguments; {d} is the temp dir. */
    private static final String[][] CASES = {
        {"-F", "name=John \"Q\" Doe", "-F", "file=@{d}/body.txt;type=text/plain", "-F", "x=<{d}/data.json", "-F",
            "j=@{d}/data.json;filename=renamed.json", "--form-string", "raw=@notfile;type=x"},
        {"-F", "a=b;type=text/x", "-F", "a=@{d}/a.txt", "-F", "a=@{d}/a.txt;type=text/html;filename=n.x"},
        {"-F", "a=@{d}/b.txt,{d}/data.json"},
        {"-F", "a=@{d}/b.txt,{d}/data.json;type=text/x"},
        {"-F", "a=@{d}/b.txt;type=t/1,{d}/data.json;type=t/2"},
        {"-F", "a=@{d}/b.txt;filename=x.png,{d}/t.png;headers=X-Z: 1"},
        {"-F", "a=@{d}/b.txt, {d}/a.txt ,{d}/t.PNG"},
        {"-F", "a=@\"{d}/my file.txt\";type=text/plain"},
        {"-F", "a=<\"{d}/my file.txt\""},
        {"-F", "a=\"x;y\""},
        {"-F", "a=\"x\\\"y\\\\z\""},
        {"-F", "a=\"@{d}/a.txt\"", "-F", "b=\"<{d}/a.txt\"", "--form-string", "c=\"q\""},
        {"-F", "a="},
        {"-F", "=v"},
        {"-F", "a"},
        {"-F", "a=@{d}/p.png"},
        {"-F", "a=@{d}/a.txt;headers=X-A: 1"},
        {"-F", "a=v;headers=X-A: 1;headers=X-B: 2"},
        {"-F", "a=@{d}/a.txt;type=text/x;headers=X-A: 1"},
        {"-F", "a=v;headers=@{d}/hdr.txt"},
        {"-F", "a=@{d}/a.txt;headers=@{d}/hdr.txt;type=t/t"},
        {"-F", "a=v;type=t/t;headers=Content-Type: z/z"},
        {"-F", "a=@{d}/a.txt;headers=Content-Type: z/z"},
        {"-F", "a=v;headers=Content-Disposition: attachment"},
        {"-F", "a=v;headers=X-A:"},
        {"-F", "a=v;headers=\"X-A: a;b\""},
        {"-F", "a=x;y"},
        {"-F", "a=x;"},
        {"-F", "a=x;;type=t/t"},
        {"-F", "a=x;type=a;y=2"},
        {"-F", "a=x;type=text/plain;charset=utf-8"},
        {"-F", "a=x;type=text/plain; charset=utf-8"},
        {"-F", "a=x;type=t/t;foo=1;filename=z"},
        {"-F", "a=x;type=t/t;filename=z;foo"},
        {"-F", "a=x;filename=z;type=t/t"},
        {"-F", "a=x;type=t/t;"},
        {"-F", "a=x;type=t/t; ;headers=H: 1"},
        {"-F", "a=x;TYPE= t/t ;FILENAME=q"},
        {"-F", "a=x;type="},
        {"-F", "a=x;type=\"t/t;u\""},
        {"-F", "a=v;filename=z"},
        {"-F", "a=v;filename=x.png"},
        {"-F", "a=@{d}/a.txt;filename="},
        {"-F", "a=@{d}/a.txt;filename=\"q\\\"r.txt\""},
        {"-F", "a=@{d}/a.txt;filename=q\"r.txt"},
        {"-F", "a=@{d}/a.txt;filename=é.txt"},
        {"-F", "a=@{d}/a.txt;filename=a\\b"},
        {"-F", "a=@{d}/a.txt;filename=a\rb\nc"},
        {"-F", "a\"b=v"},
        {"-F", "a\\b=v"},
        {"-F", "a\rb\nc=v"},
        {"-F", "é=v"},
        {"-F", "a = x"},
        {"-F", "a= x"},
        {"-F", "a= @{d}/a.txt"},
        {"-F", "a=@ {d}/a.txt"},
        {"-F", "a=x ;type=t/t"},
        {"-F", "a=\"x"},
        {"-F", "a=\"x;type=t/t"},
        {"-F", "a=\"\";type=t/t"},
        {"-F", "a=\"x\"junk;type=t/t"},
        {"-F", "\"a\"=v"},
        {"-F", "a=x=y"},
        {"--form-escape", "-F", "a\"b\\c=v"},
        {"--form-escape", "-F", "a=@{d}/a.txt;filename=q\"r\\s.txt"},
        {"--form-escape", "-F", "a\rb\nc=v"},
        {"--form-escape", "-F", "é=v"},
        {"--form-escape", "-F", "a=@{d}/a.txt,{d}/b.txt;filename=q\"r"},
        {"-F", "a=<{d}/a.txt;type=text/x"},
        {"-F", "a=<{d}/a.txt;filename=z.txt"},
        {"-F", "a=<{d}/b.txt,{d}/a.txt"},
        {"-F", "a=<{d}/multi.txt"},
        {"-F", "a=@{d}/multi.txt"},
        {"-F", "a=@{d}/nonexist"},
        {"-F", "a=<{d}/nonexist"},
        {"-F", "a=@"},
        {"-F", "a=<"},
        {"-F", "a=@{d}/a.txt,"},
        {"-F", "a=@{d}/a.txt;foo,{d}/b.txt"},
        {"-F", "a=x;y;type=t/t"},
        {"-F", "a=x;y=1;filename=z"},
        {"-F", "a=x;;;filename=z"},
        {"-F", "a=x; ;filename=z"},
        {"-F", "a=x;\"q;r\";filename=z"},
        {"-F", "a=@{d}/a.txt;y;type=t/t"},
        {"--form-string", "a"},
        {"--form-string", "a=x;type=t/t"},
        {"-F", "a=@{d}/a.txt;type=\"t/t\""},
        {"-F", "a=@{d}/a.txt;type=t/t;type=u/u"},
        {"-F", "a=v;type=t/t;type=u/u"},
        {"-F", "a=@{d}/a.txt;type=/"},
        {"-F", "a=@{d}/a.txt;type=a/"},
        {"-F", "a=@{d}/a.txt;filename=x.json"},
        {"-F", "a=@{d}/t.png;filename=x.zz"},
        {"-F", "a=@{d}/t.png;filename=x.txt"},
        {"-F", "a=@{d}/.txt"},
        {"-F", "a=@{d}/noext"},
        {"-F", "a=@{d}/t.html.bak"},
        {"-F", "a=@{d}/t.gif", "-F", "b=@{d}/t.jpg", "-F", "c=@{d}/t.jpeg", "-F", "d=@{d}/t.svg", "-F", "e=@{d}/t.htm",
            "-F", "f=@{d}/t.html", "-F", "g=@{d}/t.pdf", "-F", "h=@{d}/t.xml", "-F", "i=@{d}/t.TXT", "-F", "j=@{d}/t.Html",
            "-F", "k=@{d}/t.css", "-F", "l=@{d}/t.js", "-F", "m=@{d}/t.zip", "-F", "n=@{d}/t.webp"},
        {"-F", "a=@{d}/sub/in.txt"},
        {"-F", "a=@{d}/sub/../a.txt"},
    };

    private Map<String, byte[]> setUp() throws IOException {
        Map<String, byte[]> m = new LinkedHashMap<>();
        m.put("body.txt", "hello body\n".getBytes(StandardCharsets.UTF_8));
        m.put("a.txt", "hello\n".getBytes(StandardCharsets.UTF_8));
        m.put("b.txt", "B".getBytes(StandardCharsets.UTF_8));
        m.put("data.json", "{\"k\":\"v\"}".getBytes(StandardCharsets.UTF_8));
        m.put("my file.txt", "x".getBytes(StandardCharsets.UTF_8));
        m.put("multi.txt", "l1\nl2\r\nl3".getBytes(StandardCharsets.UTF_8));
        m.put("p.png", new byte[] {0, 1, (byte) 0xff, '\r', '\n', '-', '-'});
        m.put("hdr.txt", "X-File: yes\nX-Two: 2\n".getBytes(StandardCharsets.UTF_8));
        m.put("noext", "z".getBytes(StandardCharsets.UTF_8));
        m.put("t.html.bak", "z".getBytes(StandardCharsets.UTF_8));
        m.put(".txt", "z".getBytes(StandardCharsets.UTF_8));
        for (String e : new String[] {"gif", "jpg", "jpeg", "png", "svg", "htm", "html", "pdf", "xml", "TXT", "Html", "css", "js", "zip", "webp"}) {
            m.put("t." + e, "z".getBytes(StandardCharsets.UTF_8));
        }
        Files.createDirectories(dir.resolve("sub"));
        m.put("sub/in.txt", "z".getBytes(StandardCharsets.UTF_8));
        for (Map.Entry<String, byte[]> e : m.entrySet()) {
            Files.write(dir.resolve(e.getKey()), e.getValue());
        }
        return m;
    }

    @TestFactory
    Stream<DynamicTest> formCasesAgainstRealCurl() throws IOException {
        Assumptions.assumeTrue(CurlUrlDifferentialTest.curlAvailable(), "curl binary not found");
        setUp();
        return java.util.Arrays.stream(CASES)
                .map(c -> DynamicTest.dynamicTest(String.join(" | ", c).replace("{d}", "<dir>"), () -> check(c)));
    }

    private static String normalise(String text) {
        Map<String, String> names = new LinkedHashMap<>();
        Matcher m = BOUNDARY.matcher(text);
        StringBuilder sb = new StringBuilder();
        while (m.find()) {
            String n = names.computeIfAbsent(m.group(), k -> "<B" + (names.size() + 1) + ">");
            m.appendReplacement(sb, Matcher.quoteReplacement(n));
        }
        m.appendTail(sb);
        return sb.toString();
    }

    private void check(String[] template) throws Exception {
        List<String> args = new ArrayList<>();
        String d = dir.toString();
        for (String a : template) {
            args.add(a.replace("{d}", d));
        }
        args.add("http://form.example/");
        CurlUrlDifferentialTest.Captured got = CurlUrlDifferentialTest.capture(args.toArray(new String[0]));
        FileAccess fa = path -> Files.readAllBytes(Path.of(path));

        MultipartBuilder b = new MultipartBuilder();
        boolean ok = true;
        Throwable failure = null;
        try {
            for (int i = 0; i < args.size() - 1; i++) {
                String a = args.get(i);
                if (a.equals("-F")) {
                    b.add(FormField.parse(args.get(++i)), fa);
                } else if (a.equals("--form-string")) {
                    b.add(FormField.parseString(args.get(++i)), fa);
                } else if (a.equals("--form-escape")) {
                    b.formEscape(true);
                }
            }
        } catch (CurlParseException | IOException e) {
            ok = false;
            failure = e;
        }
        if (got.raw == null || got.raw.length == 0) {
            assertEquals(false, ok, "curl failed (exit " + got.exit + ": " + got.stderr.trim() + ") but we built a body");
            return;
        }
        assertEquals(true, ok, "curl succeeded but we failed: " + failure);
        String curlType = normalise(got.header("Content-Type"));
        String curlBody = normalise(new String(got.body(), StandardCharsets.ISO_8859_1));
        String ourBody = normalise(new String(b.build(), StandardCharsets.ISO_8859_1));
        assertEquals(curlBody, ourBody, "body");
        String ours = b.contentType();
        assertEquals(curlType, normalise(ours), "Content-Type");
        assertEquals(Integer.parseInt(got.header("Content-Length")), b.build().length, "Content-Length");
    }

    static int caseCount() {
        return CASES.length;
    }
}
