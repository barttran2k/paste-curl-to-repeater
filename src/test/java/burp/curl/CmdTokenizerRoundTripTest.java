package burp.curl;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import org.junit.jupiter.api.Test;

/**
 * Round-trip against faithful Java ports of the browsers' cmd generators:
 * Chrome DevTools NetworkLogView.ts (devtools-frontend main @ 4f5cdad) and
 * Firefox devtools/client/shared/curl.js (mozilla-firefox main @ 48389b4).
 */
class CmdTokenizerRoundTripTest {

    // ---------------------------------------------------------------- JS semantics helpers
    /** JS \s */
    static boolean jsWs(int c) {
        return c == 9 || c == 10 || c == 11 || c == 12 || c == 13 || c == 32 || c == 0xA0 || c == 0x1680
                || (c >= 0x2000 && c <= 0x200A) || c == 0x2028 || c == 0x2029 || c == 0x202F || c == 0x205F
                || c == 0x3000 || c == 0xFEFF;
    }

    static boolean alnum(int c) {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9');
    }

    /** s.replace(/%(?=[a-zA-Z0-9_])/g, "%^") */
    static String percentCaret(String s) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            sb.append(c);
            if (c == '%' && i + 1 < s.length() && (alnum(s.charAt(i + 1)) || s.charAt(i + 1) == '_')) {
                sb.append('^');
            }
        }
        return sb.toString();
    }

    /** s.replace(/\r?\n|\r/g, "^\n\n") */
    static String newlines(String s) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '\r') {
                if (i + 1 < s.length() && s.charAt(i + 1) == '\n') {
                    i++;
                }
                sb.append("^\n\n");
            } else if (c == '\n') {
                sb.append("^\n\n");
            } else {
                sb.append(c);
            }
        }
        return sb.toString();
    }

    // ---------------------------------------------------------------- Chrome port
    /** NetworkLogView.ts escapeStringWin, step for step (UTF-16 units, no /u flag). */
    static String chromeEscape(String str) {
        String s = str.replace("\\", "\\\\");                         // /\\/g -> \\\\
        s = s.replace("\"", "\"\"");                                  // /"/g  -> ""
        StringBuilder b = new StringBuilder();                        // /[^a-zA-Z0-9\s_\-:=+~'\/.',?;*]/g -> ^$&
        for (char c : s.toCharArray()) {
            boolean ok = alnum(c) || jsWs(c) || "_-:=+~'/.,?;*".indexOf(c) >= 0;
            if (!ok) {
                b.append('^');
            }
            b.append(c);
        }
        s = percentCaret(b.toString());                               // /%(?=[a-zA-Z0-9_])/g -> %^
        b = new StringBuilder();                                      // /[^ -~\r\n]/g -> ' '
        for (char c : s.toCharArray()) {
            b.append((c >= ' ' && c <= '~') || c == '\r' || c == '\n' ? c : ' ');
        }
        s = newlines(b.toString());
        return "^\"" + s + "^\"";
    }

    /** What Chrome's generator turns a string into (its lossy part): non-printables -> ' ' per unit, CR/CRLF -> LF. */
    static String chromeNormalize(String s) {
        StringBuilder b = new StringBuilder();
        for (char c : s.toCharArray()) {
            b.append((c >= ' ' && c <= '~') || c == '\r' || c == '\n' ? c : ' ');
        }
        return b.toString().replace("\r\n", "\n").replace('\r', '\n');
    }

    /** Chrome escapeStringWin applied to the URL, then [ { } ] get a backslash (curl globbing). */
    static String chromeUrl(String url) {
        return chromeEscape(url).replaceAll("[\\[{}\\]]", "\\\\$0");
    }

    static String chromeUrlExpected(String url) {
        return chromeNormalize(url).replaceAll("[\\[{}\\]]", "\\\\$0");
    }

    /** generateCurlCommand(request, 'win') for a request without securityState Insecure. */
    static String chromeCommand(String url, String method, List<String[]> headers, String body, boolean insecure) {
        List<String> command = new ArrayList<>();
        command.add("--url " + chromeUrl(url));
        String inferred = "GET";
        List<String> data = new ArrayList<>();
        boolean hasBody = body != null && !body.isEmpty();
        if (hasBody) {
            data.add("--data-raw " + chromeEscape(body));
            inferred = "POST";
        }
        if (!method.equals(inferred)) {
            command.add("-X " + chromeEscape(method));
        }
        for (String[] h : headers) {
            String name = h[0];
            String value = h[1];
            if (value.isBlank()) {
                command.add("-H " + chromeEscape(name + ";"));
            } else if (name.equalsIgnoreCase("cookie") && value.contains("=")) {
                command.add("-b " + chromeEscape(value));
            } else {
                command.add("-H " + chromeEscape(name + ": " + value));
            }
        }
        command.addAll(data);
        if (insecure) {
            command.add("--insecure");
        }
        return "curl " + String.join(command.size() >= 3 ? " ^\n  " : " ", command);
    }

    // ---------------------------------------------------------------- Firefox port
    static boolean jsC(int cp) {
        int t = Character.getType(cp);
        return t == Character.CONTROL || t == Character.FORMAT || t == Character.SURROGATE
                || t == Character.PRIVATE_USE || t == Character.UNASSIGNED;
    }

    /** curl.js escapeStringWin, step for step. */
    static String firefoxEscape(String str) {
        String s = str.replace("\\", "\\\\");                         // \ -> \\
        s = s.replace("\"", "\\\"");                                  // " -> \"
        StringBuilder b = new StringBuilder();                        // /[^-a-zA-Z0-9\s_:=+~\/.',?;()*`\p{C}]/gu -> ^$&
        for (int i = 0; i < s.length(); ) {
            int cp = s.codePointAt(i);
            i += Character.charCount(cp);
            boolean ok = alnum(cp) || jsWs(cp) || (cp < 128 && "-_:=+~/.',?;()*`".indexOf(cp) >= 0) || jsC(cp);
            if (!ok) {
                b.append('^');
            }
            b.appendCodePoint(cp);
        }
        s = percentCaret(b.toString());
        b = new StringBuilder();                                      // /[^\S\r\n]/g -> ' '
        for (char c : s.toCharArray()) {
            b.append(jsWs(c) && c != '\r' && c != '\n' ? ' ' : c);
        }
        s = newlines(b.toString());
        return "^\"" + s + "^\"";
    }

    /** Firefox lossy part: JS whitespace other than CR/LF -> ' ', CR/CRLF -> LF. */
    static String firefoxNormalize(String s) {
        StringBuilder b = new StringBuilder();
        for (char c : s.toCharArray()) {
            b.append(jsWs(c) && c != '\r' && c != '\n' ? ' ' : c);
        }
        return b.toString().replace("\r\n", "\n").replace('\r', '\n');
    }

    static String firefoxIfNeeded(String v) {
        return v.matches("[a-zA-Z-]+") ? v : firefoxEscape(v);
    }

    /** Curl.generateCommand(data, "WINNT"), without multipart / compressed handling. */
    static String firefoxCommand(String url, String method, List<String[]> headers, String postData) {
        List<String> parts = new ArrayList<>();
        parts.add(firefoxEscape(url));
        if (url.contains("[") || url.contains("]")) {
            parts.add("--globoff");
        }
        List<String> postParts = new ArrayList<>();
        if (postData != null && !postData.isEmpty() && List.of("PUT", "POST", "PATCH").contains(method)) {
            postParts.add("--data-raw " + firefoxIfNeeded(postData));
        }
        if (method.equals("HEAD")) {
            parts.add("-I");
        } else if (!method.equals("GET")) {
            parts.add("-X " + firefoxIfNeeded(method));
        }
        for (String[] h : headers) {
            parts.add("-H " + firefoxIfNeeded(h[0] + ": " + h[1]));
        }
        parts.addAll(postParts);
        return "curl.exe " + String.join(parts.size() >= 3 ? " ^\n  " : " ", parts);
    }

    // ---------------------------------------------------------------- decode helper
    static List<String> argv(String cmd) throws Exception {
        TokenizeResult r = new CmdTokenizer().tokenize(cmd);
        assertEquals(1, r.commands().size(), "commands in: " + cmd);
        List<String> out = new ArrayList<>();
        for (Token t : r.commands().get(0).argv()) {
            out.add(t.text());
        }
        return out;
    }

    static String decodeOne(String escaped) throws Exception {
        List<String> a = argv("curl " + escaped);
        assertEquals(2, a.size(), "argv for " + escaped);
        return a.get(1);
    }

    // ---------------------------------------------------------------- corpus & random
    static final String[] CORPUS = {
        "", " ", "a", "hello world", "\"", "\"\"", "\"\"\"", "a\"b", "\\", "\\\\", "\\\"", "\"\\", "a\\", "a\\\\",
        "\\\\\"", "\\\\\\\"", "%", "%%", "%PATH%", "%a%", "100%", "%1", "%_x%", "^", "^^", "^\"", "\"^", "^%", "%^",
        "&", "&&", "|", "||", "<", ">", ">>", "2>&1", "!", "!x!", "`", "``", "'", "''", "'a'", "(", ")", "()", "(a)",
        "\t", "a\tb", "\n", "\n\n", "a\nb", "a\n", "\nb", "a\n\nb", "[x]", "{x}", "a=1&b=2%20c", "https://example.com/a?b=c&d=%20e#f",
        "{\"a\":\"b\",\"c\":[1,2,{\"d\":null}]}", "{\"s\":\"line1\\nline2\",\"p\":\"C:\\\\dir\\\\f\"}",
        "{\"q\":\"say \\\"hi\\\"\"}", "SELECT * FROM t WHERE a='x' AND b=\"y\";", "a;b,c:d=e+f~g/h.i'j*k?l",
        "é", "日本語", "😀", "a😀b", "\u0001", "\u007f", "x\u0000y", "\u00a0", "a\u2028b", "\u200b", "\uFEFF",
        "echo \"%USERNAME%\" ^& calc", "^\"^\"", "\"&calc&\"", "a  b", "  lead", "trail  ",
    };

    static final String[] FRAGMENTS = {
        "\"", "\\", "%", "^", "&", "|", "<", ">", "!", "`", "'", "(", ")", " ", "  ", "\t", "\n", "\r\n", "\r", "%PATH%",
        "%a%", "%1", "%x_", "é", "日本", "😀", "\u0001", "\u00a0", "\u2028", "\u200b", "{\"a\":\"b\"}", "\\\"", "\\\\",
        "\"\"", "[", "]", "{", "}", ";", ",", ":", "=", "+", "~", "/", ".", "?", "*", "a", "Z", "0", "_", "-", "#", "$",
        "@", "bar", "http://x/", "\u007f", "\u0000",
    };

    static String randomString(Random r) {
        int n = r.nextInt(14);
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < n; i++) {
            if (r.nextInt(5) == 0) {
                sb.append((char) (0x20 + r.nextInt(0x5f)));
            } else {
                sb.append(FRAGMENTS[r.nextInt(FRAGMENTS.length)]);
            }
        }
        return sb.toString();
    }

    // ---------------------------------------------------------------- tests
    @Test
    void chromeCorpusRoundTrip() throws Exception {
        for (String s : CORPUS) {
            assertEquals(chromeNormalize(s), decodeOne(chromeEscape(s)), "corpus: " + show(s));
        }
    }

    @Test
    void firefoxCorpusRoundTrip() throws Exception {
        for (String s : CORPUS) {
            assertEquals(firefoxNormalize(s), decodeOne(firefoxEscape(s)), "corpus: " + show(s));
        }
    }

    @Test
    void chromeRandomExactRoundTrip() throws Exception {
        Random r = new Random(20241112L);
        int exact = 0;
        while (exact < 2500) {
            String s = randomString(r);
            if (!chromeNormalize(s).equals(s)) {
                continue; // generator-lossy class, covered by chromeRandomLossyMapping
            }
            assertEquals(s, decodeOne(chromeEscape(s)), "random: " + show(s));
            exact++;
        }
    }

    @Test
    void firefoxRandomExactRoundTrip() throws Exception {
        Random r = new Random(20241113L);
        int exact = 0;
        while (exact < 2500) {
            String s = randomString(r);
            if (!firefoxNormalize(s).equals(s)) {
                continue;
            }
            assertEquals(s, decodeOne(firefoxEscape(s)), "random: " + show(s));
            exact++;
        }
    }

    @Test
    void randomLossyMappingIsExactlyTheGeneratorsLoss() throws Exception {
        Random r = new Random(7L);
        for (int i = 0; i < 3000; i++) {
            String s = randomString(r);
            assertEquals(chromeNormalize(s), decodeOne(chromeEscape(s)), "chrome: " + show(s));
            assertEquals(firefoxNormalize(s), decodeOne(firefoxEscape(s)), "firefox: " + show(s));
        }
    }

    /** Minimal proofs that the generators themselves lose information (so those classes are excluded). */
    @Test
    void generatorLossProofs() throws Exception {
        // Both: TAB and CR/CRLF are not representable.
        assertEquals(" ", decodeOne(chromeEscape("\t")));
        assertEquals(" ", decodeOne(firefoxEscape("\t")));
        assertEquals("\n", decodeOne(chromeEscape("\r\n")));
        assertEquals("\n", decodeOne(firefoxEscape("\r")));
        assertEquals(chromeEscape("\r\n"), chromeEscape("\n"));
        // Both: NBSP -> space.
        assertEquals(" ", decodeOne(chromeEscape("\u00a0")));
        assertEquals(" ", decodeOne(firefoxEscape("\u00a0")));
        // Chrome only: every non-ASCII UTF-16 unit and control char -> space (emoji = 2 spaces).
        assertEquals(" ", decodeOne(chromeEscape("é")));
        assertEquals("  ", decodeOne(chromeEscape("😀")));
        assertEquals(" ", decodeOne(chromeEscape("\u0001")));
        // Firefox keeps non-ASCII, emoji and control characters.
        assertEquals("é😀\u0001", decodeOne(firefoxEscape("é😀\u0001")));
    }

    @Test
    void chromeFullCommandsRandom() throws Exception {
        Random r = new Random(99L);
        for (int i = 0; i < 2000; i++) {
            String url = "https://h" + r.nextInt(9) + ".example/" + randomString(r);
            String method = new String[] {"GET", "POST", "PUT", "DELETE", "PATCH"}[r.nextInt(5)];
            List<String[]> headers = new ArrayList<>();
            int nh = r.nextInt(4);
            for (int k = 0; k < nh; k++) {
                String name = new String[] {"X-A", "Cookie", "Accept", "X-Empty"}[r.nextInt(4)];
                headers.add(new String[] {name, r.nextInt(6) == 0 ? "" : randomString(r)});
            }
            String body = r.nextBoolean() ? randomString(r) : "";
            boolean insecure = r.nextBoolean();
            String cmd = chromeCommand(url, method, headers, body, insecure);

            List<String> exp = new ArrayList<>(List.of("curl", "--url", chromeUrlExpected(url)));
            String inferred = !body.isEmpty() ? "POST" : "GET";
            if (!method.equals(inferred)) {
                exp.addAll(List.of("-X", method));
            }
            for (String[] h : headers) {
                String v = h[1];
                if (v.isBlank()) {
                    exp.addAll(List.of("-H", h[0] + ";"));
                } else if (h[0].equalsIgnoreCase("cookie") && v.contains("=")) {
                    exp.addAll(List.of("-b", chromeNormalize(v)));
                } else {
                    exp.addAll(List.of("-H", chromeNormalize(h[0] + ": " + v)));
                }
            }
            if (!body.isEmpty()) {
                exp.addAll(List.of("--data-raw", chromeNormalize(body)));
            }
            if (insecure) {
                exp.add("--insecure");
            }
            assertEquals(exp, argv(cmd), "cmd: " + cmd);
        }
    }

    @Test
    void firefoxFullCommandsRandom() throws Exception {
        Random r = new Random(101L);
        for (int i = 0; i < 2000; i++) {
            String url = "https://h" + r.nextInt(9) + ".example/" + randomString(r);
            String method = new String[] {"GET", "POST", "PUT", "HEAD", "PATCH", "DELETE"}[r.nextInt(6)];
            List<String[]> headers = new ArrayList<>();
            int nh = r.nextInt(4);
            for (int k = 0; k < nh; k++) {
                headers.add(new String[] {new String[] {"X-A", "Cookie", "Accept"}[r.nextInt(3)], randomString(r)});
            }
            String body = r.nextBoolean() ? randomString(r) : "";
            String cmd = firefoxCommand(url, method, headers, body);

            List<String> exp = new ArrayList<>(List.of("curl.exe", firefoxNormalize(url)));
            if (url.contains("[") || url.contains("]")) {
                exp.add("--globoff");
            }
            if (method.equals("HEAD")) {
                exp.add("-I");
            } else if (!method.equals("GET")) {
                exp.addAll(List.of("-X", method));
            }
            for (String[] h : headers) {
                exp.addAll(List.of("-H", firefoxNormalize(h[0] + ": " + h[1])));
            }
            if (!body.isEmpty() && List.of("PUT", "POST", "PATCH").contains(method)) {
                exp.addAll(List.of("--data-raw", firefoxNormalize(body)));
            }
            assertEquals(exp, argv(cmd), "cmd: " + cmd);
        }
    }

    @Test
    void chromeCopyAllJoinsCommandsWithAmpersandCrLf() throws Exception {
        String a = chromeCommand("https://a.example/?x=1&y=2", "GET", List.of(), "", false);
        String b = chromeCommand("https://b.example/", "POST", List.<String[]>of(new String[] {"X-A", "v"}), "{\"k\":\"v\"}", false);
        TokenizeResult r = new CmdTokenizer().tokenize(a + " &\r\n" + b);
        assertEquals(2, r.commands().size());
        assertEquals("https://a.example/?x=1&y=2", r.commands().get(0).argv().get(2).text());
        assertEquals("{\"k\":\"v\"}", r.commands().get(1).argv().get(r.commands().get(1).argv().size() - 1).text());
    }

    @Test
    void quotedFlagSetForGeneratorOutput() throws Exception {
        TokenizeResult r = new CmdTokenizer().tokenize("curl.exe ^\"https://x^\" -X POST");
        List<Token> v = r.commands().get(0).argv();
        assertTrue(v.get(1).quoted());
        assertTrue(!v.get(0).quoted());
        assertTrue(!v.get(3).quoted());
    }

    static String show(String s) {
        StringBuilder b = new StringBuilder("[");
        for (char c : s.toCharArray()) {
            if (c >= ' ' && c <= '~') {
                b.append(c);
            } else {
                b.append(String.format("\\u%04x", (int) c));
            }
        }
        return b.append("]").toString();
    }
}
