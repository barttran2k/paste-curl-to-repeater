package burp.curl;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

class PosixTokenizerTest {
    static TokenizeResult tok(String in) throws CurlParseException {
        return new PosixTokenizer().tokenize(in);
    }

    static List<String> argv(CommandLine c) {
        List<String> l = new ArrayList<>();
        for (Token t : c.argv()) l.add(t.text());
        return l;
    }

    /** argv of the single command. */
    static List<String> one(String in) throws CurlParseException {
        TokenizeResult r = tok(in);
        assertEquals(1, r.commands().size(), "commands in: " + in);
        return argv(r.commands().get(0));
    }

    static long lossy(TokenizeResult r) {
        return r.warnings().stream().filter(w -> w.severity() == Warning.Severity.LOSSY).count();
    }

    static long notes(TokenizeResult r) {
        return r.warnings().stream().filter(w -> w.severity() == Warning.Severity.NOTE).count();
    }

    @Test
    void chromeCopyAsCurl() throws Exception {
        String in = "curl 'https://api.example.com/v1/users/42?expand=roles&fields=id,name' \\\n"
                + "  -X 'PUT' \\\n"
                + "  -H 'sec-ch-ua: \"Chromium\";v=\"130\", \"Not?A_Brand\";v=\"99\"' \\\n"
                + "  -b 'session=abc123; csrftoken=xyz' \\\n"
                + "  --data-raw $'{\"name\":\"O\\'Brien\",\"note\":\"line1\\\\nline2 -H \\'x: y\\'\"}' \\\n"
                + "  --compressed\n";
        assertEquals(List.of("curl", "https://api.example.com/v1/users/42?expand=roles&fields=id,name",
                "-X", "PUT", "-H", "sec-ch-ua: \"Chromium\";v=\"130\", \"Not?A_Brand\";v=\"99\"",
                "-b", "session=abc123; csrftoken=xyz", "--data-raw",
                "{\"name\":\"O'Brien\",\"note\":\"line1\\nline2 -H 'x: y'\"}", "--compressed"), one(in));
        assertEquals(0, lossy(tok(in)));
    }

    @Test
    void emptyInput() throws Exception {
        assertTrue(tok("").commands().isEmpty());
        assertTrue(tok("  \n\t \r\n").commands().isEmpty());
        assertTrue(tok("\uFEFF").commands().isEmpty());
    }

    @Test
    void emptyQuotedWordKept() throws Exception {
        TokenizeResult r = tok("curl -d '' \"\" x");
        List<Token> a = r.commands().get(0).argv();
        assertEquals(5, a.size());
        assertEquals("", a.get(2).text());
        assertTrue(a.get(2).quoted());
        assertEquals("", a.get(3).text());
        assertFalse(a.get(1).quoted());
    }

    @Test
    void quotedFlag() throws Exception {
        List<Token> a = tok("a b\\ c 'd' -H'x: y' $'z' \"w\" $VAR").commands().get(0).argv();
        assertFalse(a.get(0).quoted());
        assertTrue(a.get(1).quoted());
        assertTrue(a.get(2).quoted());
        assertTrue(a.get(3).quoted());
        assertTrue(a.get(4).quoted());
        assertTrue(a.get(5).quoted());
        assertFalse(a.get(6).quoted());
    }

    @Test
    void concatenation() throws Exception {
        assertEquals(List.of("a'b", "-Hx: y"), one("'a'\\''b' -H'x: y'"));
    }

    @Test
    void bytesAreRawForAnsiC() throws Exception {
        Token t = tok("$'\\xff\\x41\\101\u00e9'").commands().get(0).argv().get(0);
        assertArrayEquals(new byte[] {(byte) 0xff, 0x41, 0x41, (byte) 0xc3, (byte) 0xa9}, t.bytes());
        t = tok("$'\\u00e9\\U0001F600'").commands().get(0).argv().get(0);
        assertArrayEquals("\u00e9\uD83D\uDE00".getBytes(StandardCharsets.UTF_8), t.bytes());
    }

    @Test
    void expansionsKeptVerbatimWithWarnings() throws Exception {
        TokenizeResult r = tok("curl $TOKEN ${A:-b c} $(echo \"x y\") \"$(cat a b)\" `date +%s` $((1+2)) \"pre-$X-post\"");
        assertEquals(List.of("curl", "$TOKEN", "${A:-b c}", "$(echo \"x y\")", "$(cat a b)", "`date +%s`",
                "$((1+2))", "pre-$X-post"), argv(r.commands().get(0)));
        assertEquals(5, lossy(r)); // the three command substitutions are one message now
        assertTrue(r.warnings().get(0).message().contains("$TOKEN"));
    }

    @Test
    void sameExpansionWarnsOnce() throws Exception {
        TokenizeResult r = tok("curl $A $A \"$A\"");
        assertEquals(1, lossy(r));
    }

    @Test
    void plainDollarNoWarning() throws Exception {
        TokenizeResult r = tok("curl a$ $ \"$\" 5$, '$x' \"\\$x\" $'$x'");
        assertEquals(List.of("curl", "a$", "$", "$", "5$,", "$x", "$x", "$x"), argv(r.commands().get(0)));
        assertEquals(0, lossy(r));
    }

    @Test
    void parenScanHandlesNestedQuotes() throws Exception {
        assertEquals(List.of("curl", "$(echo ')' \"a)b\" $(x))", "next"), one("curl $(echo ')' \"a)b\" $(x)) next"));
    }

    @Test
    void noGlobTildeBraceExpansion() throws Exception {
        assertEquals(List.of("curl", "~/x", "*.txt", "[a-z]?", "{a,b}", "h/{1..3}"),
                one("curl ~/x *.txt [a-z]? {a,b} h/{1..3}"));
    }

    @Test
    void pipesAndSeparators() throws Exception {
        TokenizeResult r = tok("curl -s http://h | jq . && echo ok || echo no; echo x");
        assertEquals(5, r.commands().size());
        assertEquals(List.of("curl", "-s", "http://h"), argv(r.commands().get(0)));
        assertEquals(List.of("jq", "."), argv(r.commands().get(1)));
        assertEquals(List.of("echo", "x"), argv(r.commands().get(4)));
    }

    @Test
    void emptyCommandsSkipped() throws Exception {
        TokenizeResult r = tok(";; \n\n curl a ;; ; \n");
        assertEquals(1, r.commands().size());
    }

    @Test
    void ampersandInsideWordIsLiteral() throws Exception {
        assertEquals(List.of("curl", "http://h/p?a=1&b=2"), one("curl http://h/p?a=1&b=2"));
        assertEquals(List.of("curl", "a&b&c"), one("curl a&b&c"));
    }

    @Test
    void ampersandAsOperator() throws Exception {
        TokenizeResult r = tok("curl a & curl b");
        assertEquals(2, r.commands().size());
        r = tok("curl a&");
        assertEquals(List.of("curl", "a"), argv(r.commands().get(0)));
        r = tok("curl a&& curl b");
        assertEquals(2, r.commands().size());
        assertEquals(List.of("curl", "a"), argv(r.commands().get(0)));
        r = tok("curl a&curl b".replace("&c", "& c"));
        assertEquals(2, r.commands().size());
    }

    @Test
    void ampersandBeforeGtIsRedirect() throws Exception {
        assertEquals(List.of("curl", "a"), one("curl a &>/dev/null"));
        assertEquals(List.of("curl", "a"), one("curl a &>>log"));
        assertEquals(List.of("curl", "a"), one("curl a&>log"));
    }

    @Test
    void outputRedirectionsRemoved() throws Exception {
        assertEquals(List.of("curl", "a"), one("curl a > out.txt"));
        assertEquals(List.of("curl", "a"), one("curl a >out.txt"));
        assertEquals(List.of("curl", "a"), one("curl a >>out"));
        assertEquals(List.of("curl", "a"), one("curl a >| out"));
        assertEquals(List.of("curl", "a"), one("curl a 2>/dev/null"));
        assertEquals(List.of("curl", "a"), one("curl a 2>&1"));
        assertEquals(List.of("curl", "a"), one("curl a >&2"));
        assertEquals(List.of("curl", "a", "b"), one("curl a 2> /dev/null b"));
        assertEquals(List.of("curl", "a2"), one("curl a2>f"));
        assertEquals(List.of("curl", "2a"), one("curl 2a>f"));
        assertEquals(List.of("curl", "a"), one("curl a 2>&1 | tee x".split("\\|")[0]));
    }

    @Test
    void quotedRedirectCharsStayLiteral() throws Exception {
        assertEquals(List.of("curl", ">", "a>b", "<x", "|", ";", "&"), one("curl '>' a'>'b \\<x \"|\" ';' \\&"));
    }

    @Test
    void stdinFile() throws Exception {
        CommandLine c = tok("curl -d @- < body.json http://x").commands().get(0);
        assertEquals("body.json", c.stdinFile());
        assertEquals(List.of("curl", "-d", "@-", "http://x"), argv(c));
        assertNull(c.stdin());
        assertEquals("a b.json", tok("curl <'a b.json'").commands().get(0).stdinFile());
    }

    @Test
    void hereString() throws Exception {
        CommandLine c = tok("curl -d @- <<< 'a b' http://x").commands().get(0);
        assertEquals("a b\n", new String(c.stdin(), StandardCharsets.UTF_8));
        assertEquals(List.of("curl", "-d", "@-", "http://x"), argv(c));
        c = tok("curl <<<\"{\\\"k\\\":1}\"").commands().get(0);
        assertEquals("{\"k\":1}\n", new String(c.stdin(), StandardCharsets.UTF_8));
    }

    @Test
    void heredocQuotedDelimiterIsLiteral() throws Exception {
        TokenizeResult r = tok("curl -d @- <<'EOF' http://x\n{\"a\": \"$HOME\"}\n\\n `x`\nEOF\n");
        CommandLine c = r.commands().get(0);
        assertEquals(List.of("curl", "-d", "@-", "http://x"), argv(c));
        assertEquals("{\"a\": \"$HOME\"}\n\\n `x`\n", new String(c.stdin(), StandardCharsets.UTF_8));
        assertEquals(0, lossy(r));
        assertEquals(1, r.commands().size());
        r = tok("curl <<\"EOF\"\n$x\nEOF");
        assertEquals("$x\n", new String(r.commands().get(0).stdin(), StandardCharsets.UTF_8));
        r = tok("curl <<E\\OF\n$x\nEOF");
        assertEquals("$x\n", new String(r.commands().get(0).stdin(), StandardCharsets.UTF_8));
    }

    @Test
    void heredocUnquotedProcessesEscapesAndWarns() throws Exception {
        TokenizeResult r = tok("curl -d @- <<EOF\na \\$x \\\\ \\` b\\\nc \\q\nEOF\n");
        assertEquals("a $x \\ ` bc \\q\n", new String(r.commands().get(0).stdin(), StandardCharsets.UTF_8));
        assertEquals(0, lossy(r));
        r = tok("curl -d @- <<EOF\nhello $USER and ${X} $(id) `id`\nEOF\n");
        assertEquals("hello $USER and ${X} $(id) `id`\n",
                new String(r.commands().get(0).stdin(), StandardCharsets.UTF_8));
        assertTrue(lossy(r) >= 1);
    }

    @Test
    void heredocStripTabs() throws Exception {
        CommandLine c = tok("curl <<-EOF\n\t\tone\n\ttwo\n\tEOF\n").commands().get(0);
        assertEquals("one\ntwo\n", new String(c.stdin(), StandardCharsets.UTF_8));
        c = tok("curl <<EOF\n\tone\n\tEOF\nEOF\n").commands().get(0);
        assertEquals("\tone\n\tEOF\n", new String(c.stdin(), StandardCharsets.UTF_8));
    }

    @Test
    void heredocThenPipeAndNextCommand() throws Exception {
        TokenizeResult r = tok("curl -d @- <<EOF | jq .\nbody\nEOF\ncurl second\n");
        assertEquals(3, r.commands().size());
        assertEquals("body\n", new String(r.commands().get(0).stdin(), StandardCharsets.UTF_8));
        assertNull(r.commands().get(1).stdin());
        assertEquals(List.of("curl", "second"), argv(r.commands().get(2)));
    }

    @Test
    void heredocTerminatorAtEofWithoutNewline() throws Exception {
        CommandLine c = tok("curl <<EOF\nx\nEOF").commands().get(0);
        assertEquals("x\n", new String(c.stdin(), StandardCharsets.UTF_8));
    }

    @Test
    void comments() throws Exception {
        TokenizeResult r = tok("# first\ncurl a #trailing comment\n#another\ncurl b#notcomment");
        assertEquals(2, r.commands().size());
        assertEquals(List.of("curl", "a"), argv(r.commands().get(0)));
        assertEquals(List.of("curl", "b#notcomment"), argv(r.commands().get(1)));
        assertEquals(List.of("curl", "#x"), one("curl '#x'"));
        assertEquals(List.of("curl", "#x"), one("curl \\#x"));
    }

    @Test
    void promptStripping() throws Exception {
        assertEquals(List.of("curl", "x"), one("$ curl x"));
        assertEquals(List.of("curl", "x"), one("  % curl x"));
        assertEquals(List.of("$x"), one("$x"));
    }

    @Test
    void bomAndCrlf() throws Exception {
        assertEquals(List.of("curl", "a", "b"), one("\uFEFFcurl a \\\r\n b\r\n"));
        assertEquals(List.of("curl", "a", "b"), one("curl a \\\r b"));
        assertEquals(2, tok("curl a\r\ncurl b").commands().size());
        assertEquals(List.of("curl", "x\ny"), one("curl 'x\r\ny'"));
    }

    @Test
    void nbspIsWhitespaceOutsideQuotes() throws Exception {
        assertEquals(List.of("curl", "a", "b"), one("curl\u00a0a\u00a0\u00a0b"));
        assertEquals(List.of("curl", "a\u00a0b"), one("curl 'a\u00a0b'"));
    }

    @Test
    void curlyQuotes() throws Exception {
        TokenizeResult r = tok("curl \u2018https://x/a b\u2019 -H \u201cX: y\u201d");
        assertEquals(List.of("curl", "https://x/a b", "-H", "X: y"), argv(r.commands().get(0)));
        assertEquals(1, notes(r));
        assertTrue(r.commands().get(0).argv().get(1).quoted());
        // curly inside regular quotes are literal
        r = tok("curl 'it\u2019s' \"\u201cq\u201d\"");
        assertEquals(List.of("curl", "it\u2019s", "\u201cq\u201d"), argv(r.commands().get(0)));
        assertEquals(0, notes(r));
        assertEquals(List.of("curl", "a\"b"), one("curl \u201ca\"b\u201d"));
    }

    @Test
    void newlineWithoutBackslashBeforeDash() throws Exception {
        TokenizeResult r = tok("curl http://x\n  -H 'a: b'\n\n  --compressed\ncurl http://y");
        assertEquals(2, r.commands().size());
        assertEquals(List.of("curl", "http://x", "-H", "a: b", "--compressed"), argv(r.commands().get(0)));
        assertEquals(1, notes(r));
        assertEquals(2, tok("curl a\ncurl b").commands().size());
        assertEquals(0, notes(tok("curl a\ncurl b")));
    }

    @Test
    void backslashSpacesNewlineIsContinuation() throws Exception {
        TokenizeResult r = tok("curl a \\  \n  b \\\t\n c");
        assertEquals(List.of("curl", "a", "b", "c"), argv(r.commands().get(0)));
        assertEquals(1, notes(r));
        assertEquals(List.of("curl", "a b"), one("curl a\\ b"));
    }

    @Test
    void continuationRules() throws Exception {
        assertEquals(List.of("curl", "ab"), one("curl a\\\nb"));
        assertEquals(List.of("curl", "a", "b"), one("curl a\\\n b"));
        assertEquals(List.of("curl", "a b"), one("curl \"a \\\nb\""));
        assertEquals(List.of("curl", "a\\\nb"), one("curl 'a\\\nb'"));
    }

    @Test
    void trailingBackslashKept() throws Exception {
        assertEquals(List.of("curl", "a\\"), one("curl a\\"));
    }

    @Test
    void multipleCurls() throws Exception {
        TokenizeResult r = tok("curl a\ncurl b; curl c");
        assertEquals(3, r.commands().size());
    }

    @Test
    void unicodeLiteral() throws Exception {
        assertEquals(List.of("curl", "h\u00e9llo-\u4e16\u754c-\uD83D\uDE00"), one("curl h\u00e9llo-\u4e16\u754c-\uD83D\uDE00"));
    }
}
