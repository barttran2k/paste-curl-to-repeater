package burp.curl.browser;

import static org.junit.jupiter.api.Assertions.assertEquals;

import burp.curl.CommandLine;
import burp.curl.Curl;
import burp.curl.PosixTokenizer;
import burp.curl.Token;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * Regression tests for shell grouping: unquoted ( ) of a subshell and { } of a brace group are not part of words.
 * Real bash 5.3: {@code (echo x)}, {@code ( echo x )}, {@code { echo x; }}, {@code echo hi | (cat)} all run echo;
 * {@code echo http://h/a(b)} is a syntax error in bash, which we read leniently as a single word.
 */
class PosixTokenizerGroupingTest {

    private static List<List<String>> cmds(String text) throws Exception {
        List<List<String>> out = new ArrayList<>();
        for (CommandLine c : new PosixTokenizer().tokenize(text).commands()) {
            List<String> a = new ArrayList<>();
            for (Token t : c.argv()) {
                a.add(t.text());
            }
            out.add(a);
        }
        return out;
    }

    @Test
    void subshellParens() throws Exception {
        assertEquals(List.of(List.of("curl", "-s", "http://h/sub")), cmds("(curl -s http://h/sub)"));
        assertEquals(List.of(List.of("curl", "-s", "http://h/sub")), cmds("( curl -s http://h/sub )"));
        assertEquals(List.of(List.of("curl", "http://h/a"), List.of("curl", "http://h/b")),
                cmds("(curl http://h/a; curl http://h/b)"));
        assertEquals(List.of(List.of("echo", "hi"), List.of("curl", "http://h/")), cmds("echo hi | (curl http://h/)"));
        assertEquals(List.of(List.of("curl", "http://h/")), cmds("(\ncurl http://h/\n)"));
    }

    @Test
    void closingParenGluedToTheLastWord() throws Exception {
        assertEquals(List.of(List.of("curl", "-s", "http://h/sub")), cmds("(curl -s http://h/sub)"));
        assertEquals(List.of(List.of("curl", "http://h/a(b)")), cmds("(curl http://h/a(b))"));
        assertEquals(List.of(List.of("curl", "http://h/a(b)c(d)")), cmds("( curl http://h/a(b)c(d) )"));
        assertEquals(List.of(List.of("curl", "-H", "X: )", "http://h/")), cmds("(curl -H 'X: )' http://h/)"));
        assertEquals(List.of(List.of("curl", "http://h/x"), List.of("curl", "http://h/y")),
                cmds("(curl http://h/x); (curl http://h/y)"));
        assertEquals(List.of(List.of("curl", "http://h/a)b")), cmds("curl http://h/a)b"));
    }

    @Test
    void braceGroup() throws Exception {
        assertEquals(List.of(List.of("curl", "http://h/")), cmds("{ curl http://h/; }"));
        assertEquals(List.of(List.of("curl", "http://h/")), cmds("{ curl http://h/ ; }"));
        assertEquals(List.of(List.of("curl", "http://h/")), cmds("{\n  curl http://h/\n}"));
        assertEquals(List.of(List.of("curl", "-g", "http://h/{id}")), cmds("{ curl -g http://h/{id}; }"));
    }

    @Test
    void parensInsideWordsAndQuotesAreKept() throws Exception {
        assertEquals(List.of(List.of("curl", "http://h/a(b)")), cmds("curl http://h/a(b)"));
        assertEquals(List.of(List.of("curl", "http://h/a(b)c")), cmds("curl http://h/a(b)c"));
        assertEquals(List.of(List.of("curl", "(x)")), cmds("curl '(x)'"));
        assertEquals(List.of(List.of("curl", "-d", "(a)", "http://h/")), cmds("curl -d \"(a)\" http://h/"));
        assertEquals(List.of(List.of("curl", "-H", "X: (v)", "http://h/")), cmds("curl -H 'X: (v)' http://h/"));
        assertEquals(List.of(List.of("curl", "-d", "(", "http://h/")), cmds("curl -d \\( http://h/"));
        assertEquals(List.of(List.of("curl", "{", "http://h/")), cmds("curl '{' http://h/"));
    }

    @Test
    void expansionsStillKeptVerbatim() throws Exception {
        assertEquals(List.of(List.of("curl", "-d", "$(echo hi)", "http://h/")), cmds("curl -d $(echo hi) http://h/"));
        assertEquals(List.of(List.of("curl", "-d", "$((1+2))", "http://h/")), cmds("curl -d $((1+2)) http://h/"));
        assertEquals(List.of(List.of("curl", "-d", "@<(echo hi)", "http://h/")),
                cmds("curl -d @<(echo hi) http://h/"));
        assertEquals(List.of(List.of("curl", "-d", "<(echo )", "http://h/")), cmds("curl -d <(echo ) http://h/"));
        assertEquals(List.of(List.of("curl", "-d", "$(echo ')')", "http://h/")), cmds("curl -d $(echo ')') http://h/"));
    }

    @Test
    void parseFindsCurlInGroups() throws Exception {
        assertEquals(1, Curl.parse("(curl -s http://h/sub)").build(burp.curl.FileAccess.DENY).size());
        assertEquals(1, Curl.parse("{ curl -s http://h/sub; }").build(burp.curl.FileAccess.DENY).size());
    }
}
