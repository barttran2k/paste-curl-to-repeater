package burp.curl;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import org.junit.jupiter.api.Test;

/** The curl word must be the command word: only assignments and known wrappers may precede it. */
class CurlSelectionTest {
    private static List<BuiltRequest> build(String text) throws Exception {
        return Curl.parse(text).build(FileAccess.DENY);
    }

    @Test
    void wordsThatMerelyMentionCurlAreNotCurlCommands() {
        for (String c : new String[] {"echo curl http://h/x", "man curl", "brew install curl", "which curl",
                "apt-get install curl http://h/x", "cat curl.txt", "command -v curl", "type curl",
                "ls /usr/bin/curl"}) {
            assertThrows(CurlParseException.class, () -> Curl.parse(c), c);
        }
    }

    @Test
    void wrappersAndAssignmentsMayPrecedeCurl() throws Exception {
        for (String c : new String[] {"sudo curl http://h/x", "sudo -u root curl http://h/x", "sudo -E -n curl http://h/x",
                "env A=1 B=2 curl http://h/x", "env -i curl http://h/x", "env -u HOME curl http://h/x",
                "time curl http://h/x", "time -p curl http://h/x", "nohup curl http://h/x", "command curl http://h/x",
                "command -p curl http://h/x", "exec curl http://h/x", "nice curl http://h/x",
                "nice -n 10 curl http://h/x", "noglob curl http://h/x", "winpty curl http://h/x",
                "proxychains curl http://h/x", "proxychains4 -q curl http://h/x", "torsocks curl http://h/x",
                "A=1 sudo env B=2 nohup curl http://h/x", "/usr/local/bin/curl http://h/x",
                "if curl http://h/x; then echo ok; fi", "! curl http://h/x", "sudo -- curl http://h/x"}) {
            List<BuiltRequest> r = build(c);
            assertEquals(1, r.size(), c);
            assertEquals("http://h/x", r.get(0).url(), c);
        }
    }

    @Test
    void anUnknownCommandInFrontOfCurlHidesIt() {
        for (String c : new String[] {"xargs curl http://h/x", "watch curl http://h/x", "ssh host curl http://h/x",
                "docker run curl http://h/x", "timeout 5 curl http://h/x", "echo hi curl http://h/x"}) {
            assertThrows(CurlParseException.class, () -> Curl.parse(c), c);
        }
    }

    @Test
    void otherCommandsOfThePasteAreIgnored() throws Exception {
        List<BuiltRequest> r = build("echo curl x && curl http://h/a; which curl\nman curl\ncurl http://h/b");
        assertEquals(List.of("http://h/a", "http://h/b"), r.stream().map(BuiltRequest::url).toList());
    }

    @Test
    void aCurlWithoutUrlIsSkippedWithANoteWhenAnotherCommandProducedRequests() throws Exception {
        ParsedCurl p = Curl.parse("curl -s -X POST\ncurl http://h/b");
        assertEquals(1, p.build(FileAccess.DENY).size());
        assertTrue(p.warnings().stream().anyMatch(w -> w.severity() == Warning.Severity.NOTE
                && w.message().contains("without a URL")), p.warnings().toString());
    }

    @Test
    void nothingProducingARequestIsAnError() {
        CurlParseException e = assertThrows(CurlParseException.class, () -> Curl.parse("curl -s -X POST"));
        assertTrue(e.getMessage().contains("URL"), e.getMessage());
        CurlParseException e2 = assertThrows(CurlParseException.class, () -> Curl.parse("echo hello"));
        assertTrue(e2.getMessage().contains("curl"), e2.getMessage());
    }

    @Test
    void aBrokenCurlIsSkippedWhenAnotherOneWorks() throws Exception {
        ParsedCurl p = Curl.parse("curl http://h/a -d\ncurl http://h/b");
        List<BuiltRequest> r = p.build(FileAccess.DENY);
        assertEquals(1, r.size());
        assertTrue(p.warnings().stream().anyMatch(w -> w.severity() == Warning.Severity.LOSSY
                && w.message().contains("skipped")), p.warnings().toString());
    }

    @Test
    void pastesThatStartWithOptionsOrAUrlStillWork() throws Exception {
        assertEquals("http://h/x", build("-X POST http://h/x -d a=1").get(0).url());
        assertEquals("http://h/x", build("http://h/x").get(0).url());
        assertEquals("http://h/x", build("A=1 -s http://h/x").get(0).url());
    }
}
