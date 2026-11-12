package burp;

import burp.curl.BuiltRequest;
import burp.curl.FileAccess;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Supplier;

import static org.junit.jupiter.api.Assertions.*;

class PasteCurlActionTest {
    static final String SECRET = "s3cr3t-token-XYZ";

    String clipboard;
    RuntimeException clipboardFailure;
    PasteCurlAction.FileChoice choice = PasteCurlAction.FileChoice.READ_FILES;
    final List<String> events = new ArrayList<>();
    final List<String> infos = new ArrayList<>();
    final List<String> errors = new ArrayList<>();
    final List<String> warnings = new ArrayList<>();
    final List<List<PasteCurlAction.FileInfo>> confirmations = new ArrayList<>();
    final List<BuiltRequest> sent = new ArrayList<>();
    final List<String> tabs = new ArrayList<>();
    final List<String> logOut = new ArrayList<>();
    final List<Throwable> logErr = new ArrayList<>();
    final List<String> filesRead = new ArrayList<>();
    int realFilesCreated;
    RuntimeException sinkFailure;

    PasteCurlAction action;

    @BeforeEach
    void setUp() {
        PasteCurlAction.Dialogs dialogs = new PasteCurlAction.Dialogs() {
            public void info(String t, String m) { infos.add(m); events.add("info"); }
            public void error(String t, String m) { errors.add(m); events.add("error"); }
            public void warning(String t, String m) { warnings.add(t + "\n" + m); events.add("warning"); }
            public PasteCurlAction.FileChoice confirmFiles(List<PasteCurlAction.FileInfo> f) {
                confirmations.add(f);
                events.add("confirm");
                return choice;
            }
        };
        PasteCurlAction.RequestSink sink = (r, tab) -> {
            if (sinkFailure != null) throw sinkFailure;
            sent.add(r);
            tabs.add(tab);
            events.add("send");
        };
        PasteCurlAction.Log log = new PasteCurlAction.Log() {
            public void output(String m) { logOut.add(m); }
            public void error(Throwable t) { logErr.add(t); }
        };
        PasteCurlAction.FileProbe probe = p -> new PasteCurlAction.FileInfo(p, "/abs/" + p, "found, 3 bytes");
        Supplier<FileAccess> real = () -> {
            realFilesCreated++;
            return p -> {
                filesRead.add(p);
                return "FILEDATA".getBytes(StandardCharsets.UTF_8);
            };
        };
        action = new PasteCurlAction(() -> {
            if (clipboardFailure != null) throw clipboardFailure;
            return clipboard;
        }, dialogs, sink, log, probe, real);
    }

    static String raw(BuiltRequest r) {
        return new String(r.raw(), StandardCharsets.ISO_8859_1);
    }

    @Test
    void emptyClipboardShowsInfo() {
        clipboard = "   ";
        action.run();
        assertEquals(1, infos.size());
        assertTrue(sent.isEmpty());
        assertTrue(errors.isEmpty());
    }

    @Test
    void nonTextClipboardShowsInfo() {
        clipboard = null;
        action.run();
        assertEquals(1, infos.size());
        assertTrue(sent.isEmpty());
    }

    @Test
    void parseErrorWithoutPosition() {
        clipboard = "curl https://e.com -H";
        action.run();
        assertTrue(sent.isEmpty());
        assertEquals(1, errors.size(), errors.toString());
        assertFalse(errors.get(0).contains("Near character"));
    }

    @Test
    void parseErrorWithPositionShowsExcerpt() {
        clipboard = "curl 'https://example.com -H x";
        action.run();
        assertTrue(sent.isEmpty());
        assertEquals(1, errors.size());
        String m = errors.get(0);
        assertTrue(m.contains("Unterminated"), m);
        assertTrue(m.contains("Near character 5"), m);
        assertTrue(m.contains("curl  >>HERE<< 'https://example.com -H x"), m);
    }

    @Test
    void excerptMarksPositionAndFlattensNewlines() {
        String text = "a".repeat(50) + "\nBAD\n" + "b".repeat(50);
        String ex = PasteCurlAction.excerpt(text, 51);
        assertTrue(ex.startsWith("..."));
        assertTrue(ex.endsWith("..."));
        assertTrue(ex.contains(" >>HERE<< BAD"), ex);
        assertFalse(ex.contains("\n"));
        assertEquals("x >>HERE<< ", PasteCurlAction.excerpt("x", 99));
        assertEquals(" >>HERE<< xy", PasteCurlAction.excerpt("xy", -5));
    }

    @Test
    void mustPassFlowWithRealCore() {
        clipboard = "curl 'https://api.example.com/v1/users/42?expand=roles' -X 'PUT' -H 'content-type: application/json' "
                + "-b 'session=abc' --data-raw $'{\"name\":\"O\\'Brien\"}' --compressed";
        action.run();
        assertEquals(1, sent.size(), events.toString());
        BuiltRequest r = sent.get(0);
        assertTrue(r.secure());
        assertEquals("api.example.com", r.host());
        assertEquals(443, r.port());
        String raw = raw(r);
        assertTrue(raw.startsWith("PUT /v1/users/42?expand=roles HTTP/1.1\r\nHost: api.example.com\r\n"), raw);
        assertTrue(raw.endsWith("{\"name\":\"O'Brien\"}"), raw);
        assertNull(tabs.get(0));
        assertTrue(errors.isEmpty() && infos.isEmpty() && warnings.isEmpty() && confirmations.isEmpty());
    }

    @Test
    void fileConfirmationReadFiles() {
        clipboard = "curl https://example.com/ --data-binary @payload.bin";
        choice = PasteCurlAction.FileChoice.READ_FILES;
        action.run();
        assertEquals(1, confirmations.size());
        assertEquals("payload.bin", confirmations.get(0).get(0).written());
        assertEquals("/abs/payload.bin", confirmations.get(0).get(0).resolved());
        assertEquals(1, realFilesCreated);
        assertEquals(List.of("payload.bin"), filesRead);
        assertEquals(1, sent.size());
        assertTrue(raw(sent.get(0)).endsWith("FILEDATA"));
        assertTrue(events.indexOf("confirm") < events.indexOf("send"));
    }

    @Test
    void fileConfirmationPlaceholders() {
        clipboard = "curl https://example.com/ --data-binary @payload.bin";
        choice = PasteCurlAction.FileChoice.USE_PLACEHOLDERS;
        action.run();
        assertEquals(0, realFilesCreated);
        assertTrue(filesRead.isEmpty());
        assertEquals(1, sent.size());
        assertTrue(raw(sent.get(0)).contains("<<FILE: payload.bin>>"), raw(sent.get(0)));
        assertEquals(1, warnings.size(), "placeholder is LOSSY");
    }

    @Test
    void fileConfirmationCancel() {
        clipboard = "curl https://example.com/ --data-binary @payload.bin";
        choice = PasteCurlAction.FileChoice.CANCEL;
        action.run();
        assertEquals(0, realFilesCreated);
        assertTrue(filesRead.isEmpty());
        assertTrue(sent.isEmpty());
        assertTrue(errors.isEmpty());
    }

    @Test
    void noFileReadBeforeChoice() {
        clipboard = "curl https://example.com/ --data-binary @payload.bin";
        // the confirmation sees the state when it is shown
        PasteCurlAction a = new PasteCurlAction(() -> clipboard, new PasteCurlAction.Dialogs() {
            public void info(String t, String m) { }
            public void error(String t, String m) { }
            public void warning(String t, String m) { }
            public PasteCurlAction.FileChoice confirmFiles(List<PasteCurlAction.FileInfo> f) {
                assertEquals(0, realFilesCreated);
                assertTrue(filesRead.isEmpty());
                return PasteCurlAction.FileChoice.CANCEL;
            }
        }, (r, t) -> fail("must not send"), new PasteCurlAction.Log() {
            public void output(String m) { }
            public void error(Throwable t) { }
        }, p -> new PasteCurlAction.FileInfo(p, p, "x"), () -> {
            realFilesCreated++;
            return FileAccess.DENY;
        });
        a.run();
        assertEquals(0, realFilesCreated);
    }

    @Test
    void severalRequestsGetTabNames() {
        clipboard = "curl https://a.example/1 --next https://b.example/2 --next https://c.example/3";
        action.run();
        assertEquals(3, sent.size());
        assertEquals(List.of("curl 1/3", "curl 2/3", "curl 3/3"), tabs);
    }

    @Test
    void tabCapAtTwenty() {
        StringBuilder sb = new StringBuilder("curl https://h0.example/");
        for (int i = 1; i < 25; i++) sb.append(" --next https://h").append(i).append(".example/");
        clipboard = sb.toString();
        action.run();
        assertEquals(20, sent.size());
        assertEquals("curl 1/20", tabs.get(0));
        assertEquals("curl 20/20", tabs.get(19));
        String all = String.join("\n", infos) + String.join("\n", warnings);
        assertTrue(all.contains("25") && all.contains("20"), all);
        assertTrue(logOut.stream().anyMatch(l -> l.contains("only the first 20")));
    }

    @Test
    void lossyShownNoteLoggedOnlyAndDeduplicated() {
        // -K is not read (LOSSY or NOTE depending on core); use a command known to produce a LOSSY placeholder
        clipboard = "curl https://example.com/ -d @a.txt -d @a.txt";
        choice = PasteCurlAction.FileChoice.USE_PLACEHOLDERS;
        action.run();
        assertEquals(1, warnings.size());
        long dupes = warnings.get(0).lines().filter(l -> l.startsWith("- ")).count();
        long distinct = warnings.get(0).lines().filter(l -> l.startsWith("- ")).distinct().count();
        assertEquals(distinct, dupes, warnings.get(0));
        assertTrue(logOut.stream().anyMatch(l -> l.startsWith("LOSSY: ")));
    }

    @Test
    void noteOnlyDoesNotOpenDialog() {
        clipboard = "curl https://example.com/ --compressed";
        action.run();
        assertTrue(warnings.isEmpty());
        assertEquals(1, sent.size());
    }

    @Test
    void sinkFailureShowsErrorAndLogs() {
        clipboard = "curl https://example.com/";
        sinkFailure = new IllegalStateException("boom");
        action.run();
        assertEquals(1, errors.size());
        assertEquals(1, logErr.size());
        assertSame(sinkFailure, logErr.get(0));
    }

    @Test
    void clipboardFailureShowsErrorAndLogs() {
        clipboardFailure = new IllegalStateException("clipboard busy");
        action.run();
        assertEquals(1, errors.size());
        assertTrue(errors.get(0).contains("clipboard busy"));
        assertEquals(1, logErr.size());
    }

    @Test
    void nothingSensitiveIsLogged() {
        clipboard = "curl 'https://example.com/path?k=" + SECRET + "' -H 'Authorization: Bearer " + SECRET
                + "' -b 'sid=" + SECRET + "' --data-raw '{\"p\":\"" + SECRET + "\"}' --next https://x.example/ -d @f.txt";
        choice = PasteCurlAction.FileChoice.USE_PLACEHOLDERS;
        action.run();
        assertEquals(2, sent.size());
        for (String l : logOut) {
            assertFalse(l.contains(SECRET), l);
        }
        assertTrue(logErr.isEmpty());
    }
}
