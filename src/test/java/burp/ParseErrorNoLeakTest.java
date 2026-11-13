package burp;

import burp.curl.BuiltRequest;
import burp.curl.FileAccess;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/** A unique marker in every argument position of broken commands never reaches a dialog or the log. */
class ParseErrorNoLeakTest {
    static final String M = "ZqMark7x91";

    static final String[] BROKEN = {
        "curl -H 'Authorization: Bearer @@",
        "curl -H \"X-Token: @@",
        "curl -H $'X-Token: @@",
        "curl -u @@:@@ 'https://h.test/@@",
        "curl -u '@@:@@ https://h.test/",
        "curl https://@@:@@@h.test/path?q=@@ -d '@@",
        "curl 'https://h.test/@@' -X @@ -d \"a=@@",
        "curl -b 'sid=@@; other=@@' -H 'Cookie: @@' --data-raw '@@",
        "curl --data-urlencode 'n=@@' -F 'f=@@' --url 'https://h.test/@@",
        "curl -H @@ https://h.test/ -H '@@: @@",
        "curl https://h.test/ -d @@ \\\n  -H 'k: @@' \\\n  --data '@@",
        "curl ^\"https://h.test/@@^\" -H ^\"X: @@^\" -d ^\"@@",
        "curl -d '@@' -H 'a: @@' https://h.test/ -H",
        "curl https://h.test/ -d @@ -d",
        "curl https://h.test/?@@ --header",
        "curl --user @@:@@ --proxy-user @@:@@ -x 'http://@@:@@@p.test:1 https://h.test/",
        "curl `echo @@ -H 'a: @@' https://h.test/",
        "curl -H \"a: $(echo @@\" https://h.test/",
        "echo @@; curl -H 'Authorization: @@' -d \"@@ https://h.test/",
        "curl --header='X: @@' -d='@@' 'https://h.test/@@",
    };

    @Test
    void theMarkerNeverAppearsInADialogOrTheLog() {
        int errorsSeen = 0;
        for (String template : BROKEN) {
            String command = template.replace("@@", M);
            List<String> shown = new ArrayList<>();
            List<String> logged = new ArrayList<>();
            PasteCurlAction.Dialogs dialogs = new PasteCurlAction.Dialogs() {
                public void info(String t, String m) { shown.add(t + "\n" + m); }
                public void error(String t, String m) { shown.add(t + "\n" + m); }
                public void warning(String t, String m) { shown.add(t + "\n" + m); }
                public PasteCurlAction.FileChoice confirmFiles(List<PasteCurlAction.FileInfo> f, String home) {
                    shown.add(SwingDialogs.fileConfirmationText(f, home));
                    return PasteCurlAction.FileChoice.USE_PLACEHOLDERS;
                }
            };
            PasteCurlAction.Log log = new PasteCurlAction.Log() {
                public void output(String m) { logged.add(m); }
                public void error(Throwable t) { logged.add(String.valueOf(t)); }
            };
            List<BuiltRequest> sent = new ArrayList<>();
            new PasteCurlAction(() -> command, dialogs, (r, t) -> sent.add(r), log,
                    p -> new PasteCurlAction.FileInfo(p, p, "x"), () -> FileAccess.DENY).run();
            assertFalse(shown.isEmpty(), "no dialog for: " + template);
            boolean parseError = shown.stream().anyMatch(s -> s.contains("cannot parse"));
            if (parseError) {
                errorsSeen++;
                assertTrue(shown.stream().anyMatch(s -> s.contains(">>HERE<<") || !s.contains("Near line")),
                        "no excerpt for: " + template);
            }
            for (String s : shown) {
                assertFalse(s.contains(M), "marker in a dialog for: " + template + "\n" + s);
            }
            for (String s : logged) {
                assertFalse(s.contains(M), "marker in the log for: " + template + "\n" + s);
            }
        }
        assertTrue(errorsSeen >= BROKEN.length / 2, "too few commands failed to parse: " + errorsSeen);
    }

    @Test
    void theExcerptOfAnUnterminatedQuoteHidesTheToken() {
        List<String> errs = new ArrayList<>();
        PasteCurlAction.Dialogs d = new PasteCurlAction.Dialogs() {
            public void info(String t, String m) { }
            public void error(String t, String m) { errs.add(m); }
            public void warning(String t, String m) { }
            public PasteCurlAction.FileChoice confirmFiles(List<PasteCurlAction.FileInfo> f, String h) {
                return PasteCurlAction.FileChoice.CANCEL;
            }
        };
        new PasteCurlAction(() -> "curl -H 'Authorization: Bearer SUPERSECRET", d, (r, t) -> { },
                new PasteCurlAction.Log() {
                    public void output(String m) { }
                    public void error(Throwable t) { }
                }, p -> new PasteCurlAction.FileInfo(p, p, "x"), () -> FileAccess.DENY).run();
        assertEquals(1, errs.size());
        assertFalse(errs.get(0).contains("SUPERSECRET"), errs.get(0));
        assertFalse(errs.get(0).contains("Bearer"), errs.get(0));
        assertTrue(errs.get(0).contains("line 1, column"), errs.get(0));
    }
}
