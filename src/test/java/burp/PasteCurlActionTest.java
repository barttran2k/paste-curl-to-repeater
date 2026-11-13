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
            public PasteCurlAction.FileChoice confirmFiles(List<PasteCurlAction.FileInfo> f, String home) {
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
    void parseErrorWithPositionShowsLineColumnAndMaskedExcerpt() {
        clipboard = "curl 'https://example.com -H x";
        action.run();
        assertTrue(sent.isEmpty());
        assertEquals(1, errors.size());
        String m = errors.get(0);
        assertTrue(m.contains("Unterminated"), m);
        assertTrue(m.contains("Near line 1, column 6"), m);
        assertTrue(m.contains("\u00b7\u00b7\u00b7\u00b7  >>HERE<< '\u00b7\u00b7\u00b7\u00b7\u00b7"), m);
        assertFalse(m.contains("example"), m);
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
            public PasteCurlAction.FileChoice confirmFiles(List<PasteCurlAction.FileInfo> f, String home) {
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

    @Test
    void nothingFromTheCommandReachesTheLogEvenForWarningsAndErrors() {
        String[] commands = {
            "curl -F '" + SECRET + "' -u " + SECRET + " -z " + SECRET + " -H '" + SECRET + ": " + SECRET + "' "
                    + "-d \"$(echo " + SECRET + ")\" https://example.com/ --unknown-x=" + SECRET,
            "curl https://example.com/ ; curl ftp://" + SECRET + ".example/x",
            "curl -d '" + SECRET,
            "curl --digest -u " + SECRET + ":" + SECRET + " --proxy http://" + SECRET + "@p.example:1 https://e.com/",
        };
        for (String c : commands) {
            clipboard = c;
            action.run();
        }
        assertFalse(sent.isEmpty());
        for (String line : logOut) {
            assertFalse(line.contains(SECRET), line);
        }
        assertTrue(logErr.isEmpty(), logErr.toString());
    }

    @Test
    void aBadUrlDoesNotStopTheOtherRequests() {
        clipboard = "curl https://ok.example/a ; curl ftp://x.example/f";
        action.run();
        assertEquals(1, sent.size());
        assertTrue(errors.isEmpty(), errors.toString());
        assertEquals(1, warnings.size());
        assertTrue(warnings.get(0).contains("skipped"), warnings.get(0));
    }

    @Test
    void theDialogNamesTheDirectoryOfTheProbeThatResolvesThePaths() {
        List<String> homes = new ArrayList<>();
        PasteCurlAction.FileProbe probe = new PasteCurlAction.FileProbe() {
            public PasteCurlAction.FileInfo describe(String p) {
                return new PasteCurlAction.FileInfo(p, "/probe-home/" + p, "found, 1 bytes");
            }

            public String homeDirectory() {
                return "/probe-home";
            }
        };
        PasteCurlAction a = new PasteCurlAction(() -> "curl https://example.com/ -d @x.json", new PasteCurlAction.Dialogs() {
            public void info(String t, String m) { }
            public void error(String t, String m) { }
            public void warning(String t, String m) { }
            public PasteCurlAction.FileChoice confirmFiles(List<PasteCurlAction.FileInfo> f, String home) {
                homes.add(home);
                return PasteCurlAction.FileChoice.CANCEL;
            }
        }, (r, t) -> fail("must not send"), new PasteCurlAction.Log() {
            public void output(String m) { }
            public void error(Throwable t) { }
        }, probe, () -> FileAccess.DENY);
        a.run();
        assertEquals(List.of("/probe-home"), homes);
    }

    @org.junit.jupiter.api.io.TempDir
    java.nio.file.Path tmpHome;
    @org.junit.jupiter.api.io.TempDir
    java.nio.file.Path tmpOther;

    @Test
    void symlinkedFileIsShownWithItsRealTargetAndThatIsWhatIsSent() throws Exception {
        java.nio.file.Path secret = tmpOther.resolve("id_rsa");
        java.nio.file.Files.writeString(secret, "PRIVATE-KEY");
        try {
            java.nio.file.Files.createSymbolicLink(tmpHome.resolve("body.json"), secret);
        } catch (UnsupportedOperationException | IOException e) {
            org.junit.jupiter.api.Assumptions.assumeTrue(false, "no symlinks: " + e);
        }
        LocalFiles lf = new LocalFiles(tmpHome);
        List<String> dialogText = new ArrayList<>();
        List<BuiltRequest> out = new ArrayList<>();
        PasteCurlAction a = new PasteCurlAction(() -> "curl --data-binary @~/body.json https://t.example/", new PasteCurlAction.Dialogs() {
            public void info(String t, String m) { }
            public void error(String t, String m) { }
            public void warning(String t, String m) { }
            public PasteCurlAction.FileChoice confirmFiles(List<PasteCurlAction.FileInfo> f, String home) {
                dialogText.add(SwingDialogs.fileConfirmationText(f, home));
                return PasteCurlAction.FileChoice.READ_FILES;
            }
        }, (r, t) -> out.add(r), new PasteCurlAction.Log() {
            public void output(String m) { }
            public void error(Throwable t) { }
        }, lf, () -> lf);
        a.run();
        assertEquals(1, dialogText.size());
        assertTrue(dialogText.get(0).contains("Symbolic link to: " + secret.toRealPath()), dialogText.get(0));
        assertEquals(1, out.size());
        assertTrue(raw(out.get(0)).endsWith("PRIVATE-KEY"));
    }

    @Test
    void aSwapBetweenTheDialogAndTheReadGivesAPlaceholderAndAWarning() throws Exception {
        java.nio.file.Path safe = tmpOther.resolve("safe.json");
        java.nio.file.Files.writeString(safe, "SAFE");
        java.nio.file.Path secret = tmpOther.resolve("id_rsa");
        java.nio.file.Files.writeString(secret, "PRIVATE-KEY");
        java.nio.file.Path l = tmpHome.resolve("body.json");
        try {
            java.nio.file.Files.createSymbolicLink(l, safe);
        } catch (UnsupportedOperationException | IOException e) {
            org.junit.jupiter.api.Assumptions.assumeTrue(false, "no symlinks: " + e);
        }
        LocalFiles lf = new LocalFiles(tmpHome);
        List<BuiltRequest> out = new ArrayList<>();
        List<String> warn = new ArrayList<>();
        PasteCurlAction a = new PasteCurlAction(() -> "curl --data-binary @~/body.json https://t.example/", new PasteCurlAction.Dialogs() {
            public void info(String t, String m) { }
            public void error(String t, String m) { }
            public void warning(String t, String m) { warn.add(m); }
            public PasteCurlAction.FileChoice confirmFiles(List<PasteCurlAction.FileInfo> f, String home) {
                try {
                    java.nio.file.Files.delete(l);
                    java.nio.file.Files.createSymbolicLink(l, secret);
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
                return PasteCurlAction.FileChoice.READ_FILES;
            }
        }, (r, t) -> out.add(r), new PasteCurlAction.Log() {
            public void output(String m) { }
            public void error(Throwable t) { }
        }, lf, () -> lf);
        a.run();
        assertEquals(1, out.size());
        assertFalse(raw(out.get(0)).contains("PRIVATE-KEY"));
        assertTrue(raw(out.get(0)).contains("<<FILE: ~/body.json>>"), raw(out.get(0)));
        assertEquals(1, warn.size());
    }

    @Test
    void clipboardTextOverTheLimitIsRefusedBeforeParsing() {
        assertEquals(10 * 1024 * 1024, PasteCurlAction.MAX_CLIPBOARD_CHARS);
        clipboard = "curl https://example.com/ -d '" + "x".repeat(PasteCurlAction.MAX_CLIPBOARD_CHARS) + "'";
        action.run();
        assertTrue(sent.isEmpty());
        assertEquals(1, errors.size());
        assertTrue(errors.get(0).contains("too large"), errors.get(0));
        assertFalse(errors.get(0).contains("xxxxxxxx"));
    }

    @Test
    void clipboardTextAtTheLimitIsStillParsed() {
        String head = "curl https://example.com/ -d '";
        clipboard = head + "x".repeat(PasteCurlAction.MAX_CLIPBOARD_CHARS - head.length() - 1) + "'";
        assertEquals(PasteCurlAction.MAX_CLIPBOARD_CHARS, clipboard.length());
        action.run();
        assertEquals(1, sent.size(), errors.toString());
    }

    @Test
    void theSuppliedBrowserUserAgentIsSentAndTheNoteGoesOnlyToTheLog() {
        PasteCurlAction a = new PasteCurlAction(() -> "curl https://t.example/", new PasteCurlAction.Dialogs() {
            public void info(String t, String m) { infos.add(m); }
            public void error(String t, String m) { errors.add(m); }
            public void warning(String t, String m) { warnings.add(m); }
            public PasteCurlAction.FileChoice confirmFiles(List<PasteCurlAction.FileInfo> f, String home) {
                return PasteCurlAction.FileChoice.CANCEL;
            }
        }, (r, t) -> sent.add(r), new PasteCurlAction.Log() {
            public void output(String m) { logOut.add(m); }
            public void error(Throwable t) { logErr.add(t); }
        }, p -> new PasteCurlAction.FileInfo(p, p, "x"), () -> FileAccess.DENY,
                () -> new burp.curl.CurlSettings(BrowserUserAgent.userAgent(BrowserUserAgent.Os.LINUX, 142),
                        "User-Agent set to a browser value (Chrome 142, version of the installed Chrome); curl itself would send its own curl/x.y.z"));
        a.run();
        assertEquals(1, sent.size());
        assertTrue(raw(sent.get(0)).contains("User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                + "(KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36\r\nAccept: */*\r\n"), raw(sent.get(0)));
        assertTrue(logOut.contains("NOTE: User-Agent set to a browser value (Chrome 142, version of the installed "
                + "Chrome); curl itself would send its own curl/x.y.z"), logOut.toString());
        // the core default is untouched
        assertEquals("curl/8.7.1", burp.curl.CurlSettings.DEFAULT_USER_AGENT);
        assertTrue(warnings.isEmpty() && errors.isEmpty() && infos.isEmpty());
    }

    @Test
    void withoutASettingsSupplierTheOldBehaviourHolds() {
        clipboard = "curl https://t.example/";
        action.run();
        assertTrue(raw(sent.get(0)).contains("User-Agent: curl/8.7.1\r\n"));
        assertTrue(logOut.stream().noneMatch(l -> l.contains("User-Agent")), logOut.toString());
    }
}
