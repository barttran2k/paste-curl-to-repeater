package burp;

import burp.curl.BuiltRequest;
import burp.curl.Curl;
import burp.curl.CurlParseException;
import burp.curl.CurlSettings;
import burp.curl.FileAccess;
import burp.curl.ParsedCurl;
import burp.curl.Warning;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.function.Supplier;

/**
 * The whole "Paste cURL command" flow: clipboard, parse, file confirmation, build, send, warnings.
 *
 * <p>Depends only on the small interfaces declared here so it can be tested without Burp or Swing.
 * Call {@link #run()} on the thread that may show dialogs (the EDT). Parsing and building are cheap and run on
 * the same thread; to move them off the EDT later, split {@link #run()} at the dialog calls.
 *
 * <p>Nothing from the pasted command (headers, bodies, URLs) is ever written to the {@link Log}.
 */
public final class PasteCurlAction {
    /** Maximum number of Repeater tabs created by one paste. */
    public static final int MAX_TABS = 20;
    /** Maximum number of LOSSY warnings listed in the dialog. */
    public static final int MAX_LISTED_WARNINGS = 15;
    /** Largest clipboard text (in characters) that is parsed; anything bigger is refused before parsing. */
    public static final int MAX_CLIPBOARD_CHARS = 10 * 1024 * 1024;

    /** Title used by all dialogs. */
    public static final String TITLE = "Paste cURL";

    /** Source of the clipboard text. */
    public interface ClipboardSource {
        /** @return the clipboard text, or null when the clipboard holds no text */
        String text() throws Exception;
    }

    /** User choice in the file confirmation dialog. */
    public enum FileChoice { READ_FILES, USE_PLACEHOLDERS, CANCEL }

    /**
     * What is known about a local path named in the command.
     * @param written the path as written in the command
     * @param resolved the absolute path it resolves to, or a short reason when it cannot be resolved
     * @param status "found, N bytes", "not found", "too large (N bytes)", ...
     * @param symlinkTarget the real file behind {@code resolved} when a symbolic link (in the file or in a parent
     *                      directory) leads somewhere else; null when the path is its own real path
     */
    public record FileInfo(String written, String resolved, String status, String symlinkTarget) {
        /** A path without a symbolic link. */
        public FileInfo(String written, String resolved, String status) {
            this(written, resolved, status, null);
        }
    }

    /** Inspects paths without reading their content. */
    public interface FileProbe {
        /** @param path path as written in the command @return facts about it; must not read the content */
        FileInfo describe(String path);

        /**
         * @return the directory against which {@link #describe} resolves relative paths and {@code ~}, as shown in
         *         the confirmation dialog; null when the probe has no such notion
         */
        default String homeDirectory() {
            return null;
        }
    }

    /** User-facing dialogs. All calls happen on the thread that calls {@link #run()}. */
    public interface Dialogs {
        /** @param title dialog title @param message text */
        void info(String title, String message);

        /** @param title dialog title @param message text */
        void error(String title, String message);

        /** @param title dialog title @param message text */
        void warning(String title, String message);

        /**
         * @param files every path the command wants to read
         * @param home the directory relative paths are resolved against (from the same probe that produced
         *             {@code files}), or null
         * @return the user's choice
         */
        FileChoice confirmFiles(List<FileInfo> files, String home);
    }

    /** Receives finished requests. */
    public interface RequestSink {
        /** @param request the request @param tabName tab title, or null for the default naming */
        void send(BuiltRequest request, String tabName);
    }

    /** Extension log. */
    public interface Log {
        /** @param message a line for the extension output */
        void output(String message);

        /** @param t an unexpected failure */
        void error(Throwable t);
    }

    private final ClipboardSource clipboard;
    private final Dialogs dialogs;
    private final RequestSink sink;
    private final Log log;
    private final FileProbe probe;
    private final Supplier<FileAccess> realFiles;
    private final Supplier<CurlSettings> settings;

    /**
     * @param clipboard clipboard source
     * @param dialogs dialogs
     * @param sink request sink
     * @param log log
     * @param probe path inspector for the confirmation dialog
     * @param realFiles factory of the FileAccess used after the user chose "Read files"
     */
    public PasteCurlAction(ClipboardSource clipboard, Dialogs dialogs, RequestSink sink, Log log,
                           FileProbe probe, Supplier<FileAccess> realFiles) {
        this(clipboard, dialogs, sink, log, probe, realFiles, () -> CurlSettings.DEFAULTS);
    }

    /**
     * @param clipboard clipboard source
     * @param dialogs dialogs
     * @param sink request sink
     * @param log log
     * @param probe path inspector for the confirmation dialog
     * @param realFiles factory of the FileAccess used after the user chose "Read files"
     * @param settings supplies the build settings (default User-Agent); called once per paste, must not
     *                 block for long
     */
    public PasteCurlAction(ClipboardSource clipboard, Dialogs dialogs, RequestSink sink, Log log,
                           FileProbe probe, Supplier<FileAccess> realFiles, Supplier<CurlSettings> settings) {
        this.settings = settings;
        this.clipboard = clipboard;
        this.dialogs = dialogs;
        this.sink = sink;
        this.log = log;
        this.probe = probe;
        this.realFiles = realFiles;
    }

    /** Runs the flow once. Never throws. */
    public void run() {
        try {
            runUnchecked();
        } catch (Throwable t) {
            try {
                log.error(t);
            } catch (Throwable ignored) {
                // nothing left to do
            }
            try {
                dialogs.error(TITLE + " - unexpected error",
                        "Unexpected error: " + t + "\nNo request was sent. Details are in the extension's Errors tab.");
            } catch (Throwable ignored) {
                // nothing left to do
            }
        }
    }

    private void runUnchecked() throws Exception {
        String text = clipboard.text();
        if (text == null || text.isBlank()) {
            dialogs.info(TITLE, "The clipboard does not contain any text. Copy a cURL command first.");
            return;
        }

        if (text.length() > MAX_CLIPBOARD_CHARS) {
            dialogs.error(TITLE + " - text too large",
                    "The clipboard text is too large (" + text.length() + " characters; the limit is "
                            + MAX_CLIPBOARD_CHARS + ", about 10 MB). Nothing was parsed and no request was sent.\n"
                            + "Copy only the curl command, and put a large body in a file (-d @file).");
            return;
        }

        ParsedCurl parsed;
        try {
            parsed = Curl.parse(text);
        } catch (CurlParseException e) {
            showParseError(e, text);
            return;
        }

        FileAccess files = FileAccess.DENY;
        List<String> refs = parsed.fileRefs();
        if (!refs.isEmpty()) {
            List<FileInfo> infos = new ArrayList<>();
            for (String ref : refs) {
                infos.add(probe.describe(ref));
            }
            FileChoice choice = dialogs.confirmFiles(infos, probe.homeDirectory());
            if (choice == null || choice == FileChoice.CANCEL) {
                return;
            }
            if (choice == FileChoice.READ_FILES) {
                files = realFiles.get();
            }
        }

        List<BuiltRequest> requests;
        try {
            requests = parsed.build(files, settings.get());
        } catch (CurlParseException e) {
            showParseError(e, text);
            return;
        }
        if (requests.isEmpty()) {
            dialogs.info(TITLE, "The command did not produce any HTTP request.");
            return;
        }

        int total = requests.size();
        int sent = Math.min(total, MAX_TABS);
        for (int i = 0; i < sent; i++) {
            sink.send(requests.get(i), total == 1 ? null : "curl " + (i + 1) + "/" + sent);
        }
        log.output("Sent " + sent + (sent == 1 ? " request" : " requests") + " to Repeater");

        report(parsed, requests.subList(0, sent), total, sent);
    }

    private void report(ParsedCurl parsed, List<BuiltRequest> sentRequests, int total, int sent) {
        Set<Warning> all = new LinkedHashSet<>(parsed.warnings());
        for (BuiltRequest r : sentRequests) {
            all.addAll(r.warnings());
        }
        List<String> lossy = new ArrayList<>();
        for (Warning w : all) {
            if (w.severity() == Warning.Severity.LOSSY) {
                lossy.add(w.message());
                log.output("LOSSY: " + w.message());
            } else {
                log.output("NOTE: " + w.message());
            }
        }
        String capNote = total > sent
                ? "The command produced " + total + " requests; only the first " + sent + " were sent to Repeater."
                : null;
        if (capNote != null) {
            log.output(capNote);
        }

        if (!lossy.isEmpty()) {
            StringBuilder sb = new StringBuilder();
            sb.append("The request in Repeater may differ from what curl would send:\n");
            int shown = Math.min(lossy.size(), MAX_LISTED_WARNINGS);
            for (int i = 0; i < shown; i++) {
                sb.append("\n- ").append(lossy.get(i));
            }
            if (lossy.size() > shown) {
                sb.append("\n- ... and ").append(lossy.size() - shown).append(" more (see the extension output)");
            }
            if (capNote != null) {
                sb.append("\n\n").append(capNote);
            }
            dialogs.warning(TITLE + " - request may differ from curl", sb.toString());
        } else if (capNote != null) {
            dialogs.info(TITLE, capNote);
        }
    }

    private void showParseError(CurlParseException e, String text) {
        StringBuilder sb = new StringBuilder("Could not parse the cURL command:\n").append(e.getMessage());
        if (e.position() >= 0) {
            sb.append("\n\nNear ").append(ParseErrorView.lineAndColumn(text, e.position()))
                    .append(" (the text of the arguments is hidden):\n")
                    .append(ParseErrorView.maskedExcerpt(text, e.position()));
        }
        dialogs.error(TITLE + " - cannot parse", sb.toString());
    }
}
