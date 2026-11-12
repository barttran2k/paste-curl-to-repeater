package burp.curl;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Entry point of the new curl parsing core.
 *
 * <p>Pipeline: {@link DialectDetector} picks the shell dialect, {@link PosixTokenizer} or {@link CmdTokenizer}
 * splits the text into commands, every command that runs {@code curl} is walked by {@link CurlCommandParser}
 * (one {@link Operation} per {@code --next} group) and {@link CurlRequestBuilder} builds one request per URL.
 */
public final class Curl {
    private static final Pattern ASSIGNMENT = Pattern.compile("[A-Za-z_][A-Za-z0-9_]*=.*", Pattern.DOTALL);
    private static final Pattern HOSTISH = Pattern.compile("[^\\s/?#:@]+(:\\d+)?([/?#].*)?", Pattern.DOTALL);

    private Curl() {
    }

    /**
     * @param pastedText the text pasted by the user
     * @return the parsed result
     * @throws CurlParseException if the text cannot be parsed
     */
    public static ParsedCurl parse(String pastedText) throws CurlParseException {
        try {
            return parseUnguarded(pastedText);
        } catch (CurlParseException e) {
            throw e;
        } catch (RuntimeException | StackOverflowError e) {
            throw new CurlParseException("The pasted text could not be parsed (" + e + ")");
        }
    }

    /**
     * {@link #parse} without the safety net that turns unexpected runtime failures into parse exceptions.
     *
     * <p>The text is read in the dialect {@link DialectDetector} reports. If that reading fails in the tokenizer or
     * finds no curl command, the other dialect is tried (the detector cannot tell a bash string that contains
     * whitespace followed by {@code ^"} from cmd); when it succeeds a note names the dialect used, when it also fails
     * the error of the detected dialect is reported. Windows cmd is only tried for a POSIX-detected text that
     * contains a caret: cmd has no quotes the POSIX tokenizer could be missing, so without cmd's escape character a
     * failure is a real bash syntax error and the cmd reading of it would be nonsense.
     */
    static ParsedCurlImpl parseUnguarded(String pastedText) throws CurlParseException {
        if (pastedText == null || pastedText.isBlank()) {
            throw new CurlParseException("Nothing to parse: the pasted text is empty");
        }
        boolean cmd = DialectDetector.detect(pastedText) == DialectDetector.Dialect.CMD;
        Attempt first = attempt(pastedText, cmd, null);
        if (first.result != null) {
            return first.result;
        }
        if (first.retry && (cmd || pastedText.indexOf('^') >= 0)) {
            Warning note = Warning.note(cmd
                    ? "The text looked like Windows cmd but could not be read as such; it was read as a POSIX shell "
                            + "(bash) command"
                    : "The text could not be read as a POSIX shell command; it was read as a Windows cmd command");
            Attempt second = attempt(pastedText, !cmd, note);
            if (second.result != null) {
                return second.result;
            }
        }
        throw first.failure;
    }

    /** Outcome of reading the text in one dialect. */
    private record Attempt(ParsedCurlImpl result, CurlParseException failure, boolean retry) {
    }

    private static Attempt attempt(String pastedText, boolean cmd, Warning leadingNote) {
        try {
            return new Attempt(parseDialect(pastedText, cmd ? new CmdTokenizer() : new PosixTokenizer(), leadingNote),
                    null, false);
        } catch (RetryableException e) {
            return new Attempt(null, e.original, true);
        } catch (CurlParseException e) {
            return new Attempt(null, e, false);
        }
    }

    /** The tokenizer rejected the text, or it holds no usable curl command: the other dialect may do better. */
    private static final class RetryableException extends CurlParseException {
        private static final long serialVersionUID = 1L;
        final transient CurlParseException original;

        RetryableException(CurlParseException original) {
            super(original.getMessage(), original.position());
            this.original = original;
        }
    }

    private static ParsedCurlImpl parseDialect(String pastedText, Tokenizer tk, Warning leadingNote)
            throws CurlParseException {
        TokenizeResult tr;
        try {
            tr = tk.tokenize(pastedText);
        } catch (CurlParseException e) {
            throw new RetryableException(e);
        }
        List<Warning> warnings = new ArrayList<>();
        if (leadingNote != null) {
            warnings.add(leadingNote);
        }
        warnings.addAll(tr.warnings());

        List<ParsedCurlImpl.Run> runs = new ArrayList<>();
        List<CurlParseException> errors = new ArrayList<>();
        boolean sawCurl = false;
        for (CommandLine cmd : tr.commands()) {
            int at = curlIndex(cmd.argv());
            if (at >= 0) {
                sawCurl = true;
                add(cmd, cmd.argv().subList(at + 1, cmd.argv().size()), runs, warnings, errors);
            }
        }
        if (!sawCurl && !tr.commands().isEmpty()) {
            CommandLine first = tr.commands().get(0);
            int start = 0;
            while (start < first.argv().size() && ASSIGNMENT.matcher(first.argv().get(start).text()).matches()
                    && !looksLikeUrl(first.argv().get(start).text())) {
                start++;
            }
            if (start < first.argv().size()) {
                String w = first.argv().get(start).text();
                if (w.startsWith("-") || looksLikeUrl(w)) {
                    warnings.add(Warning.note("No curl command found; the text was read as curl arguments"));
                    sawCurl = true;
                    add(first, first.argv().subList(start, first.argv().size()), runs, warnings, errors);
                }
            }
        }
        if (runs.isEmpty()) {
            if (!errors.isEmpty()) {
                throw errors.get(0);
            }
            throw new RetryableException(new CurlParseException("No curl command found. Paste a command such as: "
                    + "curl -X POST https://example.com/api -d 'a=1'"));
        }
        for (CurlParseException e : errors) {
            warnings.add(e.getMessage().startsWith("No URL")
                    ? Warning.note("A curl command without a URL was skipped")
                    : Warning.lossy("A curl command was skipped: " + e.getMessage()));
        }
        return new ParsedCurlImpl(runs, warnings);
    }

    /**
     * Parses and builds in one go, keeping the pieces the legacy facade needs.
     *
     * @param pastedText the pasted text
     * @param files access to local files for {@code @file} data (null denies every read)
     * @return details of every request, in order (never empty)
     * @throws CurlParseException if the text cannot be parsed or a request cannot be built
     */
    public static List<RequestDetails> parseAndBuild(String pastedText, FileAccess files)
            throws CurlParseException {
        ParsedCurl p = parse(pastedText);
        List<RequestDetails> d = ((ParsedCurlImpl) p).details(files);
        if (d.isEmpty()) {
            throw new CurlParseException("The curl command produced no request");
        }
        return d;
    }

    private static void add(CommandLine cmd, List<Token> args, List<ParsedCurlImpl.Run> runs,
                            List<Warning> warnings, List<CurlParseException> errors) {
        List<String> read = new ArrayList<>();
        FileAccess recorder = path -> {
            read.add(path);
            return new byte[0];
        };
        try {
            CurlCommandParser.Parsed p = CurlCommandParser.parse(args, cmd, recorder);
            warnings.addAll(p.warnings);
            runs.add(new ParsedCurlImpl.Run(cmd, args, p.operations, read));
        } catch (CurlParseException e) {
            errors.add(e);
        }
    }

    private static final Set<String> WRAPPERS = Set.of("sudo", "env", "time", "nohup", "command", "exec", "nice",
            "noglob", "winpty", "proxychains", "proxychains4", "torsocks");
    /** wrapper options that take a separate argument */
    private static final Map<String, Set<String>> WRAPPER_ARG_FLAGS = Map.of(
            "sudo", Set.of("-u", "-g", "-h", "-p", "-C", "-D", "-R", "-T", "-U"),
            "env", Set.of("-u", "-C", "-S", "-P"),
            "nice", Set.of("-n"),
            "exec", Set.of("-a"),
            "proxychains", Set.of("-f"),
            "proxychains4", Set.of("-f"),
            "torsocks", Set.of("-a", "-p", "-P", "-u"),
            "time", Set.of("-f", "-o"));

    /** Shell keywords after which a command word follows ({@code if curl ...; then}). */
    private static final Set<String> KEYWORDS = Set.of("if", "then", "else", "elif", "do", "while", "until", "!", "{",
            "(");

    private static String baseName(String w) {
        int cut = Math.max(w.lastIndexOf('/'), w.lastIndexOf('\\'));
        return w.substring(cut + 1).toLowerCase(Locale.ROOT);
    }

    /**
     * Index of the curl word when it is the command word: only {@code NAME=value} assignments and the known
     * wrappers (with their own flags) may precede it. -1 otherwise.
     */
    private static int curlIndex(List<Token> argv) {
        int i = 0;
        int n = argv.size();
        while (i < n) {
            String w = argv.get(i).text();
            if (ASSIGNMENT.matcher(w).matches()) {
                i++;
                continue;
            }
            String base = baseName(w);
            if (base.equals("curl") || base.equals("curl.exe")) {
                return i;
            }
            if (KEYWORDS.contains(w)) {
                i++;
                continue;
            }
            if (!WRAPPERS.contains(base)) {
                return -1;
            }
            i++;
            Set<String> withArg = WRAPPER_ARG_FLAGS.getOrDefault(base, Set.of());
            while (i < n) {
                String f = argv.get(i).text();
                if (f.equals("--")) {
                    i++;
                    break;
                }
                if (!f.startsWith("-") || f.length() < 2) {
                    break;
                }
                if (base.equals("command") && (f.contains("v") || f.contains("V"))) {
                    return -1;
                }
                i += withArg.contains(f) ? 2 : 1;
            }
        }
        return -1;
    }

    private static boolean looksLikeUrl(String w) {
        if (w.contains("://")) {
            return true;
        }
        return HOSTISH.matcher(w).matches() && (w.startsWith("localhost") || w.indexOf('.') > 0
                || w.matches("\\[[0-9A-Fa-f:.]+\\].*"));
    }
}
