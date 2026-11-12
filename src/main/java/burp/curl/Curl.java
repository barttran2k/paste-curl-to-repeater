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

    /** {@link #parse} without the safety net that turns unexpected runtime failures into parse exceptions. */
    static ParsedCurlImpl parseUnguarded(String pastedText) throws CurlParseException {
        if (pastedText == null || pastedText.isBlank()) {
            throw new CurlParseException("Nothing to parse: the pasted text is empty");
        }
        Tokenizer tk = DialectDetector.detect(pastedText) == DialectDetector.Dialect.CMD
                ? new CmdTokenizer() : new PosixTokenizer();
        TokenizeResult tr = tk.tokenize(pastedText);
        List<Warning> warnings = new ArrayList<>(tr.warnings());

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
            throw new CurlParseException("No curl command found. Paste a command such as: "
                    + "curl -X POST https://example.com/api -d 'a=1'");
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
