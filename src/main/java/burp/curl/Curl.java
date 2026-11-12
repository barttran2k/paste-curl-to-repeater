package burp.curl;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
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
        if (pastedText == null || pastedText.isBlank()) {
            throw new CurlParseException("Nothing to parse: the pasted text is empty");
        }
        Tokenizer tk = DialectDetector.detect(pastedText) == DialectDetector.Dialect.CMD
                ? new CmdTokenizer() : new PosixTokenizer();
        TokenizeResult tr = tk.tokenize(pastedText);
        List<Warning> warnings = new ArrayList<>(tr.warnings());

        List<Operation> operations = new ArrayList<>();
        boolean sawCurl = false;
        for (CommandLine cmd : tr.commands()) {
            int at = curlIndex(cmd.argv());
            if (at >= 0) {
                sawCurl = true;
                add(cmd, cmd.argv().subList(at + 1, cmd.argv().size()), operations, warnings);
            }
        }
        if (!sawCurl) {
            if (!tr.commands().isEmpty()) {
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
                        add(first, first.argv().subList(start, first.argv().size()), operations, warnings);
                        sawCurl = true;
                    }
                }
            }
            if (!sawCurl) {
                throw new CurlParseException("No curl command found. Paste a command such as: "
                        + "curl -X POST https://example.com/api -d 'a=1'");
            }
        }
        return new ParsedCurlImpl(operations, warnings);
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

    private static void add(CommandLine cmd, List<Token> args, List<Operation> operations, List<Warning> warnings)
            throws CurlParseException {
        CurlCommandParser.Parsed p = CurlCommandParser.parse(args, cmd);
        operations.addAll(p.operations);
        warnings.addAll(p.warnings);
    }

    /** Index of the first word whose basename is curl or curl.exe; -1 when there is none. */
    private static int curlIndex(List<Token> argv) {
        for (int i = 0; i < argv.size(); i++) {
            String w = argv.get(i).text();
            int cut = Math.max(w.lastIndexOf('/'), w.lastIndexOf('\\'));
            String base = w.substring(cut + 1).toLowerCase(Locale.ROOT);
            if (base.equals("curl") || base.equals("curl.exe")) {
                return i;
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
