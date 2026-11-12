package burp.curl;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

/**
 * Walks the argv of one curl command like {@code parse_args}/{@code getparameter} in curl's
 * {@code tool_getparam.c} and fills one {@link Operation} per {@code --next} group.
 *
 * <p>Every option of {@link CurlOptionTable} is consumed with the right arity, whether or not it changes the
 * request, so an option's argument is never mistaken for a URL. Options without an effect on the request
 * (groups C and D) are consumed silently; group B options add a lossy warning; group A options that are not
 * implemented yet add {@code "<option> is not supported yet"}.
 */
public final class CurlCommandParser {

    /** Output of {@link #parse}. */
    static final class Parsed {
        final List<Operation> operations = new ArrayList<>();
        final List<Warning> warnings = new ArrayList<>();
        /** files the variables ({@code --variable name@file}) read */
        final List<String> variableFiles = new ArrayList<>();
    }

    private final CurlOptionTable table = CurlOptionTable.get();
    private final Parsed out = new Parsed();
    private final Operation.StdinSource stdin;
    private final FileAccess files;
    private final CurlVariables variables = new CurlVariables();
    private final List<Warning> lateWarnings = new ArrayList<>();
    private Operation current = new Operation();

    private CurlCommandParser(CommandLine command, FileAccess files) {
        this.files = files;
        this.stdin = command.stdin() != null || command.stdinFile() != null
                ? new Operation.StdinSource(command.stdin(), command.stdinFile()) : null;
        current.stdin = stdin;
    }

    /**
     * @param args the words after the {@code curl} word
     * @param command the shell command the words came from (for its stdin)
     * @return the operations (those without a URL are dropped) and the warnings
     * @throws CurlParseException on a missing option argument or when no operation has a URL
     */
    static Parsed parse(List<Token> args, CommandLine command) throws CurlParseException {
        return parse(args, command, FileAccess.DENY);
    }

    /**
     * Like {@link #parse(List, CommandLine)} with access to the files that variables read at parse time.
     *
     * @param files source of {@code --variable name@file} contents
     */
    static Parsed parse(List<Token> args, CommandLine command, FileAccess files) throws CurlParseException {
        CurlCommandParser p = new CurlCommandParser(command, files);
        p.walk(args);
        return p.out;
    }

    private void walk(List<Token> args) throws CurlParseException {
        List<Operation> all = new ArrayList<>();
        all.add(current);
        boolean ended = false;
        int i = 0;
        while (i < args.size()) {
            Token t = args.get(i++);
            byte[] b = t.bytes();
            String w = t.text();
            if (!ended && w.equals("--")) {
                ended = true;
            } else if (!ended && w.startsWith("--")) {
                String name = w.substring(2);
                Optional<CurlOptionTable.LongMatch> m = table.resolveLong(name);
                if (m.isEmpty()) {
                    out.warnings.add(Warning.lossy("Unknown option " + w
                            + " ignored (treated as taking no argument); the request may differ"));
                    continue;
                }
                OptionSpec spec = m.get().spec();
                byte[] arg = null;
                if (spec.takesArg()) {
                    if (m.get().inlineValue() != null) {
                        arg = m.get().inlineValue().getBytes(StandardCharsets.UTF_8);
                    } else if (i < args.size()) {
                        arg = args.get(i++).bytes();
                    } else {
                        throw new CurlParseException("Option --" + spec.longName() + " needs an argument");
                    }
                }
                if (spec.longName().equals("next") && !m.get().expand()) {
                    startNext(all);
                } else {
                    apply(spec, m.get().negated(), m.get().expand(), arg);
                }
            } else if (!ended && w.startsWith("-") && w.length() > 1) {
                for (int j = 1; j < b.length; j++) {
                    char c = (char) (b[j] & 0xff);
                    Optional<OptionSpec> s = (b[j] & 0x80) == 0 ? table.byShort(c) : Optional.empty();
                    if (s.isEmpty()) {
                        out.warnings.add(Warning.lossy("Unknown option -" + new String(b, j, 1,
                                StandardCharsets.ISO_8859_1) + " ignored; the request may differ"));
                        continue;
                    }
                    OptionSpec spec = s.get();
                    if (spec.takesArg()) {
                        byte[] arg;
                        if (j + 1 < b.length) {
                            arg = Arrays.copyOfRange(b, j + 1, b.length);
                        } else if (i < args.size()) {
                            arg = args.get(i++).bytes();
                        } else {
                            throw new CurlParseException("Option -" + c + " (--" + spec.longName()
                                    + ") needs an argument");
                        }
                        apply(spec, false, false, arg);
                        break;
                    }
                    if (spec.longName().equals("next")) {
                        startNext(all);
                    } else {
                        apply(spec, false, false, null);
                    }
                }
            } else {
                current.urls.add(w);
            }
        }
        for (Operation op : all) {
            if (!op.urls.isEmpty()) {
                op.lateWarnings.addAll(lateWarnings);
                out.operations.add(op);
            }
        }
        if (out.operations.isEmpty()) {
            throw new CurlParseException("No URL found in the curl command");
        }
    }

    private void startNext(List<Operation> all) {
        current = new Operation();
        current.stdin = stdin;
        all.add(current);
    }

    private static String text(byte[] b) {
        return new String(b, StandardCharsets.UTF_8);
    }

    private void unsupported(String option) {
        out.warnings.add(Warning.lossy(option + " is not supported yet"));
    }

    /** Applies one option to the current operation. {@code arg} is null for options without argument. */
    private void apply(OptionSpec spec, boolean negated, boolean expand, byte[] arg) {
        String opt = "--" + spec.longName();
        if (expand && arg != null) {
            byte[] expanded = variables.expand(arg, lateWarnings, "--expand-" + spec.longName());
            if (expanded != null) {
                arg = expanded;
            }
        }
        Operation op = current;
        switch (spec.longName()) {
            case "request" -> {
                if (arg.length > 0) {
                    op.method = text(arg);
                }
            }
            case "head" -> op.head = !negated;
            case "get" -> op.get = !negated;
            case "url" -> op.urls.add(text(arg));
            case "header" -> op.headers.add(text(arg));
            case "user-agent" -> op.userAgent = text(arg);
            case "referer" -> op.referer = text(arg);
            case "cookie" -> {
                String c = text(arg);
                op.cookieEngine = true;
                if (c.indexOf('=') >= 0) {
                    op.cookies.add(c);
                } else if (!c.isEmpty()) {
                    op.cookieFiles.add(c);
                }
            }
            case "cookie-jar" -> op.cookieEngine = true;
            case "variable" -> variables.define(arg, this::readStdin, files, lateWarnings);
            case "form" -> addForm(arg, false);
            case "form-string" -> addForm(arg, true);
            case "form-escape" -> op.formEscape = !negated;
            case "upload-file" -> op.uploads.add(text(arg));
            case "url-query" -> addUrlQuery(arg);
            case "time-cond" -> op.timeCond = text(arg);
            case "tr-encoding" -> op.trEncoding = !negated;
            case "crlf" -> op.crlf = !negated;
            case "request-target" -> op.requestTarget = text(arg);
            case "proto-default" -> op.protoDefault = text(arg);
            case "disallow-username-in-url" -> op.disallowUsernameInUrl = !negated;
            case "user" -> op.user = text(arg);
            case "basic" -> op.basic = !negated;
            case "oauth2-bearer" -> op.bearer = text(arg);
            case "range" -> op.range = text(arg);
            case "compressed" -> op.compressed = !negated;
            case "http1.0" -> op.http10 = true;
            case "http1.1", "http2", "http2-prior-knowledge", "http3", "http3-only" -> {
                op.http10 = false;
                out.warnings.add(Warning.note(opt + ": the HTTP version is left to Burp"));
            }
            case "path-as-is" -> op.pathAsIs = !negated;
            case "globoff" -> op.globoff = !negated;
            case "data", "data-ascii" -> addData(Operation.DataPiece.Kind.ASCII, arg);
            case "data-binary" -> addData(Operation.DataPiece.Kind.BINARY, arg);
            case "data-raw" -> addData(Operation.DataPiece.Kind.RAW, arg);
            case "data-urlencode" -> addData(Operation.DataPiece.Kind.URLENCODE, arg);
            case "json" -> {
                op.json = true;
                addData(Operation.DataPiece.Kind.JSON, arg);
            }
            default -> {
                switch (spec.handling()) {
                    case A -> unsupported(opt);
                    case B -> out.warnings.add(Warning.lossy(opt
                            + " changes how curl sends the request and is not reproduced; the request may differ"));
                    default -> { }
                }
            }
        }
    }

    private byte[] readStdin(List<Warning> w) {
        if (stdin != null && stdin.bytes != null) {
            return stdin.bytes;
        }
        if (stdin != null && stdin.file != null) {
            try {
                byte[] b = files.read(stdin.file);
                if (b != null) {
                    return b;
                }
            } catch (IOException | RuntimeException e) {
                w.add(Warning.lossy("Could not read " + stdin.file + " (" + e.getMessage()
                        + "); a placeholder was used"));
                return ("<<FILE: " + stdin.file + ">>").getBytes(StandardCharsets.UTF_8);
            }
        }
        w.add(Warning.lossy("The command reads stdin (@-) but no stdin content was pasted"));
        return "<<STDIN>>".getBytes(StandardCharsets.UTF_8);
    }

    private void addForm(byte[] arg, boolean literal) {
        try {
            current.forms.add(literal ? FormField.parseString(text(arg)) : FormField.parse(text(arg)));
        } catch (CurlParseException e) {
            out.warnings.add(Warning.lossy("curl rejects this " + (literal ? "--form-string" : "-F")
                    + " argument (" + e.getMessage() + "); the field was skipped"));
        }
    }

    private void addUrlQuery(byte[] arg) {
        if (arg.length > 0 && arg[0] == '+') {
            current.urlQueries.add(new Operation.UrlQuery(true, Arrays.copyOfRange(arg, 1, arg.length), null, null));
            return;
        }
        int idx = indexOf(arg, (byte) '=');
        if (idx < 0) {
            idx = indexOf(arg, (byte) '@');
        }
        if (idx < 0) {
            current.urlQueries.add(new Operation.UrlQuery(false, arg, null, null));
            return;
        }
        byte[] name = idx > 0 ? Arrays.copyOfRange(arg, 0, idx) : null;
        byte[] rest = Arrays.copyOfRange(arg, idx + 1, arg.length);
        if (arg[idx] == '@') {
            current.urlQueries.add(new Operation.UrlQuery(false, null, text(rest), name));
        } else {
            current.urlQueries.add(new Operation.UrlQuery(false, rest, null, name));
        }
    }

    private void addData(Operation.DataPiece.Kind kind, byte[] arg) {
        Operation op = current;
        switch (kind) {
            case RAW -> op.data.add(new Operation.DataPiece(kind, arg, null, null));
            case ASCII, BINARY, JSON -> {
                if (arg.length > 0 && arg[0] == '@') {
                    op.data.add(new Operation.DataPiece(kind, null,
                            text(Arrays.copyOfRange(arg, 1, arg.length)), null));
                } else {
                    op.data.add(new Operation.DataPiece(kind, arg, null, null));
                }
            }
            case URLENCODE -> {
                int idx = indexOf(arg, (byte) '=');
                if (idx < 0) {
                    idx = indexOf(arg, (byte) '@');
                }
                if (idx < 0) {
                    op.data.add(new Operation.DataPiece(kind, arg, null, null));
                } else {
                    byte[] name = idx > 0 ? Arrays.copyOfRange(arg, 0, idx) : null;
                    byte[] rest = Arrays.copyOfRange(arg, idx + 1, arg.length);
                    if (arg[idx] == '@') {
                        op.data.add(new Operation.DataPiece(kind, null, text(rest), name));
                    } else {
                        op.data.add(new Operation.DataPiece(kind, rest, null, name));
                    }
                }
            }
            default -> throw new IllegalStateException();
        }
    }

    private static int indexOf(byte[] a, byte x) {
        for (int i = 0; i < a.length; i++) {
            if (a[i] == x) {
                return i;
            }
        }
        return -1;
    }
}
