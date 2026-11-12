package burp.curl;

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
        /**
         * true when some variable got its content from a file: the options that use it can mean something else
         * once the file is really read, so {@link #warnings} of a probe parse may not match the real parse
         */
        boolean contentDependent;
    }

    private final CurlOptionTable table = CurlOptionTable.get();
    private final Parsed out = new Parsed();
    private final Operation.StdinSource stdin;
    private final FileAccess files;
    /** true for the parse that only collects file references (no file contents are available) */
    private final boolean probe;
    private final CurlVariables variables = new CurlVariables();
    private final List<Warning> lateWarnings = new ArrayList<>();
    private Operation current = new Operation();

    private CurlCommandParser(CommandLine command, FileAccess files, boolean probe) {
        this.files = files;
        this.probe = probe;
        this.stdin = command.stdin() != null || command.stdinFile() != null
                ? new Operation.StdinSource(command.stdin(), command.stdinFile()) : null;
        current.stdin = stdin;
    }

    /**
     * @param args the words after the {@code curl} word
     * @param command the shell command the words came from (for its stdin)
     * @param files source of {@code --variable name@file} contents
     * @param probe true when {@code files} only records the paths: arguments that were expanded with the content of
     *              a file variable are then replaced by harmless ones, because the paths they would name are not
     *              known yet and must not be listed
     * @return the operations (those without a URL are dropped) and the warnings
     * @throws CurlParseException on a missing option argument or when no operation has a URL
     */
    static Parsed parse(List<Token> args, CommandLine command, FileAccess files, boolean probe)
            throws CurlParseException {
        CurlCommandParser p = new CurlCommandParser(command, files, probe);
        p.walk(args);
        p.out.contentDependent = p.variables.anyFromFile();
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
                    out.warnings.add(Warning.lossy("Unknown option " + MessageText.optionName(w)
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
                current.urls.add(wire(b));
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

    /** An argument that is text for us (file path, date, scheme): lossy UTF-8. */
    private static String text(byte[] b) {
        return new String(b, StandardCharsets.UTF_8);
    }

    /** An argument curl sends as it is: see {@link ByteText}. */
    private static String wire(byte[] b) {
        return ByteText.decode(b);
    }

    private void unsupported(String option) {
        out.warnings.add(Warning.lossy(option + " is not supported yet"));
    }

    /** Applies one option to the current operation. {@code arg} is null for options without argument. */
    private void apply(OptionSpec spec, boolean negated, boolean expand, byte[] arg) {
        String opt = "--" + spec.longName();
        boolean fromFileContent = false;
        if (expand && arg != null) {
            byte[] expanded = variables.expand(arg, lateWarnings, "--expand-" + spec.longName());
            if (expanded != null) {
                arg = expanded;
                fromFileContent = variables.lastExpansionUsedFileContent();
            }
        }
        if (probe && fromFileContent && !spec.longName().equals("variable")) {
            if (spec.longName().equals("upload-file")) {
                return;
            }
            if (FILE_PATH_OPTIONS.contains(spec.longName())) {
                arg = NEUTRAL_ARG;
            }
        }
        Operation op = current;
        switch (spec.longName()) {
            case "request" -> {
                if (arg.length > 0) {
                    op.method = wire(arg);
                }
            }
            case "head" -> op.head = !negated;
            case "get" -> op.get = !negated;
            case "url" -> op.urls.add(wire(arg));
            case "header" -> op.headers.add(wire(arg));
            case "user-agent" -> op.userAgent = wire(arg);
            case "referer" -> op.referer = wire(arg);
            case "cookie" -> {
                String c = wire(arg);
                if (c.indexOf('=') >= 0) {
                    op.cookies.add(c);
                } else if (!c.isEmpty()) {
                    op.cookieFiles.add(text(arg));
                }
            }
            case "junk-session-cookies" -> op.junkSessionCookies = !negated;
            case "variable" -> variables.define(arg, stdin, probe && fromFileContent ? FileAccess.DENY : files,
                    lateWarnings, fromFileContent);
            case "form" -> addForm(arg, false);
            case "form-string" -> addForm(arg, true);
            case "form-escape" -> op.formEscape = !negated;
            case "upload-file" -> op.uploads.add(text(arg));
            case "url-query" -> addUrlQuery(arg);
            case "time-cond" -> op.timeCond = text(arg);
            case "tr-encoding" -> op.trEncoding = !negated;
            case "crlf" -> op.crlf = !negated;
            case "request-target" -> op.requestTarget = wire(arg);
            case "proto-default" -> op.protoDefault = text(arg);
            case "disallow-username-in-url" -> op.disallowUsernameInUrl = !negated;
            case "user" -> op.user = wire(arg);
            case "basic" -> authBit(op, Operation.AUTH_BASIC, negated, opt, false);
            case "digest" -> authBit(op, Operation.AUTH_DIGEST, negated, opt, true);
            case "ntlm" -> authBit(op, Operation.AUTH_NTLM, negated, opt, true);
            case "negotiate" -> authBit(op, Operation.AUTH_NEGOTIATE, negated, opt, true);
            case "ntlm-wb" -> authBit(op, Operation.AUTH_NTLM_WB, negated, opt, true);
            case "anyauth" -> {
                op.authMask = Operation.AUTH_ANY; // --no-anyauth does not exist in the table: curl leaves the mask alone
                op.authOptions.add(opt);
                out.warnings.add(Warning.lossy(optionWarning("anyauth", opt, null)));
            }
            case "oauth2-bearer" -> {
                op.bearer = wire(arg);
                op.authMask |= Operation.AUTH_BEARER;
                op.authOptions.add(opt);
            }
            case "range" -> op.range = wire(arg);
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
                if (PROXY_OPTIONS.contains(spec.longName())) {
                    // the proxy family is group C in the table (no effect on the bytes) but worth a hint
                    out.warnings.add(Warning.lossy(optionWarning(spec.longName(), opt, null)));
                    return;
                }
                switch (spec.handling()) {
                    case A -> unsupported(opt);
                    case B -> out.warnings.add(Warning.lossy(optionWarning(spec.longName(), opt,
                            arg == null ? null : ByteText.display(wire(arg)))));
                    default -> { }
                }
            }
        }
    }

    /** Options whose argument can name a local file. */
    private static final java.util.Set<String> FILE_PATH_OPTIONS = java.util.Set.of("data", "data-ascii",
            "data-binary", "data-raw", "data-urlencode", "json", "url-query", "form", "header", "cookie");
    /** An argument of every {@link #FILE_PATH_OPTIONS} option that names no file. */
    private static final byte[] NEUTRAL_ARG = {'x', '=', '1'};

    /** Options that select a proxy for the transfer. */
    private static final java.util.Set<String> PROXY_OPTIONS = java.util.Set.of("proxy", "preproxy", "socks4",
            "socks4a", "socks5", "socks5-hostname");

    /**
     * The one-sentence warning of an option that changes how curl sends the request without changing its bytes.
     * Credentials never appear in it; only {@code --resolve} and {@code --connect-to} echo their argument.
     */
    private static String optionWarning(String name, String opt, String arg) {
        switch (name) {
            case "proxy", "preproxy", "socks4", "socks4a", "socks5", "socks5-hostname":
                return opt + ": the request content is unchanged, but curl would send it through that proxy; "
                        + "configure an upstream proxy in Burp if needed.";
            case "resolve", "connect-to":
                return opt + " " + arg + ": curl would connect to a different address than the URL's host; add a "
                        + "hostname resolution override in Burp (Settings \u2192 Network \u2192 Connections) to "
                        + "reproduce it.";
            case "unix-socket", "abstract-unix-socket":
                return opt + ": Burp cannot connect to a Unix socket, so the request is not sent over it.";
            case "cert", "key":
                return opt + ": curl would present a client TLS certificate; add it in Burp (Settings \u2192 Network "
                        + "\u2192 TLS \u2192 Client TLS certificates).";
            case "digest", "ntlm", "ntlm-wb", "negotiate", "anyauth":
                return opt + ": the authentication handshake is not precomputed, so this option itself adds no "
                        + "Authorization header; configure platform authentication in Burp or add the header yourself.";
            case "aws-sigv4":
                return opt + ": the AWS signature headers are not computed.";
            case "config":
                return opt + ": the config file is not read, so the options inside it are missing.";
            case "netrc", "netrc-file", "netrc-optional":
                return opt + ": credentials from .netrc are not read.";
            default:
                return opt + " changes how curl sends the request and is not reproduced; the request may differ";
        }
    }

    /** Sets or clears one bit of the authentication mask, like curl's tool does for {@code --digest} and friends. */
    private void authBit(Operation op, int bit, boolean negated, String opt, boolean warn) {
        if (negated) {
            op.authMask &= ~bit;
            return;
        }
        op.authMask |= bit;
        op.authOptions.add(opt);
        if (warn) {
            out.warnings.add(Warning.lossy(optionWarning(opt.substring(2), opt, null)));
        }
    }

    private void addForm(byte[] arg, boolean literal) {
        try {
            current.forms.add(literal ? FormField.parseString(wire(arg)) : FormField.parse(wire(arg)));
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
