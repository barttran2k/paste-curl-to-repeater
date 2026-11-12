package burp.curl;

import java.util.ArrayList;
import java.util.List;

/**
 * One {@code -F}/{@code --form}/{@code --form-string} argument, parsed the way curl's {@code tool_formparse.c} does.
 *
 * <p>{@code value} is the literal text for {@link Kind#LITERAL}, the file path for {@link Kind#FILE_UPLOAD} and
 * {@link Kind#FILE_CONTENT}. {@code type}/{@code filename} are null when not given. {@code headers} are the
 * {@code ;headers=} values verbatim; an entry starting with {@code @} or {@code <} names a file of header lines
 * (resolved by {@link MultipartBuilder}).
 *
 * <p>Extension to the three basic kinds: {@code name=@a,b} (several files in one field) is represented as
 * {@link Kind#FILE_LIST} whose {@code value} is the raw text after the {@code @}; use {@link #filePaths()} to list the
 * files and {@link #files()} to get one {@code FILE_UPLOAD} field per file (each with its own type/filename/headers).
 * A single file is always plain {@code FILE_UPLOAD}.
 *
 * <p>Mirrored curl rules: the name is everything before the first {@code =} (not trimmed); a value starting with
 * {@code @} or {@code <} is a file reference only when it is the very first character (so {@code "@x"} in quotes or
 * {@code " @x"} is literal); an unquoted word ends at {@code ;} and loses trailing blanks; a quoted word may contain
 * {@code ;} and the escapes {@code \"} and {@code \\}, text after the closing quote up to the next {@code ;} is
 * dropped, and an unterminated quote makes the word unquoted. After {@code type=} any further parameters other than
 * {@code filename=}, {@code headers=}, {@code encoder=} are glued onto the type ({@code type=text/plain;charset=utf-8});
 * unknown parameters without a preceding {@code type=} are skipped silently. {@code type=} needs a {@code /} with text on
 * both sides. {@code encoder=} is rejected (not implemented). A missing {@code =} is an error, as in curl.
 */
public record FormField(String name, Kind kind, String value, String type, String filename, List<String> headers) {

    /** What the content of the field is. */
    public enum Kind {
        /** {@code name=value} */
        LITERAL,
        /** {@code name=@path}: file sent as an upload (filename, guessed Content-Type) */
        FILE_UPLOAD,
        /** {@code name=<path}: file content sent as a plain text part */
        FILE_CONTENT,
        /** {@code name=@a,b}: several uploads in one field (multipart/mixed); value = raw text after '@' */
        FILE_LIST
    }

    /** Normalises a null header list. */
    public FormField {
        headers = headers == null ? List.of() : List.copyOf(headers);
    }

    /**
     * Parses the argument of {@code -F}/{@code --form}.
     *
     * @param arg e.g. {@code file=@a.txt;type=text/plain}
     * @return the field
     * @throws CurlParseException when curl would call the option "badly used"
     */
    public static FormField parse(String arg) throws CurlParseException {
        int eq = arg.indexOf('=');
        if (eq < 0) {
            throw new CurlParseException("-F: expected name=content, got '" + arg + "'");
        }
        String name = arg.substring(0, eq);
        String content = arg.substring(eq + 1);
        if (!content.isEmpty() && content.charAt(0) == '@') {
            List<FormField> files = parseUploads(name, content.substring(1));
            if (files.size() == 1) {
                return files.get(0);
            }
            return new FormField(name, Kind.FILE_LIST, content.substring(1), null, null, List.of());
        }
        if (!content.isEmpty() && content.charAt(0) == '<') {
            Part p = parsePart(content, 1, (char) 0);
            return new FormField(name, Kind.FILE_CONTENT, p.word, p.type, p.filename, p.headers);
        }
        Part p = parsePart(content, 0, (char) 0);
        return new FormField(name, Kind.LITERAL, p.word, p.type, p.filename, p.headers);
    }

    /**
     * Parses the argument of {@code --form-string}: the value is always literal, with no {@code @ < ;} processing.
     *
     * @param arg {@code name=value}
     * @return a LITERAL field
     * @throws CurlParseException when there is no '='
     */
    public static FormField parseString(String arg) throws CurlParseException {
        int eq = arg.indexOf('=');
        if (eq < 0) {
            throw new CurlParseException("--form-string: expected name=content, got '" + arg + "'");
        }
        return new FormField(arg.substring(0, eq), Kind.LITERAL, arg.substring(eq + 1), null, null, List.of());
    }

    /**
     * @return one FILE_UPLOAD field per file for {@link Kind#FILE_LIST} (and for FILE_UPLOAD itself the field alone);
     *         empty for the other kinds
     * @throws CurlParseException if the stored spec cannot be parsed (cannot happen for parsed fields)
     */
    public List<FormField> files() throws CurlParseException {
        if (kind == Kind.FILE_UPLOAD) {
            return List.of(this);
        }
        if (kind == Kind.FILE_LIST) {
            return parseUploads(name, value);
        }
        return List.of();
    }

    /**
     * @return every local path this field makes the builder read (files and header files), without the
     *         {@code @}/{@code <} markers; empty for plain literals
     */
    public List<String> filePaths() {
        List<String> out = new ArrayList<>();
        if (kind == Kind.FILE_LIST) {
            try {
                for (FormField f : files()) {
                    out.addAll(f.filePaths());
                }
            } catch (CurlParseException e) {
                // unreachable for fields produced by parse()
            }
            return out;
        }
        if (kind == Kind.FILE_UPLOAD || kind == Kind.FILE_CONTENT) {
            out.add(value);
        }
        for (String h : headers) {
            if (isHeaderFile(h)) {
                out.add(h.substring(1));
            }
        }
        return out;
    }

    static boolean isHeaderFile(String h) {
        return !h.isEmpty() && (h.charAt(0) == '@' || h.charAt(0) == '<');
    }

    // ---- parsing internals (port of get_param_word / get_param_part) ----

    private static final class Part {
        String word = "";
        String type;
        String filename;
        final List<String> headers = new ArrayList<>();
        int end;
    }

    private static List<FormField> parseUploads(String name, String spec) throws CurlParseException {
        List<FormField> out = new ArrayList<>();
        int p = 0;
        while (true) {
            Part part = parsePart(spec, p, ',');
            out.add(new FormField(name, Kind.FILE_UPLOAD, part.word, part.type, part.filename, part.headers));
            p = part.end;
            while (p < spec.length() && spec.charAt(p) != ',') {
                p = scanSegmentEnd(spec, p, ',');
                if (p < spec.length() && spec.charAt(p) == ';') {
                    p++;
                }
            }
            if (p < spec.length() && spec.charAt(p) == ',') {
                p++;
            } else {
                break;
            }
        }
        return out;
    }

    private static boolean isSpace(char c) {
        return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == 0x0b || c == '\f';
    }

    private static String trimEnd(String s) {
        int e = s.length();
        while (e > 0 && isSpace(s.charAt(e - 1))) {
            e--;
        }
        return s.substring(0, e);
    }

    /** Index of the next top-level ';' or endchar (outside double quotes) at or after i, or the end. */
    private static int scanSegmentEnd(String s, int i, char endchar) {
        while (i < s.length()) {
            char c = s.charAt(i);
            if (c == '"') {
                int j = i + 1;
                boolean closed = false;
                while (j < s.length()) {
                    char d = s.charAt(j);
                    if (d == '\\' && j + 1 < s.length()) {
                        j += 2;
                        continue;
                    }
                    if (d == '"') {
                        closed = true;
                        break;
                    }
                    j++;
                }
                if (closed) {
                    i = j + 1;
                    continue;
                }
            } else if (c == ';' || (endchar != 0 && c == endchar)) {
                return i;
            }
            i++;
        }
        return s.length();
    }

    /** Reads one word at p; returns it and sets wordEnd[0] to the index where it stopped. */
    private static String getWord(String s, int p, char endchar, int[] wordEnd) {
        int len = s.length();
        if (p < len && s.charAt(p) == '"') {
            StringBuilder sb = new StringBuilder();
            int i = p + 1;
            boolean closed = false;
            for (; i < len; i++) {
                char c = s.charAt(i);
                if (c == '\\' && i + 1 < len && (s.charAt(i + 1) == '"' || s.charAt(i + 1) == '\\')) {
                    sb.append(s.charAt(i + 1));
                    i++;
                } else if (c == '"') {
                    closed = true;
                    break;
                } else {
                    sb.append(c);
                }
            }
            if (closed) {
                i++;
                while (i < len && s.charAt(i) != ';' && !(endchar != 0 && s.charAt(i) == endchar)) {
                    i++;
                }
                wordEnd[0] = i;
                return sb.toString();
            }
        }
        int i = p;
        while (i < len && s.charAt(i) != ';' && !(endchar != 0 && s.charAt(i) == endchar)) {
            i++;
        }
        wordEnd[0] = i;
        return trimEnd(s.substring(p, i));
    }

    private static boolean prefix(String s, int p, String lower) {
        return s.regionMatches(true, p, lower, 0, lower.length());
    }

    private static Part parsePart(String s, int start, char endchar) throws CurlParseException {
        int len = s.length();
        Part r = new Part();
        int p = start;
        while (p < len && isSpace(s.charAt(p))) {
            p++;
        }
        int[] e = new int[1];
        r.word = getWord(s, p, endchar, e);
        p = e[0];
        boolean typeOpen = false;
        while (p < len && s.charAt(p) == ';') {
            p++;
            int afterSemi = p;
            while (p < len && isSpace(s.charAt(p))) {
                p++;
            }
            if (!typeOpen && prefix(s, p, "type=")) {
                p += 5;
                while (p < len && isSpace(s.charAt(p))) {
                    p++;
                }
                int t = p;
                int q = t;
                while (q < len && s.charAt(q) != '/' && s.charAt(q) != ' ') {
                    q++;
                }
                boolean ok = q > t && q < len && s.charAt(q) == '/';
                if (ok) {
                    int m = q + 1;
                    int m0 = m;
                    while (m < len && ";, \n".indexOf(s.charAt(m)) < 0) {
                        m++;
                    }
                    ok = m > m0;
                }
                if (!ok) {
                    throw new CurlParseException("illegally formatted content-type field in '" + s + "'");
                }
                int end = scanSegmentEnd(s, t, endchar);
                r.type = trimEnd(s.substring(t, end));
                p = end;
                typeOpen = true;
            } else if (prefix(s, p, "filename=")) {
                typeOpen = false;
                p += 9;
                while (p < len && isSpace(s.charAt(p))) {
                    p++;
                }
                r.filename = getWord(s, p, endchar, e);
                p = e[0];
            } else if (prefix(s, p, "headers=")) {
                typeOpen = false;
                p += 8;
                String marker = "";
                if (p < len && (s.charAt(p) == '@' || s.charAt(p) == '<')) {
                    marker = String.valueOf(s.charAt(p));
                    p++;
                }
                String h = getWord(s, p, endchar, e);
                p = e[0];
                if (!h.isEmpty()) {
                    r.headers.add(marker + h);
                }
            } else if (prefix(s, p, "encoder=")) {
                throw new CurlParseException("form option encoder= is not supported");
            } else if (typeOpen) {
                int end = scanSegmentEnd(s, afterSemi, endchar);
                r.type = r.type + ";" + s.substring(afterSemi, end);
                p = end;
            } else {
                p = scanSegmentEnd(s, p, endchar);
            }
        }
        r.end = p;
        return r;
    }
}
