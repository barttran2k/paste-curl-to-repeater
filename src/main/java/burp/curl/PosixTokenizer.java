package burp.curl;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Splits pasted bash/zsh text into simple commands the way a POSIX shell would, without executing or expanding
 * anything. Shell expansions are kept verbatim inside the word and reported as lossy warnings.
 */
public final class PosixTokenizer implements Tokenizer {

    @Override
    public TokenizeResult tokenize(String input) throws CurlParseException {
        return new Run(input == null ? "" : input).run();
    }

    private static final class Cmd {
        final List<Token> argv = new ArrayList<>();
        byte[] stdin;
        String stdinFile;
    }

    private static final class Heredoc {
        Cmd cmd;
        String delim;
        boolean strip;
        boolean quoted;
        int pos;
    }

    private static final class Run {
        final String s;
        final int end;
        final int[] map;
        int i;
        final List<Cmd> cmds = new ArrayList<>();
        Cmd cur = new Cmd();
        final List<Heredoc> pending = new ArrayList<>();
        final List<Warning> warns = new ArrayList<>();
        final Set<Warning> seen = new HashSet<>();

        Run(String raw) {
            StringBuilder sb = new StringBuilder();
            List<Integer> m = new ArrayList<>();
            int st = raw.startsWith("﻿") ? 1 : 0;
            for (int k = st; k < raw.length(); k++) {
                char c = raw.charAt(k);
                if (c == '\r') {
                    sb.append('\n');
                    m.add(k);
                    if (k + 1 < raw.length() && raw.charAt(k + 1) == '\n') k++;
                } else {
                    sb.append(c);
                    m.add(k);
                }
            }
            m.add(raw.length());
            s = sb.toString();
            end = s.length();
            map = new int[m.size()];
            for (int k = 0; k < map.length; k++) map[k] = m.get(k);
            int p = 0;
            while (p < end && isSpace(s.charAt(p))) p++;
            if (s.startsWith("$ ", p) || s.startsWith("% ", p)) p += 2;
            i = p;
        }

        static boolean isSpace(char c) {
            return c == ' ' || c == '\t' || c == '\n' || c == ' ' || Character.isWhitespace(c);
        }

        static boolean isBlank(char c) {
            return c == ' ' || c == '\t' || c == ' ';
        }

        void warn(Warning w) {
            if (seen.add(w)) warns.add(w);
        }

        char peek(int k) {
            return k < end ? s.charAt(k) : 0;
        }

        CurlParseException err(String msg, int idx) {
            return new CurlParseException(msg, map[Math.min(idx, map.length - 1)]);
        }

        // ---------------------------------------------------------------- main loop

        TokenizeResult run() throws CurlParseException {
            while (i < end) {
                char c = s.charAt(i);
                int cl = contLen(i);
                if (cl > 0) {
                    i += cl;
                    continue;
                }
                if (isBlank(c)) {
                    i++;
                    continue;
                }
                if (c == '\n') {
                    newline();
                    continue;
                }
                if (c == '#') {
                    while (i < end && s.charAt(i) != '\n') i++;
                    continue;
                }
                if (c == '|') {
                    i++;
                    if (peek(i) == '|' || peek(i) == '&') i++;
                    endCmd();
                    continue;
                }
                if (c == ';') {
                    i++;
                    endCmd();
                    continue;
                }
                if (c == '&') {
                    char n = peek(i + 1);
                    if (n == '&') {
                        i += 2;
                        endCmd();
                    } else if (n == '>') {
                        i += 2;
                        if (peek(i) == '>') i++;
                        discardTarget();
                    } else {
                        i++;
                        endCmd();
                    }
                    continue;
                }
                int j = i;
                while (j < end && s.charAt(j) >= '0' && s.charAt(j) <= '9') j++;
                if (j > i && j < end && (s.charAt(j) == '>' || s.charAt(j) == '<')) {
                    i = j;
                    c = s.charAt(i);
                }
                if (c == '>') {
                    i++;
                    char n = peek(i);
                    if (n == '>' || n == '|' || n == '&') i++;
                    discardTarget();
                    continue;
                }
                if (c == '<') {
                    redirectIn();
                    continue;
                }
                int before = i;
                Token t = readWord();
                if (t != null) cur.argv.add(t);
                if (i == before) i++;
            }
            endCmd();
            List<CommandLine> out = new ArrayList<>();
            for (Cmd c : cmds) out.add(new CommandLine(c.argv, c.stdin, c.stdinFile));
            return new TokenizeResult(out, warns);
        }

        void endCmd() {
            if (!cur.argv.isEmpty()) cmds.add(cur);
            cur = new Cmd();
        }

        void skipBlanks() {
            while (i < end) {
                int cl = contLen(i);
                if (cl > 0) {
                    i += cl;
                } else if (isBlank(s.charAt(i))) {
                    i++;
                } else {
                    break;
                }
            }
        }

        void discardTarget() throws CurlParseException {
            skipBlanks();
            readWord();
        }

        void newline() throws CurlParseException {
            i++;
            if (!pending.isEmpty()) {
                for (Heredoc h : pending) readBody(h);
                pending.clear();
            } else if (!cur.argv.isEmpty()) {
                int k = i;
                while (k < end && isSpace(s.charAt(k))) k++;
                if (k < end && s.charAt(k) == '-') {
                    warn(Warning.note("Newline without backslash treated as line continuation (next line starts with '-')"));
                    i = k;
                    return;
                }
            }
            endCmd();
        }

        /** Length of a line continuation at p (strict, or lenient with trailing blanks), else 0. */
        int contLen(int p) {
            if (p >= end || s.charAt(p) != '\\') return 0;
            int j = p + 1;
            if (j < end && s.charAt(j) == '\n') return 2;
            while (j < end && isBlank(s.charAt(j))) j++;
            if (j > p + 1 && j < end && s.charAt(j) == '\n') {
                warn(Warning.note("Backslash followed by blanks before newline treated as line continuation"));
                return j + 1 - p;
            }
            return 0;
        }

        // ---------------------------------------------------------------- redirections

        void redirectIn() throws CurlParseException {
            int op = i;
            if (peek(i + 1) == '<') {
                if (peek(i + 2) == '<') {
                    i += 3;
                    skipBlanks();
                    Token t = readWord();
                    if (t != null) {
                        byte[] b = t.bytes();
                        byte[] r = java.util.Arrays.copyOf(b, b.length + 1);
                        r[b.length] = '\n';
                        cur.stdin = r;
                    }
                    return;
                }
                i += 2;
                Heredoc h = new Heredoc();
                if (peek(i) == '-') {
                    h.strip = true;
                    i++;
                }
                skipBlanks();
                Token d = readWord();
                if (d == null) throw err("Missing heredoc delimiter after <<", op);
                h.delim = d.text();
                h.quoted = d.quoted();
                h.cmd = cur;
                h.pos = op;
                pending.add(h);
                return;
            }
            i++;
            if (peek(i) == '&') {
                i++;
                discardTarget();
                return;
            }
            if (peek(i) == '>') i++;
            skipBlanks();
            Token t = readWord();
            if (t != null) cur.stdinFile = t.text();
        }

        void readBody(Heredoc h) throws CurlParseException {
            StringBuilder raw = new StringBuilder();
            while (true) {
                if (i >= end) throw err("Unterminated heredoc, missing delimiter line '" + h.delim + "'", h.pos);
                int e = s.indexOf('\n', i);
                int le = e < 0 ? end : e;
                String line = s.substring(i, le);
                i = e < 0 ? end : e + 1;
                if (h.strip) {
                    int k = 0;
                    while (k < line.length() && line.charAt(k) == '\t') k++;
                    line = line.substring(k);
                }
                if (line.equals(h.delim)) break;
                raw.append(line).append('\n');
            }
            String body = h.quoted ? raw.toString() : processHeredoc(raw.toString());
            h.cmd.stdin = body.getBytes(StandardCharsets.UTF_8);
        }

        String processHeredoc(String raw) {
            StringBuilder o = new StringBuilder();
            int n = raw.length();
            for (int k = 0; k < n; k++) {
                char c = raw.charAt(k);
                if (c == '\\' && k + 1 < n) {
                    char nx = raw.charAt(k + 1);
                    if (nx == '\n') {
                        k++;
                        continue;
                    }
                    if (nx == '$' || nx == '\\' || nx == '`') {
                        o.append(nx);
                        k++;
                        continue;
                    }
                } else if (c == '$' && k + 1 < n) {
                    char nx = raw.charAt(k + 1);
                    String snip = null;
                    if (nx == '{' || nx == '(') {
                        snip = "$" + nx;
                    } else if (isNameStart(nx)) {
                        int e = k + 1;
                        while (e < n && isNameChar(raw.charAt(e))) e++;
                        snip = raw.substring(k, e);
                    } else if (isSpecialParam(nx)) {
                        snip = "$" + nx;
                    }
                    if (snip != null) {
                        warn(Warning.lossy("Heredoc body contains shell expansion that is not evaluated: " + snip));
                    }
                } else if (c == '`') {
                    warn(Warning.lossy("Heredoc body contains backtick command substitution that is not evaluated"));
                }
                o.append(c);
            }
            return o.toString();
        }

        // ---------------------------------------------------------------- words

        static boolean isNameStart(char c) {
            return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_';
        }

        static boolean isNameChar(char c) {
            return isNameStart(c) || (c >= '0' && c <= '9');
        }

        static boolean isSpecialParam(char c) {
            return (c >= '0' && c <= '9') || "@*#?-$!".indexOf(c) >= 0;
        }

        void lit(ByteArrayOutputStream b) {
            int cp = s.codePointAt(i);
            i += Character.charCount(cp);
            putCp(b, cp);
        }

        static void putCp(ByteArrayOutputStream b, int cp) {
            if (cp < 0x80) {
                b.write(cp);
            } else if (cp < 0x800) {
                b.write(0xC0 | (cp >> 6));
                b.write(0x80 | (cp & 0x3F));
            } else if (cp < 0x10000) {
                b.write(0xE0 | (cp >> 12));
                b.write(0x80 | ((cp >> 6) & 0x3F));
                b.write(0x80 | (cp & 0x3F));
            } else if (cp <= 0x10FFFF) {
                b.write(0xF0 | (cp >> 18));
                b.write(0x80 | ((cp >> 12) & 0x3F));
                b.write(0x80 | ((cp >> 6) & 0x3F));
                b.write(0x80 | (cp & 0x3F));
            } else {
                putCp(b, 0xFFFD);
            }
        }

        void raw(ByteArrayOutputStream b, String t) {
            byte[] x = t.getBytes(StandardCharsets.UTF_8);
            b.write(x, 0, x.length);
        }

        /** Reads one word starting at i; returns null when no word starts here. */
        Token readWord() throws CurlParseException {
            ByteArrayOutputStream b = new ByteArrayOutputStream();
            boolean any = false;
            boolean q = false;
            loop:
            while (i < end) {
                char c = s.charAt(i);
                int cl = contLen(i);
                if (cl > 0) {
                    i += cl;
                    continue;
                }
                switch (c) {
                    case ' ': case '\t': case '\n': case ' ': case '|': case ';': case '<': case '>':
                        break loop;
                    case '&': {
                        char n = peek(i + 1);
                        if (any && n != 0 && !isSpace(n) && n != '&' && n != '>') {
                            b.write('&');
                            i++;
                            continue;
                        }
                        break loop;
                    }
                    case '\'': {
                        int e = s.indexOf('\'', i + 1);
                        if (e < 0) throw err("Unterminated single quote", i);
                        raw(b, s.substring(i + 1, e));
                        i = e + 1;
                        any = q = true;
                        continue;
                    }
                    case '"':
                        readDouble(b, false);
                        any = q = true;
                        continue;
                    case '“': case '”':
                        curlyNote();
                        readDouble(b, true);
                        any = q = true;
                        continue;
                    case '‘': case '’': {
                        curlyNote();
                        int e = i + 1;
                        while (e < end && !(isCurlySingle(s.charAt(e)) && closesCurly(e))) e++;
                        if (e >= end) throw err("Unterminated curly single quote", i);
                        raw(b, s.substring(i + 1, e));
                        i = e + 1;
                        any = q = true;
                        continue;
                    }
                    case '\\':
                        if (i + 1 >= end) {
                            b.write('\\');
                            i++;
                        } else {
                            i++;
                            lit(b);
                        }
                        any = q = true;
                        continue;
                    case '$': {
                        char n = peek(i + 1);
                        if (n == '\'') {
                            ansi(b);
                            any = q = true;
                        } else if (n == '"') {
                            i++;
                            readDouble(b, false);
                            any = q = true;
                        } else {
                            expansion(b);
                            any = true;
                        }
                        continue;
                    }
                    case '`':
                        expansion(b);
                        any = true;
                        continue;
                    default:
                        lit(b);
                        any = true;
                }
            }
            if (!any) return null;
            return Token.of(b.toByteArray(), q);
        }

        static boolean isCurlySingle(char c) {
            return c == '\u2018' || c == '\u2019';
        }

        /** A curly quote at p closes its segment only before whitespace, end of input or ; | & < > ). */
        boolean closesCurly(int p) {
            char n = peek(p + 1);
            return n == 0 || isSpace(n) || ";|&<>)".indexOf(n) >= 0;
        }

        void curlyNote() {
            warn(Warning.note("Curly quotes were treated as regular quotes"));
        }

        /** At a '$' (or backtick) outside single quotes: copy a balanced expansion verbatim, or a plain '$'. */
        void expansion(ByteArrayOutputStream b) throws CurlParseException {
            int e = scanExpansion(i);
            if (e < 0) {
                b.write('$');
                i++;
                return;
            }
            String text = s.substring(i, e);
            raw(b, text);
            warn(Warning.lossy("Shell expansion is not evaluated and kept as literal text: " + text));
            i = e;
        }

        /** @return end index of the expansion starting at p, or -1 when '$' is just a literal dollar. */
        int scanExpansion(int p) throws CurlParseException {
            char c = s.charAt(p);
            if (c == '`') return scanBacktick(p);
            char n = peek(p + 1);
            if (n == '(') return scanParen(p + 2, p);
            if (n == '{') return scanBrace(p + 2, p);
            if (isNameStart(n)) {
                int e = p + 1;
                while (e < end && isNameChar(s.charAt(e))) e++;
                return e;
            }
            if (n != 0 && isSpecialParam(n)) return p + 2;
            return -1;
        }

        int scanBacktick(int p) throws CurlParseException {
            int j = p + 1;
            while (j < end) {
                char c = s.charAt(j);
                if (c == '\\') {
                    j += 2;
                } else if (c == '`') {
                    return j + 1;
                } else {
                    j++;
                }
            }
            throw err("Unterminated backtick command substitution", p);
        }

        int skipSingle(int j) throws CurlParseException {
            int e = s.indexOf('\'', j + 1);
            if (e < 0) throw err("Unterminated single quote", j);
            return e + 1;
        }

        int skipAnsi(int j) throws CurlParseException {
            int k = j + 2;
            while (k < end) {
                char c = s.charAt(k);
                if (c == '\\') k += 2;
                else if (c == '\'') return k + 1;
                else k++;
            }
            throw err("Unterminated $'...' quote", j);
        }

        int skipDouble(int j) throws CurlParseException {
            int k = j + 1;
            while (k < end) {
                char c = s.charAt(k);
                if (c == '\\') {
                    k += 2;
                } else if (c == '"') {
                    return k + 1;
                } else if (c == '$' && peek(k + 1) == '(') {
                    k = scanParen(k + 2, k);
                } else if (c == '$' && peek(k + 1) == '{') {
                    k = scanBrace(k + 2, k);
                } else if (c == '`') {
                    k = scanBacktick(k);
                } else {
                    k++;
                }
            }
            throw err("Unterminated double quote", j);
        }

        int scanParen(int j, int opener) throws CurlParseException {
            int depth = 1;
            while (j < end) {
                char c = s.charAt(j);
                if (c == '\\') {
                    j += 2;
                } else if (c == '\'') {
                    j = skipSingle(j);
                } else if (c == '$' && peek(j + 1) == '\'') {
                    j = skipAnsi(j);
                } else if (c == '"') {
                    j = skipDouble(j);
                } else if (c == '`') {
                    j = scanBacktick(j);
                } else if (c == '(') {
                    depth++;
                    j++;
                } else if (c == ')') {
                    depth--;
                    j++;
                    if (depth == 0) return j;
                } else {
                    j++;
                }
            }
            throw err("Unterminated $( command substitution", opener);
        }

        int scanBrace(int j, int opener) throws CurlParseException {
            int depth = 1;
            while (j < end) {
                char c = s.charAt(j);
                if (c == '\\') {
                    j += 2;
                } else if (c == '\'') {
                    j = skipSingle(j);
                } else if (c == '"') {
                    j = skipDouble(j);
                } else if (c == '`') {
                    j = scanBacktick(j);
                } else if (c == '$' && peek(j + 1) == '(') {
                    j = scanParen(j + 2, j);
                } else if (c == '{') {
                    depth++;
                    j++;
                } else if (c == '}') {
                    depth--;
                    j++;
                    if (depth == 0) return j;
                } else {
                    j++;
                }
            }
            throw err("Unterminated ${ parameter expansion", opener);
        }

        /** At the opening double quote (regular or curly). */
        void readDouble(ByteArrayOutputStream b, boolean curly) throws CurlParseException {
            int open = i;
            i++;
            while (true) {
                if (i >= end) throw err(curly ? "Unterminated curly double quote" : "Unterminated double quote", open);
                char c = s.charAt(i);
                if (curly ? ((c == '“' || c == '”') && closesCurly(i)) : c == '"') {
                    i++;
                    return;
                }
                if (c == '\\') {
                    char n = peek(i + 1);
                    if (n == '\n') {
                        i += 2;
                    } else if (n == '$' || n == '`' || n == '"' || n == '\\') {
                        b.write(n);
                        i += 2;
                    } else {
                        b.write('\\');
                        i++;
                    }
                } else if (c == '$' || c == '`') {
                    expansion(b);
                } else {
                    lit(b);
                }
            }
        }

        static int hexVal(char c) {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return -1;
        }

        /** At "$'". */
        void ansi(ByteArrayOutputStream b) throws CurlParseException {
            int open = i;
            i += 2;
            while (true) {
                if (i >= end) throw err("Unterminated $'...' quote", open);
                char c = s.charAt(i);
                if (c == '\'') {
                    i++;
                    return;
                }
                if (c != '\\') {
                    lit(b);
                    continue;
                }
                if (i + 1 >= end) throw err("Unterminated $'...' quote", open);
                char n = s.charAt(i + 1);
                i += 2;
                switch (n) {
                    case 'a': b.write(7); break;
                    case 'b': b.write(8); break;
                    case 'e': case 'E': b.write(27); break;
                    case 'f': b.write(12); break;
                    case 'n': b.write(10); break;
                    case 'r': b.write(13); break;
                    case 't': b.write(9); break;
                    case 'v': b.write(11); break;
                    case '\\': case '\'': case '"': case '?': b.write(n); break;
                    case '0': case '1': case '2': case '3': case '4': case '5': case '6': case '7': {
                        int v = n - '0';
                        int cnt = 1;
                        while (cnt < 3 && i < end && s.charAt(i) >= '0' && s.charAt(i) <= '7') {
                            v = v * 8 + (s.charAt(i) - '0');
                            i++;
                            cnt++;
                        }
                        b.write(v & 0xFF);
                        break;
                    }
                    case 'x': case 'u': case 'U': {
                        int max = n == 'x' ? 2 : n == 'u' ? 4 : 8;
                        long v = 0;
                        int cnt = 0;
                        while (cnt < max && i < end && hexVal(s.charAt(i)) >= 0) {
                            v = v * 16 + hexVal(s.charAt(i));
                            i++;
                            cnt++;
                        }
                        if (cnt == 0) {
                            b.write('\\');
                            b.write(n);
                        } else if (n == 'x') {
                            b.write((int) v);
                        } else {
                            putCp(b, v > 0x10FFFF ? 0xFFFD : (int) v);
                        }
                        break;
                    }
                    case 'c': {
                        if (i < end && s.charAt(i) < 0x80) {
                            char x = s.charAt(i);
                            i++;
                            b.write(x == '?' ? 0x7f : (x & 0x1f));
                        } else {
                            b.write('\\');
                            b.write('c');
                        }
                        break;
                    }
                    default:
                        b.write('\\');
                        i--;
                        lit(b);
                }
            }
        }
    }
}
