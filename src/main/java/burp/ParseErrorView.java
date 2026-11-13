package burp;

import burp.curl.CurlOptionTable;
import burp.curl.OptionSpec;

import java.util.Optional;

/**
 * Where a parse error is, without showing what the command says there. The pasted command usually carries tokens,
 * passwords and bodies, so the dialog gets a line and column plus an excerpt in which every character is replaced
 * by {@code ·} except whitespace, quotes, backslashes, {@code $}, and the words that are curl options.
 */
final class ParseErrorView {
    /** Characters of masked text shown on each side of the error position. */
    static final int RADIUS = 30;
    /** Stands for a hidden character. */
    static final char HIDDEN = '·';
    /** Stands for a line break inside the excerpt. */
    static final char NEWLINE = '↵';

    private ParseErrorView() {
    }

    /**
     * @param text pasted text
     * @param position error offset (clamped to the text)
     * @return "line L, column C", both 1-based, counted in characters of the pasted text
     */
    static String lineAndColumn(String text, int position) {
        int pos = Math.max(0, Math.min(position, text.length()));
        int line = 1;
        int lineStart = 0;
        for (int i = 0; i < pos; i++) {
            if (text.charAt(i) == '\n') {
                line++;
                lineStart = i + 1;
            }
        }
        return "line " + line + ", column " + (pos - lineStart + 1);
    }

    /**
     * @param text pasted text
     * @param position error offset (clamped to the text)
     * @return a one-line masked excerpt around the position with a visible marker
     */
    static String maskedExcerpt(String text, int position) {
        int pos = Math.max(0, Math.min(position, text.length()));
        int from = Math.max(0, pos - RADIUS);
        int to = Math.min(text.length(), pos + RADIUS);
        // the state of the quotes depends on everything before the window, so the whole text is masked
        String masked = mask(text);
        return (from > 0 ? "..." : "") + flatten(masked.substring(from, pos)) + " >>HERE<< "
                + flatten(masked.substring(pos, to)) + (to < text.length() ? "..." : "");
    }

    private static String flatten(String s) {
        StringBuilder sb = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '\n') {
                sb.append(NEWLINE);
            } else if (c != '\r') {
                sb.append(c);
            }
        }
        return sb.toString();
    }

    private static boolean structural(char c) {
        return c == '\'' || c == '"' || c == '`' || c == '\\' || c == '$' || c == '^';
    }

    /** @return the text with the same length in which everything but the structure is {@link #HIDDEN} */
    static String mask(String text) {
        int n = text.length();
        char[] out = new char[n];
        char quote = 0;
        boolean ansi = false;
        boolean wordStart = true;
        int i = 0;
        while (i < n) {
            char c = text.charAt(i);
            if (quote != 0) {
                if (c == quote) {
                    out[i++] = c;
                    quote = 0;
                    ansi = false;
                } else if (c == '\\' && (quote == '"' || ansi)) {
                    out[i++] = c;
                    if (i < n) {
                        char d = text.charAt(i);
                        out[i] = structural(d) ? d : (Character.isWhitespace(d) ? d : HIDDEN);
                        i++;
                    }
                } else if (c == '$' && quote == '"') {
                    out[i++] = c;
                } else {
                    out[i++] = Character.isWhitespace(c) ? c : HIDDEN;
                }
                continue;
            }
            if (Character.isWhitespace(c)) {
                out[i++] = c;
                wordStart = true;
                continue;
            }
            if (c == '\'' || c == '"') {
                ansi = c == '\'' && i > 0 && text.charAt(i - 1) == '$';
                quote = c;
                out[i++] = c;
                wordStart = false;
                continue;
            }
            if (c == '\\' || c == '^') {
                out[i++] = c;
                if (i < n) {
                    char d = text.charAt(i);
                    if (Character.isWhitespace(d) || structural(d)) {
                        out[i] = d;
                    } else {
                        out[i] = HIDDEN;
                    }
                    i++;
                }
                wordStart = false;
                continue;
            }
            if (structural(c)) {
                out[i++] = c;
                wordStart = false;
                continue;
            }
            if (c == '-' && wordStart) {
                int end = i;
                while (end < n && !Character.isWhitespace(text.charAt(end)) && !structural(text.charAt(end))) {
                    end++;
                }
                int kept = optionPrefixLength(text.substring(i, end));
                for (int k = 0; k < end - i; k++) {
                    out[i + k] = k < kept ? text.charAt(i + k) : HIDDEN;
                }
                i = end;
                wordStart = false;
                continue;
            }
            out[i++] = HIDDEN;
            wordStart = false;
        }
        return new String(out);
    }

    /**
     * @param word a word that starts with {@code -}, without quotes
     * @return how many leading characters are a known curl option (up to and including the first {@code =})
     */
    static int optionPrefixLength(String word) {
        CurlOptionTable table = CurlOptionTable.get();
        if (word.startsWith("--")) {
            int eq = word.indexOf('=');
            String name = eq < 0 ? word.substring(2) : word.substring(2, eq);
            if (!name.isEmpty() && (table.byLong(name).isPresent() || table.resolveLong(name).isPresent())) {
                return eq < 0 ? word.length() : eq + 1;
            }
            return 0;
        }
        // short flags: -s, -sSL; the first flag that takes an argument ends what is kept (-Hx keeps only -H)
        int kept = 0;
        for (int i = 1; i < word.length(); i++) {
            Optional<OptionSpec> s = table.byShort(word.charAt(i));
            if (s.isEmpty()) {
                break;
            }
            kept = i + 1;
            if (s.get().takesArg()) {
                break;
            }
        }
        return kept;
    }
}
