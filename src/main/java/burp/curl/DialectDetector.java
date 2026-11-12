package burp.curl;

/**
 * Decides whether pasted text is POSIX-shell or Windows cmd.exe dialect.
 *
 * <p>CMD when either holds, otherwise POSIX:
 * <ol>
 *   <li>A: a {@code ^"} occurs at a word start (start of text or directly after whitespace), or</li>
 *   <li>B: a line that is not the last non-blank line ends (ignoring trailing spaces, tabs, CR) with
 *       {@code ^} that follows whitespace or a double quote.</li>
 * </ol>
 * Veto: if some non-last line ends with a backslash (POSIX continuation) and no line ends with
 * {@code ^}, the text is POSIX even if rule A fired. So {@code '^"foo'} (caret-quote glued to a
 * quote) and JSON bodies such as {@code {"re":"^"}} are not detected as CMD; a single-quoted
 * string that contains whitespace followed by {@code ^"} inside a command without backslash
 * continuations is the residual misdetection.
 */
public final class DialectDetector {
    /** The shell dialect of pasted text. */
    public enum Dialect {
        /** bash / zsh / sh. */
        POSIX,
        /** Windows cmd.exe. */
        CMD
    }

    private DialectDetector() { }

    /**
     * @param input pasted text (may be null)
     * @return the detected dialect
     */
    public static Dialect detect(String input) {
        if (input == null || input.isEmpty()) {
            return Dialect.POSIX;
        }
        String t = input.charAt(0) == '﻿' ? input.substring(1) : input;
        t = t.replace("\r\n", "\n").replace('\r', '\n');
        String[] lines = t.split("\n", -1);
        int lastNonBlank = -1;
        for (int k = lines.length - 1; k >= 0; k--) {
            if (!lines[k].isBlank()) {
                lastNonBlank = k;
                break;
            }
        }
        boolean ruleB = false;
        boolean posixContinuation = false;
        for (int k = 0; k < lastNonBlank; k++) {
            String line = stripTrailingBlanks(lines[k]);
            if (line.length() >= 2 && line.charAt(line.length() - 1) == '^') {
                char prev = line.charAt(line.length() - 2);
                if (prev == ' ' || prev == '\t' || prev == '"') {
                    ruleB = true;
                }
            } else if (line.endsWith("\\")) {
                posixContinuation = true;
            }
        }
        if (ruleB) {
            return Dialect.CMD;
        }
        if (posixContinuation) {
            return Dialect.POSIX;
        }
        int idx = t.indexOf("^\"");
        while (idx >= 0) {
            if (idx == 0 || Character.isWhitespace(t.charAt(idx - 1))) {
                return Dialect.CMD;
            }
            idx = t.indexOf("^\"", idx + 1);
        }
        return Dialect.POSIX;
    }

    private static String stripTrailingBlanks(String s) {
        int e = s.length();
        while (e > 0 && (s.charAt(e - 1) == ' ' || s.charAt(e - 1) == '\t')) {
            e--;
        }
        return s.substring(0, e);
    }
}
