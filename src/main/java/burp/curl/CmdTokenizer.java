package burp.curl;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Tokenizer for the Windows cmd.exe dialect, as produced by the browsers' "Copy as cURL (cmd)" menu items.
 *
 * <p>Two layers, like the real thing: (1) the cmd.exe layer removes {@code ^} escapes, joins
 * {@code ^<LF>} continuations, splits on unquoted {@code & && | ||}, drops redirections; (2) the argument
 * layer splits the resulting command line into argv. Nothing is executed and no variable is expanded.
 *
 * <p>Backslashes and quotes in the argument layer depend on who wrote the argument, told by how it is opened:
 * <ul>
 * <li>An argument that starts with a caret-escaped quote ({@code ^"...^"}) comes from a browser's "Copy as cURL
 * (cmd)" menu item. The generators double every backslash and write a literal quote as {@code \^"}, so inside the
 * quotes {@code \\} gives one backslash and {@code \"} gives a quote (the inverse of the generators).</li>
 * <li>An argument that starts with a bare quote ({@code "..."}) or has no quote is hand-written and follows the exact
 * rules of the Microsoft C runtime that curl.exe uses to split its command line: 2n backslashes followed by a
 * quote give n backslashes and the quote toggles quoting; 2n+1 backslashes followed by a quote give n backslashes and
 * a literal quote; backslashes not followed by a quote are literal (so {@code "C:\\tmp"} keeps both); inside
 * quotes {@code ""} is one literal quote.</li>
 * </ul>
 */
public final class CmdTokenizer implements Tokenizer {
    private static final Pattern PROMPT =
            Pattern.compile("\\A[ \\t\\n]*[A-Za-z]:\\\\[^<>|\"\\n]*>[ \\t]*");
    private static final Pattern VAR_NAME = Pattern.compile("[A-Za-z_][^%\\s\"&|<>^]*");
    private static final Pattern HEX2 = Pattern.compile("[0-9A-Fa-f]{2}");

    /** A character that survived the cmd layer. esc: it was written as ^X. pos: index in preprocessed text. */
    private record Cell(char c, boolean esc, int pos) { }

    private record Word(int end, List<Cell> cells) { }

    private int[] origIndex;
    private String text;

    @Override
    public TokenizeResult tokenize(String input) throws CurlParseException {
        List<CommandLine> commands = new ArrayList<>();
        List<Warning> warnings = new ArrayList<>();
        if (input == null || input.isEmpty()) {
            return new TokenizeResult(commands, warnings);
        }
        preprocess(input);

        List<List<Cell>> segments = new ArrayList<>();
        List<String> stdinFiles = new ArrayList<>();
        cmdLayer(segments, stdinFiles);

        Set<String> vars = new LinkedHashSet<>();
        for (int s = 0; s < segments.size(); s++) {
            List<Cell> seg = segments.get(s);
            scanVariables(seg, vars);
            List<Token> argv = argumentLayer(seg);
            if (!argv.isEmpty()) {
                commands.add(new CommandLine(argv, null, stdinFiles.get(s)));
            }
        }
        for (String v : vars) {
            warnings.add(Warning.lossy("%" + v + "% would be expanded by cmd.exe; kept verbatim"));
        }
        return new TokenizeResult(commands, warnings);
    }

    // ---- pre-processing ----------------------------------------------------------------------

    private void preprocess(String input) {
        StringBuilder sb = new StringBuilder(input.length());
        List<Integer> map = new ArrayList<>(input.length());
        int i = input.charAt(0) == '﻿' ? 1 : 0;
        for (; i < input.length(); i++) {
            char c = input.charAt(i);
            if (c == '\r') {
                if (i + 1 < input.length() && input.charAt(i + 1) == '\n') {
                    continue;
                }
                c = '\n';
            }
            sb.append(c);
            map.add(i);
        }
        int cut = 0;
        var m = PROMPT.matcher(sb);
        if (m.find()) {
            cut = m.end();
        }
        text = sb.substring(cut);
        origIndex = new int[text.length()];
        for (int k = 0; k < text.length(); k++) {
            origIndex[k] = map.get(k + cut);
        }
    }

    private int orig(int pos) {
        return pos >= 0 && pos < origIndex.length ? origIndex[pos] : text.length();
    }

    // ---- cmd.exe layer -----------------------------------------------------------------------

    private void cmdLayer(List<List<Cell>> segments, List<String> stdinFiles) throws CurlParseException {
        final int n = text.length();
        List<Cell> cur = new ArrayList<>();
        String stdinFile = null;
        boolean inQuote = false;
        int i = 0;
        while (i < n) {
            char c = text.charAt(i);
            if (c == '\n') {
                // cmd.exe ends the line even inside quotes; a quote left open here is the cmd layer's
                // business (it is legal for e.g. "a\"b"). Unbalanced quotes are judged by the argument layer.
                inQuote = false;
                segments.add(cur);
                stdinFiles.add(stdinFile);
                cur = new ArrayList<>();
                stdinFile = null;
                i++;
                continue;
            }
            if (inQuote) {
                cur.add(new Cell(c, false, i));
                if (c == '"') {
                    inQuote = false;
                }
                i++;
                continue;
            }
            switch (c) {
                case '^' -> {
                    if (i + 1 >= n) {
                        i++;
                    } else if (text.charAt(i + 1) == '\n') {
                        // ^<LF> is a line continuation; browsers emit ^<LF><LF> for a literal newline.
                        if (i + 2 < n && text.charAt(i + 2) == '\n') {
                            cur.add(new Cell('\n', true, i + 2));
                            i += 3;
                        } else {
                            i += 2;
                        }
                    } else {
                        cur.add(new Cell(text.charAt(i + 1), true, i + 1));
                        i += 2;
                    }
                }
                case '"' -> {
                    inQuote = true;
                    cur.add(new Cell(c, false, i));
                    i++;
                }
                case '&', '|' -> {
                    segments.add(cur);
                    stdinFiles.add(stdinFile);
                    cur = new ArrayList<>();
                    stdinFile = null;
                    i++;
                    if (i < n && text.charAt(i) == c) {
                        i++;
                    }
                }
                case '>' -> {
                    stripFdDigit(cur);
                    i++;
                    if (i < n && text.charAt(i) == '>') {
                        i++;
                    }
                    if (i + 1 < n && text.charAt(i) == '&' && Character.isDigit(text.charAt(i + 1))) {
                        i += 2;
                    } else {
                        Word w = readWord(i);
                        argumentLayer(w.cells()); // validates quoting only; the target is discarded
                        i = w.end();
                    }
                }
                case '<' -> {
                    Word w = readWord(i + 1);
                    i = w.end();
                    List<Token> t = argumentLayer(w.cells());
                    if (!t.isEmpty()) {
                        stdinFile = t.get(0).text();
                    }
                }
                default -> {
                    cur.add(new Cell(c, false, i));
                    i++;
                }
            }
        }
        segments.add(cur);
        stdinFiles.add(stdinFile);
    }

    /** Removes a file-descriptor digit directly before a redirection operator ("2>" and "1>>"). */
    private static void stripFdDigit(List<Cell> cur) {
        int k = cur.size();
        if (k == 0) {
            return;
        }
        Cell last = cur.get(k - 1);
        if (last.esc() || last.c() < '0' || last.c() > '9') {
            return;
        }
        if (k == 1 || (!cur.get(k - 2).esc() && (cur.get(k - 2).c() == ' ' || cur.get(k - 2).c() == '\t'))) {
            cur.remove(k - 1);
        }
    }

    /** Reads one word (a redirection target) with cmd rules; stops before whitespace or an operator. */
    private Word readWord(int start) throws CurlParseException {
        final int n = text.length();
        int i = start;
        while (i < n && (text.charAt(i) == ' ' || text.charAt(i) == '\t')) {
            i++;
        }
        List<Cell> cells = new ArrayList<>();
        boolean inQuote = false;
        while (i < n) {
            char c = text.charAt(i);
            if (c == '\n') {
                break;
            }
            if (inQuote) {
                cells.add(new Cell(c, false, i));
                if (c == '"') {
                    inQuote = false;
                }
                i++;
                continue;
            }
            if (c == ' ' || c == '\t' || c == '&' || c == '|' || c == '<' || c == '>') {
                break;
            }
            if (c == '^') {
                if (i + 1 < n && text.charAt(i + 1) != '\n') {
                    cells.add(new Cell(text.charAt(i + 1), true, i + 1));
                    i += 2;
                } else {
                    i += (i + 1 < n) ? 2 : 1;
                }
                continue;
            }
            if (c == '"') {
                inQuote = true;
            }
            cells.add(new Cell(c, false, i));
            i++;
        }
        return new Word(i, cells);
    }

    // ---- %VAR% reporting ---------------------------------------------------------------------

    private static void scanVariables(List<Cell> seg, Set<String> out) {
        int i = 0;
        while (i < seg.size()) {
            Cell a = seg.get(i);
            if (a.c() != '%' || a.esc()) {
                i++;
                continue;
            }
            int j = i + 1;
            StringBuilder name = new StringBuilder();
            boolean ok = true;
            while (j < seg.size()) {
                Cell b = seg.get(j);
                if (b.c() == '%' && !b.esc()) {
                    break;
                }
                if (b.esc()) {
                    ok = false;
                    break;
                }
                name.append(b.c());
                j++;
            }
            if (ok && j < seg.size() && VAR_NAME.matcher(name).matches()
                    && !HEX2.matcher(name).matches()) {
                out.add(name.toString());
                i = j + 1;
            } else {
                i++;
            }
        }
    }

    // ---- argument layer ----------------------------------------------------------------------

    private List<Token> argumentLayer(List<Cell> cells) throws CurlParseException {
        List<Token> argv = new ArrayList<>();
        final int n = cells.size();
        int i = 0;
        while (true) {
            while (i < n && isSep(cells.get(i).c())) {
                i++;
            }
            if (i >= n) {
                break;
            }
            StringBuilder sb = new StringBuilder();
            boolean quoted = false;
            boolean inQ = false;
            int qOpen = -1;
            // opened with ^" : a browser generator wrote it (see the class comment)
            final boolean generated = cells.get(i).esc() && cells.get(i).c() == '"';
            while (i < n) {
                Cell cell = cells.get(i);
                char c = cell.c();
                if (!inQ) {
                    if (isSep(c)) {
                        break;
                    }
                    if (c == '\\') {
                        int k = 0;
                        while (i + k < n && cells.get(i + k).c() == '\\') {
                            k++;
                        }
                        if (i + k < n && cells.get(i + k).c() == '"') {
                            // MS CRT: 2n backslashes + quote -> n backslashes, quote toggles; 2n+1 -> literal quote.
                            sb.append("\\".repeat(k / 2));
                            quoted = true;
                            if (k % 2 == 1) {
                                sb.append('"');
                            } else {
                                inQ = true;
                                qOpen = cells.get(i + k).pos();
                            }
                            i += k + 1;
                        } else {
                            sb.append("\\".repeat(k));
                            i += k;
                        }
                    } else if (c == '"') {
                        inQ = true;
                        quoted = true;
                        qOpen = cell.pos();
                        i++;
                    } else {
                        sb.append(c);
                        quoted |= cell.esc();
                        i++;
                    }
                } else if (!generated && c == '\\') {
                    int k = 0;
                    while (i + k < n && cells.get(i + k).c() == '\\') {
                        k++;
                    }
                    if (i + k < n && cells.get(i + k).c() == '"') {
                        sb.append("\\".repeat(k / 2));
                        quoted = true;
                        if (k % 2 == 1) {
                            sb.append('"');
                            i += k + 1;
                        } else {
                            i += k; // the quote itself is handled next: it closes quoting or is half of ""
                        }
                    } else {
                        sb.append("\\".repeat(k));
                        i += k;
                    }
                } else {
                    if (c == '\\' && i + 1 < n && cells.get(i + 1).c() == '\\') {
                        sb.append('\\');
                        quoted = true;
                        i += 2;
                    } else if (c == '\\' && i + 1 < n && cells.get(i + 1).c() == '"') {
                        sb.append('"');
                        quoted = true;
                        i += 2;
                    } else if (c == '"') {
                        if (i + 1 < n && cells.get(i + 1).c() == '"') {
                            sb.append('"');
                            i += 2;
                        } else {
                            inQ = false;
                            i++;
                        }
                    } else {
                        sb.append(c);
                        quoted |= cell.esc();
                        i++;
                    }
                }
            }
            if (inQ) {
                throw new CurlParseException("Unterminated double quote", orig(qOpen));
            }
            argv.add(Token.of(sb.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8), quoted));
        }
        return argv;
    }

    private static boolean isSep(char c) {
        return c == ' ' || c == '\t' || c == '\n';
    }
}
