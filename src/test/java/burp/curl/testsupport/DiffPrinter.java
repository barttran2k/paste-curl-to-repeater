package burp.curl.testsupport;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Normalisation and human-readable mismatch reports. */
public final class DiffPrinter {
    private static final Pattern BOUNDARY = Pattern.compile("-{24}[A-Za-z0-9]{22}");
    private static final Pattern USER_AGENT = Pattern.compile("(?m)^(User-Agent: curl/)\\d+\\.\\d+\\.\\d+(?=\r\n|\\z)");

    private DiffPrinter() {
    }

    /**
     * Applies the only allowed normalisation: multipart boundaries are numbered in order of appearance and the
     * version of the default User-Agent is masked.
     * @param raw request bytes
     * @return normalised text, one char per byte (ISO-8859-1)
     */
    public static String normalise(byte[] raw) {
        String text = new String(raw, StandardCharsets.ISO_8859_1);
        int headEnd = text.indexOf("\r\n\r\n");
        String head = headEnd < 0 ? text : text.substring(0, headEnd);
        String rest = headEnd < 0 ? "" : text.substring(headEnd);
        head = USER_AGENT.matcher(head).replaceAll("$1X.Y.Z");
        String all = head + rest;
        Matcher m = BOUNDARY.matcher(all);
        StringBuilder sb = new StringBuilder();
        java.util.Map<String, String> names = new java.util.LinkedHashMap<>();
        while (m.find()) {
            String n = names.computeIfAbsent(m.group(), k -> "<boundary-" + (names.size() + 1) + ">");
            m.appendReplacement(sb, Matcher.quoteReplacement(n));
        }
        m.appendTail(sb);
        return sb.toString();
    }

    /**
     * Makes CR, LF, backslash and every non-printable or non-ASCII byte visible; a real line break follows each
     * {@code \n} so the request stays readable.
     * @param s text with one char per byte
     * @return the visible form
     */
    public static String visible(String s) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '\r' -> sb.append("\\r");
                case '\n' -> sb.append("\\n\n");
                case '\\' -> sb.append("\\\\");
                case '\t' -> sb.append("\\t");
                default -> {
                    if (c < 0x20 || c >= 0x7f) {
                        sb.append(String.format("\\x%02X", (int) c & 0xff));
                    } else {
                        sb.append(c);
                    }
                }
            }
        }
        return sb.toString();
    }

    /**
     * @param a first text
     * @param b second text
     * @return index of the first differing char, or -1 when equal
     */
    public static int firstDiff(String a, String b) {
        int n = Math.min(a.length(), b.length());
        for (int i = 0; i < n; i++) {
            if (a.charAt(i) != b.charAt(i)) {
                return i;
            }
        }
        return a.length() == b.length() ? -1 : n;
    }

    private static String around(String s, int off) {
        int from = Math.max(0, off - 30);
        int to = Math.min(s.length(), off + 30);
        return visible(s.substring(from, to)).replace("\n", "<LF>") + (off >= s.length() ? "  <end of request>" : "");
    }

    /**
     * Compares two request lists after normalisation.
     * @param pasted the pasted text as handed to both sides
     * @param curl what the real curl sent
     * @param ours what the parser built
     * @return null when identical, otherwise a full report
     */
    public static String compare(String pasted, List<byte[]> curl, List<byte[]> ours) {
        StringBuilder sb = new StringBuilder();
        boolean bad = curl.size() != ours.size();
        if (bad) {
            sb.append("request count differs: curl sent ").append(curl.size()).append(", we built ").append(ours.size())
                    .append('\n');
        }
        int n = Math.min(curl.size(), ours.size());
        StringBuilder detail = new StringBuilder();
        for (int i = 0; i < n; i++) {
            String c = normalise(curl.get(i));
            String o = normalise(ours.get(i));
            int d = firstDiff(c, o);
            if (d >= 0) {
                bad = true;
                detail.append("request #").append(i + 1).append(": first difference at offset ").append(d)
                        .append(" (curl ").append(c.length()).append(" bytes, ours ").append(o.length())
                        .append(" bytes)\n  curl: ...").append(around(c, d)).append("...\n  ours: ...")
                        .append(around(o, d)).append("...\n");
            }
        }
        if (!bad) {
            return null;
        }
        sb.append(detail);
        sb.append("\n----- pasted text -----\n").append(pasted).append("\n");
        for (int i = 0; i < curl.size(); i++) {
            sb.append("----- curl request #").append(i + 1).append(" -----\n")
                    .append(visible(normalise(curl.get(i)))).append("\n<end>\n");
        }
        for (int i = 0; i < ours.size(); i++) {
            sb.append("----- our request #").append(i + 1).append(" -----\n")
                    .append(visible(normalise(ours.get(i)))).append("\n<end>\n");
        }
        return sb.toString();
    }
}
