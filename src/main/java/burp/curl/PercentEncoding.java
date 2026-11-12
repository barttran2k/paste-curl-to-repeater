package burp.curl;

import java.io.ByteArrayOutputStream;

/** Percent-encoding and the hex digits behind it: the one copy used by the URL, the builder and the variables. */
final class PercentEncoding {
    private static final char[] UPPER = "0123456789ABCDEF".toCharArray();
    private static final char[] LOWER = "0123456789abcdef".toCharArray();

    private PercentEncoding() {
    }

    /** @return true for {@code A-Za-z0-9-._~} */
    static boolean unreserved(int c) {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '.'
                || c == '_' || c == '~';
    }

    /** Appends {@code %XX} for the low 8 bits of {@code b}. */
    static void append(StringBuilder sb, int b, boolean upperCase) {
        char[] hex = upperCase ? UPPER : LOWER;
        sb.append('%').append(hex[(b >> 4) & 15]).append(hex[b & 15]);
    }

    /**
     * @param in the bytes
     * @param spaceAsPlus true for {@code --data-urlencode} (space becomes '+'), false for the {@code :url} variable
     *                    function (space becomes %20)
     * @return everything except {@code A-Za-z0-9-._~} as upper case {@code %XX}
     */
    static byte[] encode(byte[] in, boolean spaceAsPlus) {
        ByteArrayOutputStream o = new ByteArrayOutputStream(in.length * 3);
        for (byte x : in) {
            int c = x & 0xff;
            if (unreserved(c)) {
                o.write(c);
            } else if (c == ' ' && spaceAsPlus) {
                o.write('+');
            } else {
                o.write('%');
                o.write(UPPER[c >> 4]);
                o.write(UPPER[c & 15]);
            }
        }
        return o.toByteArray();
    }
}
