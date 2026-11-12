package burp.curl;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CoderResult;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;

/**
 * The one convention for argument bytes that reach the wire ("wire text").
 *
 * <p>curl sends the bytes of its arguments as they are: {@code -H $'X: caf\xe9'} puts the single byte E9 on the
 * wire. Java {@code String}s cannot hold arbitrary bytes, so every argument that curl sends as-is (header lines,
 * cookies, user agent, referer, user and password, bearer token, method, request target, range, URL path, query and
 * userinfo, form names, values and file names, variable contents) is carried as a {@code String} made by
 * {@link #decode}: valid UTF-8 becomes ordinary text, and every byte that is not part of valid UTF-8 becomes the
 * lone surrogate {@code U+DC00 + byte} (the "surrogateescape" scheme of Python). {@link #encode} is the exact inverse
 * and is the only way such a string is turned into bytes again (header block, multipart parts, Basic credentials).
 * A wire text is therefore still readable text for everything that does not care about the bytes, and mixing it up
 * with a plain text only costs U+FFFD for bytes that were never UTF-8.
 *
 * <p>Arguments that are text for us and never reach the wire as they are (file paths, option names, the {@code -z}
 * date, the {@code --proto-default} scheme) use {@link Token#text()}, the lossy UTF-8 decoding. For messages shown to
 * the user, {@link #display} turns a wire text into plain text.
 */
final class ByteText {
    private static final char ESCAPE_LOW = '\udc80';
    private static final char ESCAPE_HIGH = '\udcff';

    private ByteText() {
    }

    /**
     * @param bytes argument bytes
     * @return the wire text of the bytes (never loses a byte)
     */
    static String decode(byte[] bytes) {
        CharsetDecoder dec = StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT);
        ByteBuffer in = ByteBuffer.wrap(bytes);
        CharBuffer out = CharBuffer.allocate(bytes.length + 1);
        StringBuilder sb = new StringBuilder(bytes.length);
        while (true) {
            CoderResult r = dec.decode(in, out, true);
            out.flip();
            sb.append(out);
            out.clear();
            if (r.isUnderflow()) {
                dec.flush(out);
                out.flip();
                sb.append(out);
                break;
            }
            if (r.isError()) {
                for (int i = 0; i < r.length(); i++) {
                    sb.append((char) (0xdc00 + (in.get() & 0xff)));
                }
            }
        }
        return sb.toString();
    }

    /**
     * @param wireText a string made by {@link #decode} (or plain text)
     * @return its bytes: escapes become their byte, everything else UTF-8
     */
    static byte[] encode(String wireText) {
        ByteArrayOutputStream out = new ByteArrayOutputStream(wireText.length() + 8);
        int start = 0;
        int n = wireText.length();
        for (int i = 0; i < n; i++) {
            char c = wireText.charAt(i);
            if (!Character.isSurrogate(c)) {
                continue;
            }
            if (Character.isHighSurrogate(c) && i + 1 < n && Character.isLowSurrogate(wireText.charAt(i + 1))) {
                i++;
                continue;
            }
            out.writeBytes(wireText.substring(start, i).getBytes(StandardCharsets.UTF_8));
            if (isEscape(c)) {
                out.write(c - 0xdc00);
            } else {
                out.writeBytes(new byte[] {(byte) 0xef, (byte) 0xbf, (byte) 0xbd});
            }
            start = i + 1;
        }
        out.writeBytes(wireText.substring(start).getBytes(StandardCharsets.UTF_8));
        return out.toByteArray();
    }

    /** @return true for a character that stands for one byte that was not valid UTF-8 */
    static boolean isEscape(char c) {
        return c >= ESCAPE_LOW && c <= ESCAPE_HIGH;
    }

    /**
     * @param wireText a wire text
     * @return plain text for messages and display: every escaped byte shows as U+FFFD
     */
    static String display(String wireText) {
        if (wireText == null) {
            return null;
        }
        StringBuilder sb = null;
        for (int i = 0; i < wireText.length(); i++) {
            char c = wireText.charAt(i);
            if (isEscape(c) && !(i > 0 && Character.isHighSurrogate(wireText.charAt(i - 1)))) {
                if (sb == null) {
                    sb = new StringBuilder(wireText.length()).append(wireText, 0, i);
                }
                sb.append('�');
            } else if (sb != null) {
                sb.append(c);
            }
        }
        return sb == null ? wireText : sb.toString();
    }
}
