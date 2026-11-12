package burp.curl;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/** One shell word. Holds bytes, not a String, so $'\xff' and binary data survive. */
public final class Token {
    private final byte[] bytes;
    private final boolean quoted;

    private Token(byte[] bytes, boolean quoted) {
        this.bytes = bytes;
        this.quoted = quoted;
    }

    /**
     * Creates a token from raw bytes (copied).
     * @param bytes the word's bytes
     * @param quoted true if any part of the word was inside quotes
     * @return the token
     */
    public static Token of(byte[] bytes, boolean quoted) {
        return new Token(bytes.clone(), quoted);
    }

    /**
     * Creates an unquoted token from text.
     * @param text the word, encoded as UTF-8
     * @return the token with quoted=false
     */
    public static Token of(String text) {
        return new Token(text.getBytes(StandardCharsets.UTF_8), false);
    }

    /** @return a defensive copy of the word's bytes */
    public byte[] bytes() {
        return bytes.clone();
    }

    /** @return the bytes decoded as UTF-8 */
    public String text() {
        return new String(bytes, StandardCharsets.UTF_8);
    }

    /** @return true if any part of the word was inside quotes */
    public boolean quoted() {
        return quoted;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof Token)) return false;
        Token t = (Token) o;
        return quoted == t.quoted && Arrays.equals(bytes, t.bytes);
    }

    @Override
    public int hashCode() {
        return 31 * Arrays.hashCode(bytes) + (quoted ? 1 : 0);
    }

    @Override
    public String toString() {
        return text();
    }
}
