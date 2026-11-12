package burp.curl;

/** Thrown when pasted text cannot be tokenized, parsed or built. */
public class CurlParseException extends Exception {
    private static final long serialVersionUID = 1L;
    private final int position;

    /** @param message description; position is unknown (-1) */
    public CurlParseException(String message) {
        this(message, -1);
    }

    /**
     * @param message description
     * @param position char offset in the input
     */
    public CurlParseException(String message, int position) {
        super(message);
        this.position = position;
    }

    /** @return char offset in the input, -1 if unknown */
    public int position() {
        return position;
    }
}
