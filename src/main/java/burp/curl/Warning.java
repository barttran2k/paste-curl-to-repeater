package burp.curl;

/**
 * A diagnostic produced while tokenizing, parsing or building.
 * @param severity how serious the warning is
 * @param message human-readable text
 */
public record Warning(Severity severity, String message) {
    /** Warning level. */
    public enum Severity {
        /** Log only. */
        NOTE,
        /** The built request may differ from what curl sends; shown to the user. */
        LOSSY
    }

    /**
     * @param m message
     * @return a NOTE warning
     */
    public static Warning note(String m) {
        return new Warning(Severity.NOTE, m);
    }

    /**
     * @param m message
     * @return a LOSSY warning
     */
    public static Warning lossy(String m) {
        return new Warning(Severity.LOSSY, m);
    }
}
