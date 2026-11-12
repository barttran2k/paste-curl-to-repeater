package burp.curl;

/** What kind of argument a curl option takes. */
public enum ArgKind {
    /** No argument (plain flag). */
    NONE,
    /** No argument (boolean flag, usually negatable with --no-). */
    BOOL,
    /** One string argument. */
    STRING,
    /** One argument that is a file path. */
    FILE,
    /** One numeric argument. */
    NUM
}
