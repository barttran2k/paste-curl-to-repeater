package burp.curl;

/**
 * Description of one curl option.
 * @param longName the long name without leading dashes
 * @param shortName the short flag character, or 0 when there is none
 * @param kind the argument kind
 * @param negatable true if {@code --no-<longName>} is accepted
 * @param handling the handling group
 */
public record OptionSpec(String longName, char shortName, ArgKind kind, boolean negatable, Handling handling) {
    /** @return true if kind is STRING, FILE or NUM */
    public boolean takesArg() {
        return kind == ArgKind.STRING || kind == ArgKind.FILE || kind == ArgKind.NUM;
    }
}
