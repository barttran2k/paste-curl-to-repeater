package burp.curl;

import java.util.List;

/**
 * Output of a {@link Tokenizer}.
 * @param commands the simple commands found, in order
 * @param warnings tokenizer warnings
 */
public record TokenizeResult(List<CommandLine> commands, List<Warning> warnings) {
    /** Canonical constructor; copies lists (null becomes empty). */
    public TokenizeResult {
        commands = commands == null ? List.of() : List.copyOf(commands);
        warnings = warnings == null ? List.of() : List.copyOf(warnings);
    }
}
