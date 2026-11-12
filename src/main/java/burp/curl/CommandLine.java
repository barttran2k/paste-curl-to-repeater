package burp.curl;

import java.util.List;

/**
 * One simple command (one {@code curl ...} invocation) after shell tokenizing.
 * @param argv all words including the command word itself (e.g. "curl") at index 0 if present
 * @param stdin heredoc / here-string content, or null
 * @param stdinFile path from a {@code < file} redirection, or null
 */
public record CommandLine(List<Token> argv, byte[] stdin, String stdinFile) {
    /** Canonical constructor; copies argv (null becomes empty) and stdin. */
    public CommandLine {
        argv = argv == null ? List.of() : List.copyOf(argv);
        stdin = stdin == null ? null : stdin.clone();
    }

    /** @return a copy of the stdin bytes, or null */
    @Override
    public byte[] stdin() {
        return stdin == null ? null : stdin.clone();
    }
}
