package burp.curl;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Set;

/**
 * The one place where local files are read for a curl command, and the guard that keeps the reads inside what the
 * user was shown.
 *
 * <p>{@link ParsedCurl#fileRefs()} lists the paths a command names; the caller asks the user about exactly those.
 * {@link #guard} wraps the caller's {@link FileAccess} so that a path outside that list is refused whatever code asks
 * for it. A path can be outside the list when it only becomes known while building, because it is part of the
 * contents of another file (for example {@code --variable p@a --expand-data '@{{p}}'}); such a path is never read
 * and is replaced by a {@code <<FILE: path>>} placeholder with a lossy warning.
 *
 * <p>{@link #read} and {@link #readStdin} are the single "read it or produce the placeholder plus warning" logic for
 * data files, header files, cookie files, variable files and stdin.
 */
final class FileReads {
    private FileReads() {
    }

    /** Raised by the guard for a path the user was not asked about. */
    static final class UnconfirmedPathException extends IOException {
        private static final long serialVersionUID = 1L;

        UnconfirmedPathException(String path) {
            super("not confirmed: " + path);
        }
    }

    /**
     * @param bytes the file contents, or the placeholder when {@code ok} is false
     * @param ok true when the bytes are the real contents
     */
    record Result(byte[] bytes, boolean ok) {
    }

    /**
     * @param real the caller's file access
     * @param allowed the paths that may be read (the {@code fileRefs()} of the same parsed command)
     * @return an access that refuses every other path with an {@link UnconfirmedPathException}
     */
    static FileAccess guard(FileAccess real, Set<String> allowed) {
        Set<String> ok = Set.copyOf(allowed);
        return path -> {
            if (path == null || !ok.contains(path)) {
                throw new UnconfirmedPathException(path);
            }
            return real.read(path);
        };
    }

    /** @return the {@code <<FILE: path>>} stand-in for a file that was not read */
    static byte[] placeholder(String path) {
        return ("<<FILE: " + path + ">>").getBytes(StandardCharsets.UTF_8);
    }

    /**
     * Reads a file, or produces the placeholder and a lossy warning.
     *
     * @param files the (guarded) access
     * @param path the path as written; not {@code -}
     * @param w receives the warning
     * @return the contents, or the placeholder with {@code ok == false}
     */
    static Result read(FileAccess files, String path, List<Warning> w) {
        if (path.isEmpty()) {
            w.add(Warning.lossy("A file name is empty, so no file could be read; a placeholder was used"));
            return new Result(placeholder(path), false);
        }
        try {
            byte[] b = files.read(path);
            if (b != null) {
                return new Result(b, true);
            }
            w.add(Warning.lossy("Could not read " + path + "; a placeholder was used"));
        } catch (UnconfirmedPathException e) {
            w.add(Warning.lossy("The path " + path + " came from the contents of a file and was not shown for "
                    + "confirmation, so it was not read; a placeholder was used"));
        } catch (IOException e) {
            w.add(Warning.lossy("Could not read " + path + " (" + e.getMessage() + "); a placeholder was used"));
        } catch (RuntimeException e) {
            w.add(Warning.lossy("Could not read " + path + " (" + e.getClass().getSimpleName()
                    + "); a placeholder was used"));
        }
        return new Result(placeholder(path), false);
    }

    /**
     * Reads what {@code @-} stands for: the pasted heredoc/here-string, the file of a {@code < file} redirect, or a
     * {@code <<STDIN>>} placeholder with a warning when nothing was pasted.
     *
     * @param stdin the stdin of the shell command, or null
     * @param files the (guarded) access
     * @param w receives the warning
     * @return the contents, or the placeholder with {@code ok == false}
     */
    static Result readStdin(Operation.StdinSource stdin, FileAccess files, List<Warning> w) {
        if (stdin != null && stdin.bytes != null) {
            return new Result(stdin.bytes, true);
        }
        if (stdin != null && stdin.file != null) {
            return read(files, stdin.file, w);
        }
        w.add(Warning.lossy("The command reads stdin (@-) but no stdin content was pasted"));
        return new Result("<<STDIN>>".getBytes(StandardCharsets.UTF_8), false);
    }
}
