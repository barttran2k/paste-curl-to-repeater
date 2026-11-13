package burp;

import burp.curl.FileAccess;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Real local file access for {@code -d @file}, {@code -F name=@file} and similar.
 *
 * <p>Path rules: a leading {@code ~} is the home directory; absolute paths are used as is; relative paths are
 * resolved against the home directory, because curl would use the shell's working directory, which Burp cannot
 * know. The path {@code -} means stdin and is never read. Files over {@link #MAX_BYTES} are refused.
 *
 * <p>Symbolic links: {@link #describe} resolves the path to its real file ({@link Path#toRealPath()}) and remembers
 * that real path for a regular file. {@link #read} only reads a path that was described, and only when it still
 * resolves to the same real file; otherwise it refuses. What is read is therefore exactly what the confirmation
 * dialog showed, including the target of a symbolic link.
 */
public final class LocalFiles implements FileAccess, PasteCurlAction.FileProbe {
    /** Largest file that is read. */
    public static final long MAX_BYTES = 20L * 1024 * 1024;

    private final Path home;
    /** path as written -> real path that was shown to the user */
    private final Map<String, Path> shown = new ConcurrentHashMap<>();

    /** Uses the user's home directory (system property user.home). */
    public LocalFiles() {
        this(Paths.get(System.getProperty("user.home")));
    }

    /** @param home directory that stands for ~ and for relative paths */
    public LocalFiles(Path home) {
        this.home = home.toAbsolutePath().normalize();
    }

    /** @return the directory used for ~ and relative paths */
    public Path home() {
        return home;
    }

    /**
     * @param path path as written in the command
     * @return the absolute, lexically normalised path (symbolic links are not followed)
     * @throws IOException if the path is stdin ("-") or not a valid path
     */
    public Path resolve(String path) throws IOException {
        if (path == null || path.isEmpty()) {
            throw new IOException("empty file name");
        }
        if ("-".equals(path)) {
            throw new IOException("\"-\" means standard input, which is not available here");
        }
        try {
            if (path.equals("~")) {
                return home;
            }
            if (path.startsWith("~/") || path.startsWith("~\\")) {
                return home.resolve(path.substring(2)).normalize();
            }
            Path p = Paths.get(path);
            return p.isAbsolute() ? p : home.resolve(p).normalize();
        } catch (InvalidPathException e) {
            throw new IOException("invalid file name: " + path, e);
        }
    }

    @Override
    public byte[] read(String path) throws IOException {
        Path lexical = resolve(path);
        Path expected = shown.get(path);
        if (expected == null) {
            throw new IOException("not shown for confirmation, so not read: " + lexical);
        }
        Path real;
        try {
            real = lexical.toRealPath();
        } catch (IOException e) {
            throw new IOException("file not found: " + lexical, e);
        }
        if (!real.equals(expected)) {
            throw new IOException("the file changed after it was shown (now " + real + ", was " + expected + "): "
                    + lexical);
        }
        if (Files.isDirectory(real)) {
            throw new IOException("is a directory: " + real);
        }
        if (!Files.isRegularFile(real)) {
            throw new IOException("file not found: " + real);
        }
        long size = Files.size(real);
        if (size > MAX_BYTES) {
            throw new IOException("file too large (" + size + " bytes, limit " + MAX_BYTES + "): " + real);
        }
        try (InputStream in = Files.newInputStream(real, LinkOption.NOFOLLOW_LINKS)) {
            byte[] b = in.readNBytes((int) MAX_BYTES + 1);
            if (b.length > MAX_BYTES) {
                throw new IOException("file too large (limit " + MAX_BYTES + "): " + real);
            }
            return b;
        }
    }

    @Override
    public String homeDirectory() {
        return home.toString();
    }

    @Override
    public PasteCurlAction.FileInfo describe(String path) {
        shown.remove(path);
        Path p;
        try {
            p = resolve(path);
        } catch (IOException e) {
            return new PasteCurlAction.FileInfo(path, "-", "cannot be read: " + e.getMessage());
        }
        Path real = null;
        String status;
        try {
            if (Files.isSymbolicLink(p) && !Files.exists(p)) {
                status = "not found (broken or circular symbolic link)";
            } else if (!Files.exists(p)) {
                status = "not found";
            } else {
                real = p.toRealPath();
                if (Files.isDirectory(real)) {
                    status = "is a directory";
                } else if (!Files.isRegularFile(real)) {
                    status = "not found";
                } else {
                    long size = Files.size(real);
                    if (size > MAX_BYTES) {
                        status = "too large (" + size + " bytes)";
                    } else {
                        status = "found, " + size + " bytes";
                        shown.put(path, real);
                    }
                }
            }
        } catch (IOException | SecurityException e) {
            status = "cannot be inspected";
            real = null;
        }
        String link = real != null && !real.equals(p) ? real.toString() : null;
        return new PasteCurlAction.FileInfo(path, p.toString(), status, link);
    }
}
