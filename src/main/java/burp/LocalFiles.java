package burp;

import burp.curl.FileAccess;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * Real local file access for {@code -d @file}, {@code -F name=@file} and similar.
 *
 * <p>Path rules: a leading {@code ~} is the home directory; absolute paths are used as is; relative paths are
 * resolved against the home directory, because curl would use the shell's working directory, which Burp cannot
 * know. The path {@code -} means stdin and is never read. Files over {@link #MAX_BYTES} are refused.
 */
public final class LocalFiles implements FileAccess, PasteCurlAction.FileProbe {
    /** Largest file that is read. */
    public static final long MAX_BYTES = 20L * 1024 * 1024;

    private final Path home;

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
     * @return the absolute path
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
        Path p = resolve(path);
        if (Files.isDirectory(p)) {
            throw new IOException("is a directory: " + p);
        }
        if (!Files.isRegularFile(p)) {
            throw new IOException("file not found: " + p);
        }
        long size = Files.size(p);
        if (size > MAX_BYTES) {
            throw new IOException("file too large (" + size + " bytes, limit " + MAX_BYTES + "): " + p);
        }
        return Files.readAllBytes(p);
    }

    @Override
    public PasteCurlAction.FileInfo describe(String path) {
        Path p;
        try {
            p = resolve(path);
        } catch (IOException e) {
            return new PasteCurlAction.FileInfo(path, "-", "cannot be read: " + e.getMessage());
        }
        String status;
        try {
            if (Files.isDirectory(p)) {
                status = "is a directory";
            } else if (!Files.isRegularFile(p)) {
                status = "not found";
            } else {
                long size = Files.size(p);
                status = size > MAX_BYTES ? "too large (" + size + " bytes)" : "found, " + size + " bytes";
            }
        } catch (IOException | SecurityException e) {
            status = "cannot be inspected";
        }
        return new PasteCurlAction.FileInfo(path, p.toString(), status);
    }
}
