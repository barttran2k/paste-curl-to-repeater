package burp.curl;

/**
 * The one place that cuts the file name off a path.
 *
 * <p>Measured with curl 8.7.1 on a POSIX machine: {@code -T 'a\b.png'} uploads to {@code .../b.png} (the tool cuts
 * at the last {@code /} or {@code \}), while {@code -F 'f=@a\b.png'} sends {@code filename="a\b.png"} (libcurl cuts
 * at {@code /} only). curl.exe on Windows cuts {@code -F} paths at both separators, so a path that is recognisably a
 * Windows path (drive letter, UNC) is cut at both here too.
 */
final class PathNames {
    private PathNames() {
    }

    /**
     * @param path a path as written
     * @param bothSeparators true to cut at the last {@code /} or {@code \}, false for {@code /} only
     * @return the part after the last separator
     */
    static String baseName(String path, boolean bothSeparators) {
        int cut = path.lastIndexOf('/');
        if (bothSeparators) {
            cut = Math.max(cut, path.lastIndexOf('\\'));
        }
        return path.substring(cut + 1);
    }

    /** @return true for {@code X:\...}, {@code X:/...} and {@code \\server\...} */
    static boolean isWindowsPath(String path) {
        if (path.length() >= 3 && Character.isLetter(path.charAt(0)) && path.charAt(0) < 128 && path.charAt(1) == ':'
                && (path.charAt(2) == '\\' || path.charAt(2) == '/')) {
            return true;
        }
        if (path.startsWith("\\\\") && path.length() > 2 && path.charAt(2) != '\\' && path.charAt(2) != '/') {
            int sep = path.indexOf('\\', 2);
            return sep > 2;
        }
        return false;
    }

    /** @return the file name {@code -F name=@path} sends: both separators for a Windows path, else {@code /} only */
    static String formFileName(String path) {
        return baseName(path, isWindowsPath(path));
    }

    /** @return the name {@code -T path} appends to a URL that ends with a slash: both separators (measured) */
    static String uploadName(String path) {
        return baseName(path, true);
    }
}
