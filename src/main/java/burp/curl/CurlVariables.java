package burp.curl;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * The variables of one curl command line ({@code --variable}) and their expansion in {@code --expand-<option>}
 * arguments, as in curl 8.7.1's {@code var.c}.
 *
 * <p>Syntax of {@code {{name}}} with optional functions {@code :trim :json :url :b64} (applied left to right);
 * {@code \{{} gives a literal {@code {{}; an unterminated {@code {{} is kept literally; an invalid name, an empty or
 * unknown function make curl refuse the option (here: the text stays unexpanded and a warning is added).
 * An undefined variable expands to nothing. {@code %NAME} imports from the environment, which cannot be done from a
 * pasted command: the default ({@code %NAME=text}, {@code %NAME@file}) is used, otherwise the variable stays undefined.
 */
final class CurlVariables {
    private static final int MAX_NAME = 128;
    private final Map<String, byte[]> vars = new HashMap<>();
    /** variables whose content comes from a file (directly or through another such variable) */
    private final java.util.Set<String> fromFiles = new java.util.HashSet<>();
    private boolean expansionUsedFileContent;

    /** @return true when the last {@link #expand} call inserted the content of a variable that came from a file */
    boolean lastExpansionUsedFileContent() {
        return expansionUsedFileContent;
    }

    /** @return true when some variable got its content from a file */
    boolean anyFromFile() {
        return anyFromFile;
    }

    private boolean anyFromFile;

    /** Result of {@link #expand}: the bytes, or null when curl would refuse the argument. */
    byte[] expand(byte[] in, List<Warning> warnings, String option) {
        expansionUsedFileContent = false;
        ByteArrayOutputStream out = new ByteArrayOutputStream(in.length + 16);
        int i = 0;
        while (i < in.length) {
            byte c = in[i];
            if (c == '\\' && i + 2 < in.length && in[i + 1] == '{' && in[i + 2] == '{') {
                out.write('{');
                out.write('{');
                i += 3;
                continue;
            }
            if (c == '{' && i + 1 < in.length && in[i + 1] == '{') {
                int end = indexOfClose(in, i + 2);
                if (end < 0) {
                    out.write(c);
                    i++;
                    continue;
                }
                byte[] value = expandOne(new String(in, i + 2, end - (i + 2), StandardCharsets.ISO_8859_1),
                        warnings, option);
                if (value == null) {
                    return null;
                }
                out.writeBytes(value);
                i = end + 2;
                continue;
            }
            out.write(c);
            i++;
        }
        return out.toByteArray();
    }

    private static int indexOfClose(byte[] in, int from) {
        for (int i = from; i + 1 < in.length; i++) {
            if (in[i] == '}' && in[i + 1] == '}') {
                return i;
            }
        }
        return -1;
    }

    private byte[] expandOne(String spec, List<Warning> warnings, String option) {
        String[] parts = spec.split(":", -1);
        String name = parts[0];
        if (!validName(name)) {
            warnings.add(Warning.lossy(option + ": curl refuses a variable expression with an invalid variable "
                    + "name; the argument is used unexpanded"));
            return null;
        }
        byte[] v = vars.getOrDefault(name, new byte[0]);
        if (fromFiles.contains(name)) {
            expansionUsedFileContent = true;
        }
        for (int k = 1; k < parts.length; k++) {
            switch (parts[k]) {
                case "trim" -> v = trim(v);
                case "json" -> v = json(v);
                case "url" -> v = CurlRequestBuilder.urlEncodeAll(v);
                case "b64" -> v = Base64.getEncoder().encode(v);
                default -> {
                    warnings.add(Warning.lossy(option + ": curl refuses an unknown variable function in a "
                            + "variable expression; the argument is used unexpanded"));
                    return null;
                }
            }
        }
        return v;
    }

    private static boolean validName(String n) {
        if (n.isEmpty() || n.length() > MAX_NAME) {
            return false;
        }
        for (int i = 0; i < n.length(); i++) {
            char c = n.charAt(i);
            if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_')) {
                return false;
            }
        }
        return true;
    }

    private static boolean isWs(byte b) {
        return b == ' ' || b == '\t' || b == '\r' || b == '\n' || b == '\f' || b == 0x0b;
    }

    private static byte[] trim(byte[] v) {
        int s = 0;
        int e = v.length;
        while (s < e && isWs(v[s])) {
            s++;
        }
        while (e > s && isWs(v[e - 1])) {
            e--;
        }
        return java.util.Arrays.copyOfRange(v, s, e);
    }

    private static byte[] json(byte[] v) {
        ByteArrayOutputStream o = new ByteArrayOutputStream(v.length + 8);
        for (byte b : v) {
            switch (b) {
                case '"' -> o.writeBytes("\\\"".getBytes(StandardCharsets.US_ASCII));
                case '\\' -> o.writeBytes("\\\\".getBytes(StandardCharsets.US_ASCII));
                case '\b' -> o.writeBytes("\\b".getBytes(StandardCharsets.US_ASCII));
                case '\f' -> o.writeBytes("\\f".getBytes(StandardCharsets.US_ASCII));
                case '\n' -> o.writeBytes("\\n".getBytes(StandardCharsets.US_ASCII));
                case '\r' -> o.writeBytes("\\r".getBytes(StandardCharsets.US_ASCII));
                case '\t' -> o.writeBytes("\\t".getBytes(StandardCharsets.US_ASCII));
                default -> {
                    if ((b & 0xff) < 0x20) {
                        o.writeBytes(String.format("\\u%04x", b & 0xff).getBytes(StandardCharsets.US_ASCII));
                    } else {
                        o.write(b);
                    }
                }
            }
        }
        return o.toByteArray();
    }

    /**
     * Applies one {@code --variable} argument.
     *
     * @param arg {@code name=content}, {@code name@file}, {@code %name}, {@code %name=default}, {@code %name@file}
     * @param stdin the stdin of the shell command, read for {@code @-}
     * @param files reads {@code @file} contents
     * @param fromFileContent true when {@code arg} was expanded with the content of a variable that came from a
     *                        file: such an argument names a path (or a content) that is not in the command itself
     */
    void define(byte[] arg, Operation.StdinSource stdin, FileAccess files, List<Warning> warnings,
                boolean fromFileContent) {
        String s = new String(arg, StandardCharsets.ISO_8859_1);
        boolean env = s.startsWith("%");
        int p = env ? 1 : 0;
        int q = p;
        while (q < s.length() && (Character.isLetterOrDigit(s.charAt(q)) && s.charAt(q) < 128 || s.charAt(q) == '_')) {
            q++;
        }
        String name = s.substring(p, q);
        if (name.isEmpty() || name.length() > MAX_NAME) {
            warnings.add(Warning.note("--variable: the argument has no valid variable name; ignored"));
            return;
        }
        char sep = q < s.length() ? s.charAt(q) : 0;
        byte[] content = null;
        boolean file = false;
        if (sep == '=') {
            content = java.util.Arrays.copyOfRange(arg, q + 1, arg.length);
            file = fromFileContent;
        } else if (sep == '@') {
            String path = new String(arg, q + 1, arg.length - q - 1, StandardCharsets.UTF_8);
            file = true;
            content = path.equals("-") ? FileReads.readStdin(stdin, files, warnings).bytes()
                    : FileReads.read(files, path, warnings).bytes();
        } else if (q < s.length()) {
            warnings.add(Warning.note("--variable: the argument is not name=content or name@file; ignored"));
            return;
        }
        if (env) {
            if (content == null) {
                warnings.add(Warning.lossy("--variable %" + name + " imports an environment variable that is not "
                        + "known when pasting; {{" + name + "}} expands to nothing"));
                vars.remove(name);
                fromFiles.remove(name);
                return;
            }
            warnings.add(Warning.lossy("--variable %" + name + " imports an environment variable; the default value "
                    + "is used"));
            vars.put(name, content);
            setFromFile(name, file);
            return;
        }
        vars.put(name, content == null ? new byte[0] : content);
        setFromFile(name, file);
    }

    private void setFromFile(String name, boolean file) {
        if (file) {
            fromFiles.add(name);
            anyFromFile = true;
        } else {
            fromFiles.remove(name);
        }
    }
}
