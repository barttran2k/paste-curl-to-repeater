package burp.curl;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
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

    /** Result of {@link #expand}: the bytes, or null when curl would refuse the argument. */
    byte[] expand(byte[] in, List<Warning> warnings, String option) {
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
            warnings.add(Warning.lossy(option + ": curl refuses the variable expression {{" + spec
                    + "}}; the argument is used unexpanded"));
            return null;
        }
        byte[] v = vars.getOrDefault(name, new byte[0]);
        for (int k = 1; k < parts.length; k++) {
            switch (parts[k]) {
                case "trim" -> v = trim(v);
                case "json" -> v = json(v);
                case "url" -> v = CurlRequestBuilder.urlEncodeAll(v);
                case "b64" -> v = Base64.getEncoder().encode(v);
                default -> {
                    warnings.add(Warning.lossy(option + ": curl refuses the unknown variable function '"
                            + parts[k] + "' in {{" + spec + "}}; the argument is used unexpanded"));
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
     * @param files reads {@code @file} contents
     * @param stdinSource reads {@code @-}
     */
    void define(byte[] arg, StdinReader stdinSource, FileAccess files, List<Warning> warnings) {
        String s = new String(arg, StandardCharsets.ISO_8859_1);
        boolean env = s.startsWith("%");
        int p = env ? 1 : 0;
        int q = p;
        while (q < s.length() && (Character.isLetterOrDigit(s.charAt(q)) && s.charAt(q) < 128 || s.charAt(q) == '_')) {
            q++;
        }
        String name = s.substring(p, q);
        if (name.isEmpty() || name.length() > MAX_NAME) {
            warnings.add(Warning.note("--variable: the name in '" + abbreviate(s) + "' is not valid; ignored"));
            return;
        }
        char sep = q < s.length() ? s.charAt(q) : 0;
        byte[] content = null;
        if (sep == '=') {
            content = java.util.Arrays.copyOfRange(arg, q + 1, arg.length);
        } else if (sep == '@') {
            String file = new String(arg, q + 1, arg.length - q - 1, StandardCharsets.UTF_8);
            content = readFile(file, stdinSource, files, warnings);
        } else if (q < s.length()) {
            warnings.add(Warning.note("--variable: '" + abbreviate(s) + "' is not name=content or name@file; ignored"));
            return;
        }
        if (env) {
            if (content == null) {
                warnings.add(Warning.lossy("--variable %" + name + " imports an environment variable that is not "
                        + "known when pasting; {{" + name + "}} expands to nothing"));
                vars.remove(name);
                return;
            }
            warnings.add(Warning.lossy("--variable %" + name + " imports an environment variable; the default value "
                    + "is used"));
            vars.put(name, content);
            return;
        }
        vars.put(name, content == null ? new byte[0] : content);
    }

    private static String abbreviate(String s) {
        return s.length() > 40 ? s.substring(0, 40) + "..." : s;
    }

    private static byte[] readFile(String file, StdinReader stdin, FileAccess files, List<Warning> w) {
        if (file.equals("-")) {
            return stdin.readStdin(w);
        }
        try {
            byte[] b = files.read(file);
            if (b != null) {
                return b;
            }
        } catch (IOException | RuntimeException e) {
            w.add(Warning.lossy("Could not read " + file + " (" + e.getMessage() + "); a placeholder was used"));
            return ("<<FILE: " + file + ">>").getBytes(StandardCharsets.UTF_8);
        }
        w.add(Warning.lossy("Could not read " + file + "; a placeholder was used"));
        return ("<<FILE: " + file + ">>").getBytes(StandardCharsets.UTF_8);
    }

    /** Supplies the pasted stdin of the shell command for {@code --variable name@-}. */
    interface StdinReader {
        byte[] readStdin(List<Warning> w);
    }
}
