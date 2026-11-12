package burp.curl;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Random;

/**
 * Builds a {@code multipart/form-data} body byte-for-byte like curl 8.7.1 (libcurl mime).
 *
 * <p>Mirrored behaviour: boundary is 24 dashes plus 22 random alphanumerics; every part starts with
 * {@code Content-Disposition: form-data; name="..."} (the {@code name} is omitted for an empty name) and
 * {@code ; filename="..."} when there is a file name; then {@code Content-Type} (explicit {@code ;type=}, else the
 * guess from the file name, see {@link #guessContentType}), then the {@code ;headers=} lines verbatim. A user
 * {@code Content-Disposition} header replaces the generated one; a user {@code Content-Type} header is dropped when
 * {@code ;type=} is given and otherwise replaces the guessed type. Uploads ({@code @}) get a guessed
 * {@code Content-Type} (default {@code application/octet-stream}; none for stdin path {@code -}, unless the
 * {@code filename=} has a known extension); {@code <file} and literal parts get none unless {@code type=} is given
 * (literal parts with {@code filename=} get the guess of that name when its extension is known). {@code filename=} on
 * a {@code <file} part is ignored, as in curl. The Content-Type guess uses {@code filename=} when its extension is in
 * the table, else the file's own name.
 *
 * <p>Several files in one field become a nested {@code multipart/mixed} part with its own boundary and
 * {@code Content-Disposition: attachment; filename="..."} parts.
 *
 * <p>Names and file names: by default {@code "} becomes {@code %22}, CR {@code %0D}, LF {@code %0A} (curl 8.7.1);
 * with {@link #formEscape(boolean)} {@code "} becomes {@code \"} and {@code \} becomes {@code \\}, CR/LF stay raw.
 * Non-ASCII is sent as UTF-8.
 *
 * <p>Header files ({@code headers=@file}) are read through {@link FileAccess}; unlike curl, which silently ignores
 * an unreadable one, the IOException propagates so the caller can decide.
 */
public final class MultipartBuilder {
    private static final String DASHES = "------------------------";
    private static final String ALNUM = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

    private final String boundary;
    private final Random innerRandom;
    private boolean formEscape;
    private String disposition = "form-data";
    private final List<byte[]> parts = new ArrayList<>();

    /** Creates a builder with a random curl-style boundary. */
    public MultipartBuilder() {
        this(randomBoundary(new SecureRandom()), new SecureRandom());
    }

    /**
     * Creates a builder with a fixed boundary (tests). The boundary of nested multipart/mixed parts is derived
     * deterministically from it.
     *
     * @param boundary the boundary text without the leading "--"
     */
    public MultipartBuilder(String boundary) {
        this(boundary, new Random(boundary.hashCode()));
    }

    private MultipartBuilder(String boundary, Random innerRandom) {
        this.boundary = boundary;
        this.innerRandom = innerRandom;
    }

    private static String randomBoundary(Random r) {
        StringBuilder sb = new StringBuilder(DASHES);
        for (int i = 0; i < 22; i++) {
            sb.append(ALNUM.charAt(r.nextInt(ALNUM.length())));
        }
        return sb.toString();
    }

    /**
     * Sets curl's {@code --form-escape}.
     *
     * @param on true for backslash escaping
     * @return this
     */
    public MultipartBuilder formEscape(boolean on) {
        this.formEscape = on;
        return this;
    }

    /**
     * Sets the {@code Content-Disposition} type of the top-level parts: {@code form-data} (default) or, when the user
     * gave a {@code Content-Type} header other than {@code multipart/form-data}, {@code attachment}.
     *
     * @param type the disposition type
     * @return this
     */
    public MultipartBuilder disposition(String type) {
        this.disposition = type;
        return this;
    }

    /** @return the boundary text (without the leading "--") */
    public String boundary() {
        return boundary;
    }

    /** @return the Content-Type header value for the whole body */
    public String contentType() {
        return "multipart/form-data; boundary=" + boundary;
    }

    /**
     * Appends a field.
     *
     * @param field the parsed field
     * @param files source for {@code @file}, {@code <file} and {@code headers=@file}
     * @return this
     * @throws IOException when a file cannot be read
     */
    public MultipartBuilder add(FormField field, FileAccess files) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        String name = field.name();
        switch (field.kind()) {
            case LITERAL: {
                String fn = field.filename();
                String guess = fn == null ? null : knownType(fn);
                writeHead(out, disposition, name, fn, field.type(), guess, field, files);
                out.write(ByteText.encode(field.value()));
                break;
            }
            case FILE_CONTENT: {
                byte[] data = files.read(field.value());
                writeHead(out, disposition, name, null, field.type(), null, field, files);
                out.write(data);
                break;
            }
            case FILE_UPLOAD: {
                byte[] data = files.read(field.value());
                writeHead(out, disposition, name, uploadName(field), field.type(), uploadGuess(field),
                        field, files);
                out.write(data);
                break;
            }
            case FILE_LIST: {
                List<FormField> list;
                try {
                    list = field.files();
                } catch (CurlParseException e) {
                    throw new IOException(e.getMessage(), e);
                }
                String inner = randomBoundary(innerRandom);
                writeHead(out, disposition, name, null, "multipart/mixed; boundary=" + inner, null,
                        null, files);
                for (FormField f : list) {
                    byte[] data = files.read(f.value());
                    put(out, "--" + inner + "\r\n");
                    writeHead(out, "attachment", "", uploadName(f), f.type(), uploadGuess(f), f, files, true);
                    out.write(data);
                    put(out, "\r\n");
                }
                put(out, "--" + inner + "--\r\n");
                break;
            }
            default:
                throw new IllegalStateException();
        }
        put(out, "\r\n");
        ByteArrayOutputStream part = new ByteArrayOutputStream();
        put(part, "--" + boundary + "\r\n");
        part.write(out.toByteArray());
        parts.add(part.toByteArray());
        return this;
    }

    /** @return the complete body */
    public byte[] build() {
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        for (byte[] p : parts) {
            o.write(p, 0, p.length);
        }
        byte[] end = ("--" + boundary + "--\r\n").getBytes(StandardCharsets.UTF_8);
        o.write(end, 0, end.length);
        return o.toByteArray();
    }

    // ---- part head ----

    private static String uploadName(FormField f) {
        return f.filename() != null ? f.filename() : PathNames.formFileName(f.value());
    }

    /** Guess for an upload: from filename= when its extension is known, else from the path; stdin gets none. */
    private static String uploadGuess(FormField f) {
        if (f.filename() != null) {
            String g = knownType(f.filename());
            if (g != null) {
                return g;
            }
        }
        if (f.value().equals("-")) {
            return null;
        }
        String g = knownType(PathNames.formFileName(f.value()));
        return g != null ? g : "application/octet-stream";
    }

    private void writeHead(ByteArrayOutputStream out, String disposition, String name, String filename, String type,
                           String guess, FormField owner, FileAccess files) throws IOException {
        writeHead(out, disposition, name, filename, type, guess, owner, files, false);
    }

    private void writeHead(ByteArrayOutputStream out, String disposition, String name, String filename, String type,
                           String guess, FormField owner, FileAccess files, boolean nested) throws IOException {
        List<String> user = new ArrayList<>();
        List<String> headers = owner == null ? List.of() : owner.headers();
        for (int i = 0; i < headers.size(); i++) {
            String h = headers.get(i);
            if (owner.isHeaderFile(i)) {
                byte[] data = files.read(h.substring(1));
                for (String line : ByteText.decode(data).split("\r?\n|\r")) {
                    if (!line.isEmpty()) {
                        user.add(line);
                    }
                }
            } else {
                user.add(h);
            }
        }
        boolean userDisposition = false;
        boolean userType = false;
        for (String h : user) {
            String n = headerName(h);
            userDisposition |= n.equals("content-disposition");
            userType |= n.equals("content-type");
        }
        if (!userDisposition) {
            StringBuilder cd = new StringBuilder("Content-Disposition: ").append(disposition);
            if (name != null && !name.isEmpty()) {
                cd.append("; name=\"").append(escape(name)).append('"');
            }
            if (filename != null) {
                cd.append("; filename=\"").append(escape(filename)).append('"');
            }
            put(out, cd + "\r\n");
        }
        if (type != null) {
            put(out, "Content-Type: " + type + "\r\n");
        } else if (!userType && guess != null) {
            put(out, "Content-Type: " + guess + "\r\n");
        }
        for (String h : user) {
            if (type != null && headerName(h).equals("content-type")) {
                continue;
            }
            put(out, h + "\r\n");
        }
        put(out, "\r\n");
    }

    private static String headerName(String line) {
        int c = line.indexOf(':');
        String n = c >= 0 ? line.substring(0, c) : line;
        int s = n.indexOf(';');
        if (s >= 0) {
            n = n.substring(0, s);
        }
        return n.trim().toLowerCase(Locale.ROOT);
    }

    private String escape(String s) {
        StringBuilder sb = new StringBuilder(s.length() + 8);
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (formEscape) {
                if (c == '"') {
                    sb.append("\\\"");
                } else if (c == '\\') {
                    sb.append("\\\\");
                } else {
                    sb.append(c);
                }
            } else if (c == '"') {
                sb.append("%22");
            } else if (c == '\r') {
                sb.append("%0D");
            } else if (c == '\n') {
                sb.append("%0A");
            } else {
                sb.append(c);
            }
        }
        return sb.toString();
    }

    private static void put(ByteArrayOutputStream out, String s) {
        byte[] b = ByteText.encode(s);
        out.write(b, 0, b.length);
    }

    // ---- content type table ----

    private static final String[][] TYPES = {
        {".gif", "image/gif"}, {".jpg", "image/jpeg"}, {".jpeg", "image/jpeg"}, {".png", "image/png"},
        {".svg", "image/svg+xml"}, {".txt", "text/plain"}, {".htm", "text/html"}, {".html", "text/html"},
        {".pdf", "application/pdf"}, {".xml", "application/xml"}
    };

    private static String knownType(String filename) {
        String lower = filename.toLowerCase(Locale.ROOT);
        for (String[] t : TYPES) {
            if (lower.endsWith(t[0])) {
                return t[1];
            }
        }
        return null;
    }

    /**
     * curl's built-in extension table (case-insensitive suffix match on the file name).
     *
     * @param filename file name
     * @return the type, {@code application/octet-stream} when the extension is unknown
     */
    public static String guessContentType(String filename) {
        String t = filename == null ? null : knownType(filename);
        return t != null ? t : "application/octet-stream";
    }
}
