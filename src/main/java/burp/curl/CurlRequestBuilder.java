package burp.curl;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * Turns {@link Operation}s into the HTTP/1.x request bytes curl 8.7.1 would send: header order, suppression of
 * internal headers by custom ones, body assembly, {@code -G}, authentication, URL handling. Files are read only
 * through {@link FileAccess}.
 *
 * <p>Header order: {@code Host}, {@code Authorization}, {@code Range}, {@code User-Agent}, {@code Accept},
 * {@code Accept-Encoding}, {@code Referer}, {@code Cookie}, the custom {@code -H} lines, then (with a body)
 * {@code Content-Length} and the default {@code Content-Type}. To add an option that adds an internal header,
 * add its line in {@link #headerBlock} at curl's position and guard it with {@link #hasCustom}.
 */
final class CurlRequestBuilder {
    private static final Pattern GLOB_SET = Pattern.compile("\\{[^{}]+\\}");
    private static final Pattern GLOB_RANGE =
            Pattern.compile("\\[(?:\\d+-\\d+|[A-Za-z]-[A-Za-z])(?::\\d+)?\\]");

    private final FileAccess files;
    private final Map<Operation.StdinSource, Boolean> stdinRead = new IdentityHashMap<>();

    private CurlRequestBuilder(FileAccess files) {
        this.files = files;
    }

    /**
     * @param operations the operations in order
     * @param files file access for {@code @file} data
     * @return one entry per URL per operation, in order
     * @throws CurlParseException when a URL is invalid or unsupported
     */
    static List<RequestDetails> build(List<Operation> operations, FileAccess files) throws CurlParseException {
        CurlRequestBuilder b = new CurlRequestBuilder(files);
        List<RequestDetails> result = new ArrayList<>();
        for (Operation op : operations) {
            b.buildOperation(op, result);
        }
        return result;
    }

    private void buildOperation(Operation op, List<RequestDetails> result) throws CurlParseException {
        List<Warning> warnings = new ArrayList<>();
        byte[] body = op.data.isEmpty() ? null : assembleBody(op, warnings);

        List<String> custom = new ArrayList<>(op.headers);
        if (op.json) {
            if (!hasCustom(op.headers, "Content-Type")) {
                custom.add("Content-Type: application/json");
            }
            if (!hasCustom(op.headers, "Accept")) {
                custom.add("Accept: application/json");
            }
        }
        if (body != null && op.head && !op.get) {
            warnings.add(Warning.lossy("curl refuses -I/--head together with data; the data was dropped"));
            body = null;
        }
        boolean sendBody = body != null && !op.get;

        String method = "GET";
        if (sendBody) {
            method = "POST";
        }
        if (op.head) {
            method = "HEAD";
        }
        if (op.method != null) {
            method = op.method;
        }

        for (String rawUrl : op.urls) {
            List<Warning> w = new ArrayList<>(warnings);
            CurlUrl url = CurlUrl.parse(prepareUrl(rawUrl, op.globoff, w), null, op.pathAsIs);
            if (op.get && body != null) {
                url = url.withAppendedQuery(new String(body, StandardCharsets.UTF_8));
            }
            byte[] head = headerBlock(op, url, custom, method, sendBody ? body : null, w);
            byte[] raw = head;
            if (sendBody) {
                raw = new byte[head.length + body.length];
                System.arraycopy(head, 0, raw, 0, head.length);
                System.arraycopy(body, 0, raw, head.length, body.length);
            }
            int explicit = url.port() != (url.secure() ? 443 : 80) ? url.port() : -1;
            BuiltRequest br = new BuiltRequest(url.host(), url.port(), url.secure(), raw, method, url.toString(), w);
            result.add(new RequestDetails(br, url.scheme(), url.host(), explicit, url.path(), url.query(),
                    op.headers, sendBody ? body : new byte[0]));
        }
    }

    // ---- URL ----

    /** Removes curl's glob escapes ({@code \[ \] \{ \}}) unless globbing is off and notes unescaped patterns. */
    private static String prepareUrl(String url, boolean globoff, List<Warning> w) {
        if (globoff) {
            return url;
        }
        StringBuilder clean = new StringBuilder(url.length());
        StringBuilder probe = new StringBuilder(url.length());
        for (int i = 0; i < url.length(); i++) {
            char c = url.charAt(i);
            if (c == '\\' && i + 1 < url.length() && "[]{}".indexOf(url.charAt(i + 1)) >= 0) {
                clean.append(url.charAt(i + 1));
                probe.append(' ');
                i++;
            } else {
                clean.append(c);
                probe.append(c);
            }
        }
        String p = probe.toString();
        if (GLOB_SET.matcher(p).find() || GLOB_RANGE.matcher(p).find()) {
            w.add(Warning.note("The URL contains a glob pattern ({a,b} or [1-3]); curl would have expanded it "
                    + "into several requests (use -g to turn that off). It is sent literally here."));
        }
        return clean.toString();
    }

    // ---- headers ----

    /** curl's {@code Curl_checkheaders}: the custom line starts with the name followed by ':' or ';'. */
    private static boolean matches(String line, String name) {
        int n = name.length();
        return line.length() > n && line.regionMatches(true, 0, name, 0, n)
                && (line.charAt(n) == ':' || line.charAt(n) == ';');
    }

    private static boolean hasCustom(List<String> custom, String name) {
        for (String h : custom) {
            if (matches(h, name)) {
                return true;
            }
        }
        return false;
    }

    private static boolean blank(String s) {
        return s.chars().allMatch(c -> c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\f' || c == 0x0b);
    }

    private static String valueAfterColon(String line) {
        return line.substring(line.indexOf(':') + 1).strip();
    }

    private byte[] headerBlock(Operation op, CurlUrl url, List<String> custom, String method, byte[] body,
                               List<Warning> w) {
        StringBuilder sb = new StringBuilder();
        sb.append(method).append(' ').append(url.requestTarget()).append(op.http10 ? " HTTP/1.0" : " HTTP/1.1")
                .append("\r\n");

        // Host: the first custom Host header replaces the value
        String customHost = null;
        for (String h : custom) {
            if (matches(h, "Host")) {
                customHost = h;
                break;
            }
        }
        if (customHost == null) {
            sb.append("Host: ").append(url.hostHeader()).append("\r\n");
        } else if (customHost.indexOf(':') < 0) {
            sb.append("Host:\r\n");
        } else if (!blank(valueAfterColon(customHost))) {
            sb.append("Host: ").append(valueAfterColon(customHost)).append("\r\n");
        }

        // Authorization
        if (!hasCustom(custom, "Authorization")) {
            String auth = authorization(op, url, w);
            if (auth != null) {
                sb.append("Authorization: ").append(auth).append("\r\n");
            }
        }
        if (op.range != null && !op.range.isEmpty()) {
            if (body == null) {
                if (!hasCustom(custom, "Range")) {
                    sb.append("Range: bytes=").append(op.range).append("\r\n");
                }
            } else if (!hasCustom(custom, "Content-Range")) {
                // curl treats -r on a request with a body as the range of an upload (measured on 8.7.1)
                sb.append("Content-Range: bytes ").append(op.range).append('/').append(body.length).append("\r\n");
            }
        }
        if (!hasCustom(custom, "User-Agent")) {
            if (op.userAgent == null) {
                sb.append("User-Agent: curl/8.7.1\r\n");
            } else if (!op.userAgent.isEmpty()) {
                sb.append("User-Agent: ").append(op.userAgent).append("\r\n");
            }
        }
        if (!hasCustom(custom, "Accept")) {
            sb.append("Accept: */*\r\n");
        }
        if (op.compressed && !hasCustom(custom, "Accept-Encoding")) {
            sb.append("Accept-Encoding: deflate, gzip\r\n");
        }
        if (op.referer != null && !hasCustom(custom, "Referer")) {
            String r = op.referer;
            int auto = r.indexOf(";auto");
            if (auto >= 0) {
                r = r.substring(0, auto);
            }
            if (!r.isEmpty()) {
                sb.append("Referer: ").append(r).append("\r\n");
            }
        }
        if (!op.cookies.isEmpty() && !hasCustom(custom, "Cookie")) {
            sb.append("Cookie: ").append(String.join(";", op.cookies)).append("\r\n");
        }

        // custom headers
        for (String h : custom) {
            if (matches(h, "Host")) {
                continue;
            }
            int colon = h.indexOf(':');
            if (colon >= 0) {
                if (!blank(h.substring(colon + 1))) {
                    sb.append(h).append("\r\n");
                }
            } else {
                int semi = h.indexOf(';');
                if (semi > 0 && semi == h.length() - 1) {
                    sb.append(h, 0, semi).append(":\r\n");
                }
            }
        }

        if (body != null) {
            if (!hasCustom(custom, "Content-Length")) {
                sb.append("Content-Length: ").append(body.length).append("\r\n");
            }
            if (!hasCustom(custom, "Content-Type")) {
                sb.append("Content-Type: application/x-www-form-urlencoded\r\n");
            }
        }
        sb.append("\r\n");
        return sb.toString().getBytes(StandardCharsets.UTF_8);
    }

    private static String authorization(Operation op, CurlUrl url, List<Warning> w) {
        if (op.bearer != null) {
            // with an explicit --basic curl sends neither (measured on 8.7.1)
            return op.basic ? null : "Bearer " + op.bearer;
        }
        String user;
        String pass;
        if (op.user != null) {
            if (op.user.isEmpty()) {
                return null;
            }
            int c = op.user.indexOf(':');
            if (c < 0) {
                user = op.user;
                pass = "";
                w.add(Warning.lossy("-u " + user + " has no password; curl would prompt for one, "
                        + "an empty password is used"));
            } else {
                user = op.user.substring(0, c);
                pass = op.user.substring(c + 1);
            }
        } else if (url.user() != null) {
            user = url.user();
            pass = url.password() == null ? "" : url.password();
        } else {
            return null;
        }
        return "Basic " + Base64.getEncoder().encodeToString((user + ":" + pass).getBytes(StandardCharsets.UTF_8));
    }

    // ---- body ----

    private byte[] assembleBody(Operation op, List<Warning> w) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (Operation.DataPiece p : op.data) {
            // curl joins with '&' only when something has been collected so far (measured: -d '' -d a sends "a")
            if (out.size() > 0 && p.kind != Operation.DataPiece.Kind.JSON) {
                out.write('&');
            }
            writePiece(op, p, out, w);
        }
        return out.toByteArray();
    }

    private void writePiece(Operation op, Operation.DataPiece p, ByteArrayOutputStream out, List<Warning> w) {
        byte[] content;
        boolean fromFile = p.file != null;
        boolean ok = true;
        if (fromFile) {
            byte[][] r = readData(op, p.file, w);
            content = r[0];
            ok = r[1] != null;
        } else {
            content = p.literal;
        }
        switch (p.kind) {
            case ASCII -> {
                if (fromFile && ok) {
                    content = stripNewlines(content);
                }
                out.writeBytes(content);
            }
            case URLENCODE -> {
                if (p.name != null) {
                    out.writeBytes(p.name);
                    out.write('=');
                }
                out.writeBytes(ok ? urlencode(content) : content);
            }
            default -> out.writeBytes(content);
        }
    }

    /** @return {bytes, non-null marker when really read}; on failure the placeholder and a warning */
    private byte[][] readData(Operation op, String path, List<Warning> w) {
        if (path.equals("-")) {
            Operation.StdinSource s = op.stdin;
            if (s != null && s.bytes != null) {
                return new byte[][] {stdinOnce(s, s.bytes), new byte[0]};
            }
            if (s != null && s.file != null) {
                byte[][] r = readData(op, s.file, w);
                if (r[1] != null) {
                    r[0] = stdinOnce(s, r[0]);
                }
                return r;
            }
            w.add(Warning.lossy("The command reads its data from stdin (@-) but no stdin content was pasted"));
            return new byte[][] {"<<STDIN>>".getBytes(StandardCharsets.UTF_8), null};
        }
        try {
            byte[] b = files.read(path);
            if (b != null) {
                return new byte[][] {b, new byte[0]};
            }
        } catch (IOException | RuntimeException e) {
            w.add(Warning.lossy("Could not read " + path + " (" + e.getMessage() + "); a placeholder was used"));
            return new byte[][] {placeholder(path), null};
        }
        w.add(Warning.lossy("Could not read " + path + "; a placeholder was used"));
        return new byte[][] {placeholder(path), null};
    }

    /** curl reads stdin once: a second {@code @-} sees nothing. */
    private byte[] stdinOnce(Operation.StdinSource s, byte[] data) {
        if (stdinRead.put(s, Boolean.TRUE) != null) {
            return new byte[0];
        }
        return data;
    }

    private static byte[] placeholder(String path) {
        return ("<<FILE: " + path + ">>").getBytes(StandardCharsets.UTF_8);
    }

    private static byte[] stripNewlines(byte[] in) {
        ByteArrayOutputStream o = new ByteArrayOutputStream(in.length);
        for (byte b : in) {
            if (b != '\r' && b != '\n') {
                o.write(b);
            }
        }
        return o.toByteArray();
    }

    private static final char[] HEX_UPPER = "0123456789ABCDEF".toCharArray();

    /** curl's {@code --data-urlencode} content: unreserved kept, space becomes '+', the rest %XX (upper case). */
    static byte[] urlencode(byte[] in) {
        ByteArrayOutputStream o = new ByteArrayOutputStream(in.length * 3);
        for (byte x : in) {
            int c = x & 0xff;
            if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '.'
                    || c == '_' || c == '~') {
                o.write(c);
            } else if (c == ' ') {
                o.write('+');
            } else {
                o.write('%');
                o.write(HEX_UPPER[c >> 4]);
                o.write(HEX_UPPER[c & 15]);
            }
        }
        return o.toByteArray();
    }

}
