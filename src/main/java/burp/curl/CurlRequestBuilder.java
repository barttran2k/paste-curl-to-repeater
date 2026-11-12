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
    /** why each request that could not be built was skipped (a bad URL), in order */
    final List<String> skippedReasons = new ArrayList<>();
    private int requestNumber;
    /** the lossy warning for each skipped request; the caller attaches them to the requests that were built */
    final List<Warning> skippedWarnings = new ArrayList<>();

    CurlRequestBuilder(FileAccess files) {
        this.files = files;
    }

    /** What a request carries as its body, before the headers are written. */
    private static final class Body {
        /** bytes as sent on the wire (for a chunked body set once the header block is known) */
        byte[] wire;
        /** the content after line-end conversion, before chunk encoding */
        byte[] converted;
        /** the content before chunk encoding and line-end conversion (what the legacy facade shows) */
        byte[] content;
        boolean chunked;
        /** true when curl cannot know the size in advance (stdin upload) */
        boolean unknownSize;
        /** size curl knows before any conversion, for the {@code Expect} threshold */
        long knownSize;
        /** default {@code Content-Type}, null for none */
        String contentType;
        /** a custom {@code Content-Type} was folded into {@link #contentType}: the custom lines are not sent */
        boolean dropCustomContentType;
    }

    private static final long EXPECT_THRESHOLD = 1024 * 1024;
    private static final int CHUNK_MAX = 65524;

    void buildOperation(Operation op, List<RequestDetails> result) throws CurlParseException {
        List<Warning> warnings = new ArrayList<>(op.lateWarnings);
        List<String> typed = expandHeaderFiles(op, warnings);

        boolean hasForm = !op.forms.isEmpty();
        boolean hasUpload = !op.uploads.isEmpty();
        boolean hasData = !op.data.isEmpty();
        if (hasForm && hasData) {
            warnings.add(Warning.lossy("curl refuses -d/--data together with -F/--form; the form is sent and the "
                    + "data was dropped"));
            hasData = false;
        }
        if (hasForm && hasUpload) {
            warnings.add(Warning.lossy("curl refuses -F/--form together with -T/--upload-file; the form is sent and "
                    + "the upload was dropped"));
            hasUpload = false;
        }
        if (hasUpload && hasData) {
            warnings.add(Warning.lossy("curl refuses -d/--data together with -T/--upload-file; the upload is sent "
                    + "and the data was dropped"));
            hasData = false;
        }
        if (op.head && (hasForm || hasUpload || (hasData && !op.get))) {
            warnings.add(Warning.lossy(hasForm ? "curl refuses -I/--head together with -F/--form; the form was "
                    + "dropped" : hasUpload ? "curl refuses -I/--head together with -T/--upload-file; the upload "
                    + "was dropped" : "curl refuses -I/--head together with data; the data was dropped"));
            hasForm = false;
            hasUpload = false;
            hasData = false;
        }

        List<String> custom = new ArrayList<>(typed);
        if (op.json) {
            if (!hasCustom(typed, "Content-Type")) {
                custom.add("Content-Type: application/json");
            }
            if (!hasCustom(typed, "Accept")) {
                custom.add("Accept: application/json");
            }
        }

        byte[] dataBody = hasData ? assembleBody(op, warnings) : null;
        Body formBody = null;
        long now = System.currentTimeMillis() / 1000;
        CookieJar jar = loadJar(op, warnings, now);
        boolean customChunked = customChunked(custom);

        int index = 0;
        for (String rawUrl : op.urls) {
            List<Warning> w = new ArrayList<>(warnings);
            requestNumber++;
            CurlUrl url;
            try {
                url = CurlUrl.parse(prepareUrl(rawUrl, op.globoff, w), op.protoDefault, op.pathAsIs);
            } catch (CurlParseException e) {
                // curl reports the failing URL and goes on with the next one; so do we, without echoing the URL
                skippedReasons.add(e.getMessage());
                skippedWarnings.add(Warning.lossy("Request " + requestNumber + " was skipped: " + e.getMessage()));
                index++;
                continue;
            }
            if (op.disallowUsernameInUrl && (url.user() != null)) {
                w.add(Warning.lossy("curl refuses a URL with a user name when --disallow-username-in-url is "
                        + "given; the request is built anyway"));
            }

            Body body = null;
            String method = "GET";
            if (hasUpload && index < op.uploads.size()) {
                String path = op.uploads.get(index);
                byte[][] r = readData(op, path, w);
                body = new Body();
                body.content = r[0];
                body.unknownSize = path.equals("-");
                body.knownSize = r[0].length;
                method = "PUT";
                if (!path.equals("-")) {
                    url = url.withPathSuffix(PathNames.uploadName(path));
                }
            } else if (hasForm) {
                if (formBody == null) {
                    formBody = buildForm(op, custom, w);
                }
                body = copyOf(formBody);
                method = "POST";
            } else if (dataBody != null) {
                if (op.get) {
                    url = appendQuery(url, ByteText.decode(dataBody), w);
                } else {
                    body = new Body();
                    body.content = dataBody;
                    body.knownSize = dataBody.length;
                    body.contentType = "application/x-www-form-urlencoded";
                    method = "POST";
                }
            }
            index++;

            if (op.get && dataBody != null && !op.urlQueries.isEmpty() && index == 1) {
                w.add(Warning.note("curl ignores --url-query when -G turns the -d data into the query"));
            }
            if (!(op.get && dataBody != null)) {
                url = appendUrlQueries(op, url, w);
            }
            if (op.head) {
                method = "HEAD";
            }
            if (op.method != null) {
                method = op.method;
            }

            if (body != null) {
                finishBody(op, body, customChunked, w);
            } else if (customChunked) {
                body = new Body();
                body.content = new byte[0];
                body.chunked = true;
                body.converted = new byte[0];
            }
            byte[] head = headerBlock(op, url, custom, method, body, jar, now, w);
            if (body != null && body.chunked) {
                // measured: when the request head travels together with the body the first chunk is smaller by
                // the size of the head (the send buffer is 64 KiB); after an Expect: 100-continue it is not
                int first = sendsExpect(op, custom, body) ? CHUNK_MAX : CHUNK_MAX - head.length;
                body.wire = chunkEncode(body.converted, first > 0 ? first : CHUNK_MAX);
            }
            byte[] raw = head;
            if (body != null) {
                raw = new byte[head.length + body.wire.length];
                System.arraycopy(head, 0, raw, 0, head.length);
                System.arraycopy(body.wire, 0, raw, head.length, body.wire.length);
            }
            int explicit = url.port() != (url.secure() ? 443 : 80) ? url.port() : -1;
            BuiltRequest br = new BuiltRequest(url.host(), url.port(), url.secure(), raw, ByteText.display(method),
                    ByteText.display(url.toString()), w);
            List<String> shownHeaders = new ArrayList<>();
            for (String h : typed) {
                shownHeaders.add(ByteText.display(h));
            }
            result.add(new RequestDetails(br, url.scheme(), url.host(), explicit, ByteText.display(url.path()),
                    ByteText.display(url.query()), shownHeaders, body != null ? body.content : new byte[0]));
        }
    }

    private static Body copyOf(Body b) {
        Body c = new Body();
        c.content = b.content;
        c.unknownSize = b.unknownSize;
        c.knownSize = b.knownSize;
        c.contentType = b.contentType;
        c.dropCustomContentType = b.dropCustomContentType;
        return c;
    }

    /** Applies {@code --crlf}, decides on chunking and produces the wire bytes. */
    private static void finishBody(Operation op, Body b, boolean customChunked, List<Warning> w) {
        byte[] bytes = b.content;
        if (op.crlf) {
            bytes = crlf(bytes);
        }
        b.converted = bytes;
        b.chunked = customChunked || b.unknownSize || op.crlf;
        b.wire = b.chunked ? null : bytes;
    }

    /**
     * curl 8.7.1 with {@code --crlf}: every LF becomes CRLF (also one that follows a CR) and what follows the last LF
     * is lost (measured). Without any LF the data is unchanged.
     */
    static byte[] crlf(byte[] in) {
        int last = -1;
        for (int i = 0; i < in.length; i++) {
            if (in[i] == '\n') {
                last = i;
            }
        }
        if (last < 0) {
            return in;
        }
        ByteArrayOutputStream o = new ByteArrayOutputStream(in.length + 16);
        for (int i = 0; i <= last; i++) {
            if (in[i] == '\n') {
                o.write('\r');
            }
            o.write(in[i]);
        }
        return o.toByteArray();
    }

    private static byte[] chunkEncode(byte[] data, int firstMax) {
        ByteArrayOutputStream o = new ByteArrayOutputStream(data.length + 32);
        int off = 0;
        int max = firstMax;
        while (off < data.length) {
            int n = Math.min(max, data.length - off);
            max = CHUNK_MAX;
            o.writeBytes((Integer.toHexString(n) + "\r\n").getBytes(StandardCharsets.US_ASCII));
            o.write(data, off, n);
            o.writeBytes("\r\n".getBytes(StandardCharsets.US_ASCII));
            off += n;
        }
        o.writeBytes("0\r\n\r\n".getBytes(StandardCharsets.US_ASCII));
        return o.toByteArray();
    }

    /** curl's check for a custom {@code Transfer-Encoding} header that names {@code chunked}. */
    private static boolean customChunked(List<String> custom) {
        for (String h : custom) {
            if (matches(h, "Transfer-Encoding") && h.indexOf(':') >= 0) {
                for (String t : valueAfterColon(h).split("[\\s,;]+")) {
                    if (t.equalsIgnoreCase("chunked")) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    // ---- header files, cookies, query ----

    /** The {@code -H} lines with every {@code -H @file} replaced by the lines of the file. */
    private List<String> expandHeaderFiles(Operation op, List<Warning> w) {
        List<String> out = new ArrayList<>();
        for (String h : op.headers) {
            if (!h.startsWith("@")) {
                out.add(h);
                continue;
            }
            String path = h.substring(1);
            byte[][] r = readData(op, path, w);
            if (r[1] == null) {
                out.add("X-Unreadable-Header-File: <<FILE: " + path + ">>");
                continue;
            }
            for (String line : ByteText.decode(r[0]).split("\n", -1)) {
                String l = line.endsWith("\r") ? line.substring(0, line.length() - 1) : line;
                if (!l.isEmpty() && l.charAt(0) != '#') {
                    out.add(l);
                }
            }
        }
        return out;
    }

    private CookieJar loadJar(Operation op, List<Warning> w, long now) {
        if (op.cookieFiles.isEmpty()) {
            return null;
        }
        CookieJar jar = new CookieJar();
        w.add(Warning.note("Cookies from the -b file were chosen for this URL by domain, path, secure flag and "
                + "expiry as of now; curl decides the same way when it sends the request"));
        for (String f : op.cookieFiles) {
            byte[][] r = readData(op, f, w);
            if (r[1] == null) {
                jar.addPlaceholder(ByteText.decode(r[0]));
            } else {
                jar.load(r[0], now, op.junkSessionCookies);
            }
        }
        return jar;
    }

    /** {@code --url-query}: the pieces are appended to the query like {@code -G} data. */
    private CurlUrl appendUrlQueries(Operation op, CurlUrl url, List<Warning> w) {
        if (op.urlQueries.isEmpty()) {
            return url;
        }
        ByteArrayOutputStream joined = new ByteArrayOutputStream();
        for (Operation.UrlQuery q : op.urlQueries) {
            if (joined.size() > 0) {
                joined.write('&');
            }
            if (q.raw) {
                joined.writeBytes(q.literal);
                continue;
            }
            byte[] content;
            boolean ok = true;
            if (q.file != null) {
                byte[][] r = readData(op, q.file, w);
                content = r[0];
                ok = r[1] != null;
            } else {
                content = q.literal;
            }
            if (q.name != null) {
                joined.writeBytes(q.name);
                joined.write('=');
            }
            joined.writeBytes(ok ? urlencode(content) : content);
        }
        return appendQuery(url, ByteText.decode(joined.toByteArray()), w);
    }

    /**
     * Appends query text to the URL. curl 8.7.1 refuses a query with control characters (exit 3, measured); here
     * they are percent-encoded so that a usable request is still built, and a warning says so.
     */
    private static CurlUrl appendQuery(CurlUrl url, String piece, List<Warning> w) {
        StringBuilder sb = null;
        for (int i = 0; i < piece.length(); i++) {
            char c = piece.charAt(i);
            if (c < 0x20 || c == 0x7f) {
                if (sb == null) {
                    sb = new StringBuilder(piece.length() + 8).append(piece, 0, i);
                }
                sb.append('%').append(HEX_UPPER[c >> 4]).append(HEX_UPPER[c & 15]);
            } else if (sb != null) {
                sb.append(c);
            }
        }
        if (sb == null) {
            return url.withAppendedQuery(piece);
        }
        w.add(Warning.lossy("curl refuses a query that contains control characters (URL rejected); they are "
                + "percent-encoded here"));
        return url.withAppendedQuery(sb.toString());
    }

    // ---- forms ----

    private Body buildForm(Operation op, List<String> custom, List<Warning> w) {
        java.util.Set<String> headerFiles = new java.util.HashSet<>();
        for (FormField f : op.forms) {
            collectHeaderFiles(f, headerFiles);
        }
        FileAccess access = path -> {
            byte[][] r = readData(op, path, w);
            if (r[1] == null && headerFiles.contains(path)) {
                return new byte[0];
            }
            return r[0];
        };
        MultipartBuilder mb = new MultipartBuilder().formEscape(op.formEscape);
        String customType = null;
        for (String h : custom) {
            if (matches(h, "Content-Type")) {
                customType = h.length() > 13 ? h.substring(13).stripLeading() : "";
                break;
            }
        }
        if (customType != null) {
            String t = customType;
            boolean formData = t.regionMatches(true, 0, "multipart/form-data", 0, 19)
                    && (t.length() == 19 || t.charAt(19) == ';' || t.charAt(19) == ' ' || t.charAt(19) == '\t');
            mb.disposition(formData ? "form-data" : "attachment");
        }
        for (FormField f : op.forms) {
            try {
                mb.add(f, access);
            } catch (IOException | RuntimeException e) {
                w.add(Warning.lossy("A form field could not be built ("
                        + (e instanceof IOException ? e.getMessage() : e.getClass().getSimpleName())
                        + "); it was skipped"));
            }
        }
        Body b = new Body();
        b.content = mb.build();
        b.knownSize = b.content.length;
        b.contentType = customType != null ? customType + "; boundary=" + mb.boundary() : mb.contentType();
        b.dropCustomContentType = customType != null;
        return b;
    }

    private static void collectHeaderFiles(FormField f, java.util.Set<String> out) {
        try {
            List<FormField> parts = f.kind() == FormField.Kind.FILE_LIST ? f.files() : List.of(f);
            for (FormField p : parts) {
                out.addAll(p.headerFilePaths());
            }
        } catch (CurlParseException e) {
            // not reachable for fields from FormField.parse
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

    private byte[] headerBlock(Operation op, CurlUrl url, List<String> custom, String method, Body body,
                               CookieJar jar, long now, List<Warning> w) {
        StringBuilder sb = new StringBuilder();
        sb.append(method).append(' ').append(op.requestTarget != null ? op.requestTarget : url.requestTarget())
                .append(op.http10 ? " HTTP/1.0" : " HTTP/1.1").append("\r\n");

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
                sb.append("Content-Range: bytes ").append(op.range).append('/').append(body.knownSize)
                        .append("\r\n");
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
        boolean mergedConnection = false;
        if (op.trEncoding && !hasCustom(custom, "TE")) {
            String conn = "TE";
            for (String h : custom) {
                if (matches(h, "Connection") && h.indexOf(':') >= 0 && !blank(valueAfterColon(h))) {
                    conn = valueAfterColon(h) + ", TE";
                    break;
                }
            }
            sb.append("Connection: ").append(conn).append("\r\nTE: gzip\r\n");
            mergedConnection = true;
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
        cookieHeader(op, url, custom, jar, now, sb);
        timeCondition(op, custom, sb, w);

        // custom headers
        for (String h : custom) {
            if (matches(h, "Host") || (mergedConnection && matches(h, "Connection"))
                    || (body != null && body.dropCustomContentType && matches(h, "Content-Type"))) {
                continue;
            }
            int colon = h.indexOf(':');
            if (colon == 0) {
                // curl 8.7.1 never sends a line that starts with ':' (HTTP/2 pseudo headers, ': x'; measured)
                continue;
            }
            if (colon >= 0) {
                if (!blank(h.substring(colon + 1))) {
                    sb.append(h).append("\r\n");
                }
            } else {
                int semi = h.indexOf(';');
                if (semi >= 0 && semi == h.length() - 1) {
                    sb.append(h, 0, semi).append(":\r\n");
                }
            }
        }

        if (body != null) {
            if (body.chunked) {
                if (!customChunked(custom)) {
                    sb.append("Transfer-Encoding: chunked\r\n");
                }
            } else if (!hasCustom(custom, "Content-Length")) {
                sb.append("Content-Length: ").append(body.wire.length).append("\r\n");
            }
            if (body.contentType != null && (body.dropCustomContentType || !hasCustom(custom, "Content-Type"))) {
                sb.append("Content-Type: ").append(body.contentType).append("\r\n");
            }
            if (sendsExpect(op, custom, body)) {
                sb.append("Expect: 100-continue\r\n");
            }
        }
        sb.append("\r\n");
        return ByteText.encode(sb.toString());
    }

    /** curl adds {@code Expect: 100-continue} for HTTP/1.1 bodies of unknown size or above 1 MiB. */
    private static boolean sendsExpect(Operation op, List<String> custom, Body body) {
        return body != null && !op.http10 && !hasCustom(custom, "Expect")
                && (body.unknownSize || body.knownSize > EXPECT_THRESHOLD);
    }

    /** Jar cookies first (longest path first), then the {@code -b name=value} strings. */
    private static void cookieHeader(Operation op, CurlUrl url, List<String> custom, CookieJar jar, long now,
                                     StringBuilder sb) {
        List<String> pieces = new ArrayList<>();
        if (jar != null) {
            pieces.addAll(jar.placeholders());
            for (CookieJar.Cookie c : jar.matching(url.host(), url.path(), url.secure(), now)) {
                pieces.add(c.name + "=" + c.value);
            }
        }
        String line = String.join("; ", pieces);
        if (!op.cookies.isEmpty() && !hasCustom(custom, "Cookie")) {
            line = line.isEmpty() ? String.join(";", op.cookies) : line + "; " + String.join(";", op.cookies);
        }
        if (!line.isEmpty()) {
            sb.append("Cookie: ").append(line).append("\r\n");
        }
    }

    /** {@code -z}: {@code If-Modified-Since}, with a leading '-' {@code If-Unmodified-Since}, '=' {@code Last-Modified}. */
    private static void timeCondition(Operation op, List<String> custom, StringBuilder sb, List<Warning> w) {
        if (op.timeCond == null) {
            return;
        }
        String arg = op.timeCond;
        String header = "If-Modified-Since";
        if (arg.startsWith("-")) {
            header = "If-Unmodified-Since";
            arg = arg.substring(1);
        } else if (arg.startsWith("=")) {
            header = "Last-Modified";
            arg = arg.substring(1);
        } else if (arg.startsWith("+")) {
            arg = arg.substring(1);
        }
        Long t = CurlDate.parse(arg);
        if (t == null) {
            w.add(Warning.lossy("The -z argument is not a date curl understands; curl then treats it as the name "
                    + "of a file whose modification time is used, or sends no time condition. No time condition "
                    + "header was added."));
            return;
        }
        if (!hasCustom(custom, header)) {
            sb.append(header).append(": ").append(CurlDate.format(t)).append("\r\n");
        }
    }

    private static String authorization(Operation op, CurlUrl url, List<Warning> w) {
        int mask = op.authMask;
        boolean wantsBasic = mask == 0 || mask == Operation.AUTH_BASIC;
        boolean wantsBearer = op.bearer != null && mask == Operation.AUTH_BEARER;
        if (op.bearer != null) {
            if (wantsBearer) {
                return "Bearer " + op.bearer;
            }
            suppressed(op, w);
            return null;
        }
        if (!wantsBasic) {
            if ((op.user != null && !op.user.isEmpty()) || url.user() != null) {
                suppressed(op, w);
            }
            return null;
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
                w.add(Warning.lossy("-u has no password; curl would prompt for one, an empty password is used"));
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
        return "Basic " + Base64.getEncoder().encodeToString(ByteText.encode(user + ":" + pass));
    }

    /** curl waits for a challenge with this mix of methods, and a challenge/response handshake is not reproduced. */
    private static void suppressed(Operation op, List<Warning> w) {
        w.add(Warning.lossy("curl sends no Authorization header on the first request with " + String.join(" ",
                op.authOptions) + " (the credentials are not sent as Basic or Bearer); none is added here"));
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
        FileReads.Result r;
        if (path.equals("-")) {
            r = FileReads.readStdin(op.stdin, files, w);
            if (r.ok()) {
                r = new FileReads.Result(stdinOnce(op.stdin, r.bytes()), true);
            }
        } else {
            r = FileReads.read(files, path, w);
        }
        return new byte[][] {r.bytes(), r.ok() ? new byte[0] : null};
    }

    /** curl reads stdin once: a second {@code @-} sees nothing. */
    private byte[] stdinOnce(Operation.StdinSource s, byte[] data) {
        if (stdinRead.put(s, Boolean.TRUE) != null) {
            return new byte[0];
        }
        return data;
    }

    private static byte[] stripNewlines(byte[] in) {
        ByteArrayOutputStream o = new ByteArrayOutputStream(in.length);
        for (byte b : in) {
            if (b != '\r' && b != '\n' && b != 0) {
                o.write(b);
            }
        }
        return o.toByteArray();
    }

    /** curl's {@code url} variable function: everything except {@code A-Za-z0-9-._~} becomes %XX (upper case). */
    static byte[] urlEncodeAll(byte[] in) {
        ByteArrayOutputStream o = new ByteArrayOutputStream(in.length * 3);
        for (byte x : in) {
            int c = x & 0xff;
            if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '.'
                    || c == '_' || c == '~') {
                o.write(c);
            } else {
                o.write('%');
                o.write(HEX_UPPER[c >> 4]);
                o.write(HEX_UPPER[c & 15]);
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
