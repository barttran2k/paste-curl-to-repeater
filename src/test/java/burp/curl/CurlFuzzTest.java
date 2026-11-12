package burp.curl;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

/**
 * Seeded fuzzing: random command lines built from every option of the table must either parse and build into
 * well-formed requests or end in a {@link CurlParseException}; nothing else may escape. The unguarded entry points
 * are used so that the safety net in {@link Curl#parse} cannot hide a bug.
 */
class CurlFuzzTest {
    private static final int ITERATIONS = Integer.getInteger("fuzz.iterations", 25_000);
    private static final long SEED = Long.getLong("fuzz.seed", 20240607L);

    private static final String[] URLS = {"http://127.0.0.1:1/x", "https://example.test/a?b=c#d", "example.test",
            "localhost:8080/p", "http://[::1]:99/", "http://u:p@h.test/", "HTTP://H.TEST/%41", "/relative", "ftp://h/x",
            "http://h/{a,b}", "http://h/[1-3]", "http://", "://x", "http://h:99999/", "http://h/ space", "-", "@-"};
    private static final String[] ARGS = {"", "@file", "@-", "-", "@", "@@", "=", "a=b", "a=@a.txt", "a=@-", "a=<a.txt",
            "a=@a.txt;type=text/plain;filename=x.y;headers=@h.txt", "a=@a.txt,b.txt", "a=b;type=x/y;headers=X: 1",
            "a=\"q;q\"", "+raw=1", "name@file", "k=v&w", "0-5", "-5", "5-", "1", "-1", "999999999999999999999",
            "GET", "POST", "X: y", "X;", "X:", ":", "@hdr.txt", "Content-Type: multipart/mixed",
            "Transfer-Encoding: chunked", "Expect:", "Cookie: a=b", "a=1", "jar.txt", "user:pass", "user", ":pass",
            "Sun, 06 Nov 1994 08:49:37 GMT", "-Sun, 06 Nov 1994 08:49:37 GMT", "=19941106", "not a date", "1 Jan 70",
            "{{v}}", "{{v:trim:json}}", "{{", "}}", "\\{{v}}", "{{v:nope}}", "{{ v }}", "v=1", "v@a.txt", "v@-", "%HOME",
            "%X=d", "%X@a.txt", "/custom", "*", "http://abs.test/x", "http", "ftp", "m\u00e4\u00df\u4e2d\u6587",
            "\u00ff\u00fe", "tab\there", "line\nbreak", "cr\rlf", "\"", "'", "\\", "$HOME", "`x`", "$(x)", "--next",
            "-d", "--data", "-F", "-T", "--"};
    private static final String[] SHORTS = {"s", "S", "L", "k", "v", "i", "I", "G", "g", "0", "4", "6", "f", "O", "J",
            "#", ":", "j", "N", "q", "sSL", "sk", "Ik", "GI", "vL"};
    private static final String[] PRE = {"", "", "", "sudo ", "A=1 ", "time ", "$ ", "echo hi && ", "env X=1 "};

    private final CurlOptionTable table = CurlOptionTable.get();
    private final List<OptionSpec> options = new ArrayList<>(table.all());
    /** the options that change the request, picked more often */
    private final List<OptionSpec> focus = new ArrayList<>();

    CurlFuzzTest() {
        for (String n : new String[] {"form", "form-string", "form-escape", "upload-file", "url-query", "variable",
                "data", "data-binary", "data-raw", "data-urlencode", "json", "time-cond", "cookie", "header", "get",
                "head", "request", "request-target", "proto-default", "crlf", "tr-encoding", "range", "user",
                "referer", "compressed", "oauth2-bearer", "disallow-username-in-url", "globoff", "path-as-is", "url",
                "http1.0", "http2", "next"}) {
            focus.add(table.byLong(n).orElseThrow());
        }
    }

    private static final String PUNCT = "=;:/@-{}[]\\\"'$ \t\n";

    private static String pick(Random r, String[] a) {
        return a[r.nextInt(a.length)];
    }

    private static String randomGarbage(Random r) {
        int n = r.nextInt(12);
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < n; i++) {
            int k = r.nextInt(10);
            sb.append(k < 6 ? (char) ('a' + r.nextInt(26)) : k < 8 ? PUNCT.charAt(r.nextInt(PUNCT.length()))
                    : (char) (0x80 + r.nextInt(0x700)));
        }
        return sb.toString();
    }

    private static String arg(Random r) {
        int k = r.nextInt(20);
        if (k == 0) {
            return randomGarbage(r);
        }
        if (k == 1) {
            return "x".repeat(2000 + r.nextInt(8000));
        }
        if (k == 2) {
            return pick(r, URLS);
        }
        return pick(r, ARGS);
    }

    private static String quote(Random r, String s, boolean cmd) {
        if (s.isEmpty()) {
            return cmd ? "\"\"" : "''";
        }
        int k = r.nextInt(cmd ? 3 : 6);
        if (cmd) {
            return k == 0 ? s.replace(" ", "") : "\"" + s.replace("\"", "\"\"") + "\"";
        }
        switch (k) {
            case 0:
                return s.matches("[A-Za-z0-9_./:=@,+-]+") ? s : "'" + s.replace("'", "'\\''") + "'";
            case 1:
                return "'" + s.replace("'", "'\\''") + "'";
            case 2:
                return "\"" + s.replace("\\", "\\\\").replace("\"", "\\\"").replace("$", "\\$").replace("`", "\\`")
                        + "\"";
            case 3:
                return "$'" + s.replace("\\", "\\\\").replace("'", "\\'").replace("\n", "\\n") + "'";
            case 4:
                return s.replaceAll("([^A-Za-z0-9_./:=@,+-])", "\\\\$1").replace("\n", "'\n'");
            default:
                return "'" + s.replace("'", "'\\''") + "'";
        }
    }

    private String command(Random r, boolean cmd) {
        StringBuilder sb = new StringBuilder();
        sb.append(cmd ? "curl.exe" : pick(r, PRE) + "curl");
        int parts = r.nextInt(8);
        String cont = cmd ? " ^\n  " : r.nextInt(3) == 0 ? " \\\n  " : " ";
        for (int i = 0; i < parts; i++) {
            sb.append(cont);
            int k = r.nextInt(10);
            if (k < 5) {
                OptionSpec o = r.nextInt(10) < 6 ? focus.get(r.nextInt(focus.size()))
                        : options.get(r.nextInt(options.size()));
                String name = o.longName();
                int form = r.nextInt(8);
                String flag = form == 0 ? "--no-" + name : form == 1 ? "--expand-" + name
                        : form == 2 && o.shortName() != 0 ? "-" + o.shortName() : "--" + name;
                sb.append(flag);
                if (o.takesArg() || r.nextInt(10) == 0) {
                    if (flag.startsWith("-") && !flag.startsWith("--") && r.nextBoolean()) {
                        sb.append(quote(r, arg(r), cmd));
                    } else if (r.nextInt(12) == 0) {
                        sb.append('=').append(quote(r, arg(r), cmd));
                    } else {
                        sb.append(' ').append(quote(r, arg(r), cmd));
                    }
                }
            } else if (k < 6) {
                sb.append('-').append(pick(r, SHORTS));
            } else if (k < 7) {
                sb.append(r.nextBoolean() ? "--next" : "-:");
            } else if (k < 9) {
                sb.append(quote(r, r.nextInt(3) == 0 ? arg(r) : pick(r, URLS), cmd));
            } else {
                sb.append(quote(r, randomGarbage(r), cmd));
            }
        }
        if (r.nextInt(5) != 0) {
            sb.append(cont).append(quote(r, pick(r, URLS), cmd));
        }
        if (!cmd) {
            int k = r.nextInt(12);
            if (k == 0) {
                sb.append(" <<'EOF'\n").append(randomGarbage(r)).append("\nEOF");
            } else if (k == 1) {
                sb.append(" <<< ").append(quote(r, randomGarbage(r), false));
            } else if (k == 2) {
                sb.append(" < in.txt");
            } else if (k == 3) {
                sb.append(" | cat");
            } else if (k == 4) {
                sb.append(" > /dev/null 2>&1");
            }
        }
        return sb.toString();
    }

    private String text(Random r) {
        boolean cmd = r.nextInt(10) < 3;
        int n = 1 + (r.nextInt(5) == 0 ? r.nextInt(3) : 0);
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < n; i++) {
            if (i > 0) {
                sb.append(cmd ? "\r\n" : pick(r, new String[] {"\n", " && ", " ; ", " | ", "\n\n", " || "}));
            }
            sb.append(command(r, cmd));
        }
        if (r.nextInt(30) == 0) {
            return randomGarbage(r) + sb;
        }
        return sb.toString();
    }

    /** Files with every kind of content (or none) depending on the path. */
    private static FileAccess randomFiles(Random r) {
        return path -> {
            int k = Math.floorMod(path.hashCode() + r.nextInt(3), 8);
            switch (k) {
                case 0:
                    throw new IOException("denied");
                case 1:
                    return new byte[0];
                case 2:
                    return "line one\r\nline two\n\u0000tail".getBytes(StandardCharsets.UTF_8);
                case 3:
                    return new byte[] {(byte) 0xff, 0, (byte) 0xfe, '\n', '\r', '=', '&'};
                case 4:
                    return "X-File: 1\r\n# c\n\nHost: h\n".getBytes(StandardCharsets.UTF_8);
                case 5:
                    return "127.0.0.1\tFALSE\t/\tFALSE\t0\tn\tv\nSet-Cookie: q=1; Path=/\n".getBytes(StandardCharsets.UTF_8);
                case 6:
                    throw new IllegalStateException("boom");
                default:
                    return "x".repeat(70_000).getBytes(StandardCharsets.UTF_8);
            }
        };
    }

    /**
     * The request starts with a request line ({@code METHOD SP target SP HTTP/1.x CRLF}) and has a blank line.
     * Real curl copies CR/LF in {@code -X} and {@code --request-target} verbatim (measured), so those two are
     * exempt from the single-line requirement; headers and URLs never touch the request line.
     */
    private static void checkWellFormed(BuiltRequest b, String input) {
        String raw = new String(b.raw(), StandardCharsets.ISO_8859_1);
        int eol = raw.indexOf("\r\n");
        assertTrue(eol > 0, "no CRLF: " + shorten(raw) + "\n" + input);
        String first = raw.substring(0, eol);
        boolean exempt = b.method().contains("\r") || b.method().contains("\n") || input.contains("request-");
        if (!exempt) {
            assertTrue(first.matches("[^\\r\\n]+ HTTP/1\\.[01]"), "request line: " + shorten(first) + "\n" + input);
            assertTrue(first.startsWith(new String((b.method() + " ").getBytes(StandardCharsets.UTF_8),
                    StandardCharsets.ISO_8859_1)), "method: " + shorten(first) + "\n" + input);
        }
        assertTrue(raw.contains(" HTTP/1."), "version: " + shorten(raw) + "\n" + input);
        assertTrue(raw.contains("\r\n\r\n"), "CRLFCRLF: " + shorten(raw) + "\n" + input);
    }

    private static String shorten(String s) {
        return s.length() > 300 ? s.substring(0, 300) + "..." : s;
    }

    @Test
    @Timeout(value = 300, unit = TimeUnit.SECONDS)
    void randomCommandLinesEndInSuccessOrParseException() {
        Random r = new Random(SEED);
        int parsed = 0;
        int built = 0;
        List<String> failures = new ArrayList<>();
        java.util.Map<String, Integer> seen = new java.util.TreeMap<>();
        for (int i = 0; i < ITERATIONS && failures.size() < 5; i++) {
            String input = text(r);
            ParsedCurlImpl p;
            try {
                p = Curl.parseUnguarded(input);
                parsed++;
            } catch (CurlParseException e) {
                continue;
            } catch (Throwable t) {
                failures.add("parse threw " + t + " for:\n" + input);
                continue;
            }
            try {
                p.fileRefs();
                p.warnings();
                for (FileAccess files : new FileAccess[] {FileAccess.DENY, randomFiles(r)}) {
                    for (RequestDetails d : p.detailsUnguarded(files)) {
                        checkWellFormed(d.request(), input);
                        built++;
                        String raw = new String(d.request().raw(), StandardCharsets.ISO_8859_1);
                        for (String key : new String[] {"multipart/form-data", "Transfer-Encoding: chunked",
                                "Cookie:", "If-Modified-Since", "TE: gzip", "PUT ", "<<FILE:"}) {
                            if (raw.contains(key)) {
                                seen.merge(key, 1, Integer::sum);
                            }
                        }
                    }
                }
                // the public entry points must agree: success or CurlParseException
                Curl.parse(input).build(randomFiles(r));
            } catch (CurlParseException e) {
                // allowed
            } catch (Throwable t) {
                failures.add("build threw " + t + " for:\n" + input);
            }
        }
        System.out.println("fuzz: " + parsed + " parsed, " + built + " requests built " + seen);
        if (!failures.isEmpty()) {
            fail(failures.size() + " failures, first ones:\n" + String.join("\n-----\n", failures));
        }
        assertTrue(parsed > ITERATIONS / 4, "too few inputs parsed: " + parsed);
        assertTrue(built > ITERATIONS / 4, "too few requests built: " + built);
        assertEquals(0, failures.size());
    }

    @Test
    void nastyInputsNeverEscape() {
        String[] nasty = {"", " ", "\n", "curl", "curl ''", "curl \"", "curl '", "curl <<", "curl <<EOF", "curl \\",
                "curl $'", "curl ${", "curl $(", "curl `", "curl --", "curl -", "curl - -", "curl ^", "curl.exe ^\n",
                "curl " + "-d ".repeat(5000) + "http://h/", "curl " + "(".repeat(3000) + "http://h/",
                "curl http://h/ " + "--next ".repeat(2000), "curl -F @ http://h/", "curl -F = http://h/",
                "curl -T '' http://h/", "curl -b '' http://h/", "curl -z '' http://h/", "curl -H @ http://h/",
                "curl --variable '' --expand-url '{{' http://h/", "curl --expand-url '{{a}}'",
                "curl --request-target '' http://h/", "curl --url-query '' --url-query '+' http://h/",
                "curl -K cfg http://h/", "curl @ http://h/", "curl -- -d http://h/",
                "curl http://h/ -H 'Transfer-Encoding: chunked' -T - -d x"};
        for (String s : nasty) {
            try {
                ParsedCurlImpl p = Curl.parseUnguarded(s);
                for (RequestDetails d : p.detailsUnguarded(FileAccess.DENY)) {
                    checkWellFormed(d.request(), s);
                }
            } catch (CurlParseException e) {
                // allowed
            } catch (Throwable t) {
                fail("threw " + t + " for: " + shorten(s));
            }
        }
    }
}
