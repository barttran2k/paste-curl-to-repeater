package burp.curl;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * Pins the request bytes. Every expectation was captured from the real curl 8.7.1 with
 * {@code python3 cap.py <curl args>} (a one-connection capture server on 127.0.0.1 that records the raw bytes;
 * {@code @P} in the arguments is the server port). In the expectations {@code HOST} stands for the
 * {@code 127.0.0.1:<port>} that curl printed; the tests use {@code 127.0.0.1:8080}.
 */
class CurlRequestBuilderTest {
    private static final String H = "127.0.0.1:8080";
    private static final String U = "http://" + H;

    private final Map<String, byte[]> files = new HashMap<>();
    private final FileAccess fake = p -> {
        byte[] b = files.get(p);
        if (b == null) {
            throw new IOException("no such file: " + p);
        }
        return b;
    };

    private List<BuiltRequest> buildAll(String cmd) throws Exception {
        return Curl.parse(cmd.replace("@U", U)).build(fake);
    }

    private String raw(String cmd) throws Exception {
        List<BuiltRequest> r = buildAll(cmd);
        assertEquals(1, r.size(), "request count");
        return new String(r.get(0).raw(), StandardCharsets.ISO_8859_1);
    }

    /** head: lines joined by \n (turned into CRLF), body appended after the blank line. */
    private static String wire(String head, String body) {
        return head.replace("HOST", H).replace("\n", "\r\n") + "\r\n\r\n" + body;
    }

    private void check(String cmd, String head) throws Exception {
        assertEquals(wire(head, ""), raw(cmd), cmd);
    }

    private void check(String cmd, String head, String body) throws Exception {
        assertEquals(wire(head, body), raw(cmd), cmd);
    }

    private static final String BASIC = "Host: HOST\nUser-Agent: curl/8.7.1\nAccept: */*";

    // ---- facts 1 and 2: request line, defaults, order ----

    @Test
    void plainGet() throws Exception {
        // cap.py http://127.0.0.1:@P/x
        check("curl @U/x", "GET /x HTTP/1.1\n" + BASIC);
    }

    @Test
    void http10() throws Exception {
        // cap.py -0 http://127.0.0.1:@P/p
        check("curl -0 @U/p", "GET /p HTTP/1.0\n" + BASIC);
        check("curl --http1.0 @U/p", "GET /p HTTP/1.0\n" + BASIC);
    }

    @Test
    void internalHeaderOrder() throws Exception {
        // cap.py -u user:pa:ss -b a=1 -b b=2 -e 'http://r/x;auto' -r 0-9 --compressed -A 'ua' -H 'X: 1' http://127.0.0.1:@P/x
        // (with -A '' the User-Agent line disappears: captured as Host, Authorization, Range, Accept, Accept-Encoding,
        // Referer, Cookie)
        check("curl -u user:pa:ss -b a=1 -b b=2 -e 'http://r/x;auto' -r 0-9 -A '' --compressed @U/x",
                "GET /x HTTP/1.1\nHost: HOST\nAuthorization: Basic dXNlcjpwYTpzcw==\nRange: bytes=0-9\n"
                        + "Accept: */*\nAccept-Encoding: deflate, gzip\nReferer: http://r/x\nCookie: a=1;b=2");
        check("curl -A 'a b' -H 'X-1: a' -H 'X-1: b' -e 'r;auto;x' @U/x",
                "GET /x HTTP/1.1\nHost: HOST\nUser-Agent: a b\nAccept: */*\nReferer: r\nX-1: a\nX-1: b");
    }

    @Test
    void chromeCopyAsCurl() throws Exception {
        // the Chrome-style command of the brief, captured with the real curl (bash $'..' quoting)
        String cmd = "curl '@U/v1/users/42?expand=roles&fields=id,name' \\\n"
                + "  -X 'PUT' \\\n"
                + "  -H 'accept: application/json, text/plain, */*' \\\n"
                + "  -H 'content-type: application/json' \\\n"
                + "  -b 'session=abc123; csrftoken=xyz' \\\n"
                + "  -H 'sec-ch-ua: \"Chromium\";v=\"130\", \"Google Chrome\";v=\"130\", \"Not?A_Brand\";v=\"99\"' \\\n"
                + "  -H 'user-agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)' \\\n"
                + "  --data-raw $'{\"name\":\"O\\'Brien\",\"note\":\"line1\\\\nline2 -H \\'x: y\\'\"}' \\\n"
                + "  --compressed";
        String head = "PUT /v1/users/42?expand=roles&fields=id,name HTTP/1.1\n"
                + "Host: HOST\n"
                + "Accept-Encoding: deflate, gzip\n"
                + "Cookie: session=abc123; csrftoken=xyz\n"
                + "accept: application/json, text/plain, */*\n"
                + "content-type: application/json\n"
                + "sec-ch-ua: \"Chromium\";v=\"130\", \"Google Chrome\";v=\"130\", \"Not?A_Brand\";v=\"99\"\n"
                + "user-agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)\n"
                + "Content-Length: 50";
        check(cmd, head, "{\"name\":\"O'Brien\",\"note\":\"line1\\nline2 -H 'x: y'\"}");
    }

    // ---- facts 3 and 4: custom headers ----

    @Test
    void customHostReplacesValueInFirstPosition() throws Exception {
        // cap.py -H 'Host: foo.test' -H 'X-A: 1' http://127.0.0.1:@P/x
        check("curl -H 'Host: foo.test' -H 'X-A: 1' @U/x",
                "GET /x HTTP/1.1\nHost: foo.test\nUser-Agent: curl/8.7.1\nAccept: */*\nX-A: 1");
        // cap.py -H 'host: a' -H 'Host: b' ...  -> only the first, canonical name
        check("curl -H 'host: a' -H 'Host: b' @U/x", "GET /x HTTP/1.1\nHost: a\nUser-Agent: curl/8.7.1\nAccept: */*");
        // cap.py -H 'Host:' ... removes Host; -H 'Host;' sends an empty Host
        check("curl -H 'Host:' @U/x", "GET /x HTTP/1.1\nUser-Agent: curl/8.7.1\nAccept: */*");
        check("curl -H 'Host;' @U/x", "GET /x HTTP/1.1\nHost:\nUser-Agent: curl/8.7.1\nAccept: */*");
    }

    @Test
    void customHeaderSuppressesInternalOne() throws Exception {
        // cap.py -u a:b -H 'authorization: z' ...
        check("curl -u a:b -H 'authorization: z' @U/x", "GET /x HTTP/1.1\n" + BASIC + "\nauthorization: z");
        // cap.py -b a=1 -H 'cookie: z' ...
        check("curl -b a=1 -H 'cookie: z' @U/x", "GET /x HTTP/1.1\n" + BASIC + "\ncookie: z");
        // cap.py -r 5- -H 'range: x' ...
        check("curl -r 5- -H 'range: x' @U/x", "GET /x HTTP/1.1\n" + BASIC + "\nrange: x");
        // cap.py --compressed -H 'Accept-Encoding: gzip' ...
        check("curl --compressed -H 'Accept-Encoding: gzip' @U/x", "GET /x HTTP/1.1\n" + BASIC + "\nAccept-Encoding: gzip");
    }

    @Test
    void emptyValueRemovesAndSemicolonSendsEmpty() throws Exception {
        // cap.py -H 'X-Pad:    padded value   ' -H 'Name;' -H 'nocolon' -H 'Accept:' -H 'x: a' -H 'X:' ...
        check("curl -H 'X-Pad:    padded value   ' -H 'Name;' -H 'nocolon' -H 'Accept:' -H 'x: a' -H 'X:' @U/x",
                "GET /x HTTP/1.1\nHost: HOST\nUser-Agent: curl/8.7.1\nX-Pad:    padded value   \nName:\nx: a");
        // cap.py -H 'User-Agent;' -H 'Accept ;' ...: ';' form also suppresses; "Accept " does not match "Accept"
        check("curl -H 'User-Agent;' -H 'Accept ;' @U/x",
                "GET /x HTTP/1.1\nHost: HOST\nAccept: */*\nUser-Agent:\nAccept :");
        // cap.py -H 'X-A:;' -H 'X-B: ' -H 'X-C:<TAB>' ...
        check("curl -H 'X-A:;' -H 'X-B: ' -H $'X-C:\\t' @U/x", "GET /x HTTP/1.1\n" + BASIC + "\nX-A:;");
        // cap.py -H 'Accept-Encoding;' --compressed ...
        check("curl -H 'Accept-Encoding;' --compressed @U/x", "GET /x HTTP/1.1\n" + BASIC + "\nAccept-Encoding:");
    }

    // ---- fact 5: methods ----

    @Test
    void methods() throws Exception {
        // cap.py -X POST http://127.0.0.1:@P/x   (no Content-Length)
        check("curl -X POST @U/x", "POST /x HTTP/1.1\n" + BASIC);
        // cap.py -I -X PROPFIND ...
        check("curl -I -X PROPFIND @U/x", "PROPFIND /x HTTP/1.1\n" + BASIC);
        check("curl -I @U/x", "HEAD /x HTTP/1.1\n" + BASIC);
        // cap.py -X post ... (sent as typed)
        check("curl -X post @U/x", "post /x HTTP/1.1\n" + BASIC);
        // brief: -X GET -d x=1 keeps the body
        check("curl -X GET -d x=1 @U/x", "GET /x HTTP/1.1\n" + BASIC + "\nContent-Length: 3\n"
                + "Content-Type: application/x-www-form-urlencoded", "x=1");
    }

    // ---- fact 6: data ----

    @Test
    void dataJoinedWithAmpersand() throws Exception {
        // cap.py -d a -d '' -d b ...
        check("curl -d a -d '' -d b @U/x", "POST /x HTTP/1.1\n" + BASIC
                + "\nContent-Length: 4\nContent-Type: application/x-www-form-urlencoded", "a&&b");
        // cap.py -d '' ...
        check("curl -d '' @U/x", "POST /x HTTP/1.1\n" + BASIC
                + "\nContent-Length: 0\nContent-Type: application/x-www-form-urlencoded");
        // cap.py --data-raw '@x' --data-raw '' ...
        check("curl --data-raw '@x' --data-raw '' @U/x", "POST /x HTTP/1.1\n" + BASIC
                + "\nContent-Length: 3\nContent-Type: application/x-www-form-urlencoded", "@x&");
    }

    @Test
    void emptyLeadingPiecesAddNoSeparator() throws Exception {
        String form = "\nContent-Type: application/x-www-form-urlencoded";
        // cap.py -d a -d '' -d '' ...
        check("curl -d a -d '' -d '' @U/x", "POST /x HTTP/1.1\n" + BASIC + "\nContent-Length: 3" + form, "a&&");
        // cap.py -d '' -d '' -d '' -d a ...
        check("curl -d '' -d '' -d '' -d a @U/x", "POST /x HTTP/1.1\n" + BASIC + "\nContent-Length: 1" + form, "a");
        // cap.py -d '' --json '' -d a ...
        check("curl -d '' --json '' -d a @U/x",
                "POST /x HTTP/1.1\nHost: HOST\nUser-Agent: curl/8.7.1\nContent-Type: application/json\n"
                        + "Accept: application/json\nContent-Length: 1", "a");
        // cap.py -d @empty.txt -d b ...
        files.put("empty.txt", new byte[0]);
        check("curl -d @empty.txt -d b @U/x", "POST /x HTTP/1.1\n" + BASIC + "\nContent-Length: 1" + form, "b");
    }

    @Test
    void rangeOnARequestWithBodyIsContentRange() throws Exception {
        String form = "\nContent-Type: application/x-www-form-urlencoded";
        // cap.py -r 3-4 -d a -X GET ...   (decided by the body, not by the method word)
        check("curl -r 3-4 -d a -X GET @U/x", "GET /x HTTP/1.1\nHost: HOST\nContent-Range: bytes 3-4/1\n"
                + "User-Agent: curl/8.7.1\nAccept: */*\nContent-Length: 1" + form, "a");
        // cap.py -r 3- -d abc ...
        check("curl -r 3- -d abc @U/x", "POST /x HTTP/1.1\nHost: HOST\nContent-Range: bytes 3-/3\n"
                + "User-Agent: curl/8.7.1\nAccept: */*\nContent-Length: 3" + form, "abc");
        // cap.py -r 3-4 -d a -H 'Content-Range: z' ...
        check("curl -r 3-4 -d a -H 'Content-Range: z' @U/x", "POST /x HTTP/1.1\n" + BASIC
                + "\nContent-Range: z\nContent-Length: 1" + form, "a");
        // cap.py -r 3-4 -d a -H 'Range: z' ... : a custom Range does not suppress Content-Range
        check("curl -r 3-4 -d a -H 'Range: z' @U/x", "POST /x HTTP/1.1\nHost: HOST\nContent-Range: bytes 3-4/1\n"
                + "User-Agent: curl/8.7.1\nAccept: */*\nRange: z\nContent-Length: 1" + form, "a");
        // cap.py -r 3-4 -X POST ... (no body: plain Range)
        check("curl -r 3-4 -X POST @U/x",
                "POST /x HTTP/1.1\nHost: HOST\nRange: bytes=3-4\nUser-Agent: curl/8.7.1\nAccept: */*");
        // cap.py -r 3-4 -G -d a=1 ...
        check("curl -r 3-4 -G -d a=1 @U/x",
                "GET /x?a=1 HTTP/1.1\nHost: HOST\nRange: bytes=3-4\nUser-Agent: curl/8.7.1\nAccept: */*");
    }

    @Test
    void jsonPieceHasNoSeparator() throws Exception {
        // cap.py -d a=1 --json '{"b":2}' -d c=3 ...
        check("curl -d a=1 --json '{\"b\":2}' -d c=3 @U/x",
                "POST /x HTTP/1.1\nHost: HOST\nUser-Agent: curl/8.7.1\nContent-Type: application/json\n"
                        + "Accept: application/json\nContent-Length: 14", "a=1{\"b\":2}&c=3");
        // cap.py --json a --json b ...
        check("curl --json a --json b @U/x",
                "POST /x HTTP/1.1\nHost: HOST\nUser-Agent: curl/8.7.1\nContent-Type: application/json\n"
                        + "Accept: application/json\nContent-Length: 2", "ab");
        // cap.py --json '' ...
        check("curl --json '' @U/x",
                "POST /x HTTP/1.1\nHost: HOST\nUser-Agent: curl/8.7.1\nContent-Type: application/json\n"
                        + "Accept: application/json\nContent-Length: 0");
    }

    @Test
    void dataFiles() throws Exception {
        files.put("f.txt", "l1\r\nl2\nl3 x\r".getBytes(StandardCharsets.ISO_8859_1));
        String form = "\nContent-Type: application/x-www-form-urlencoded";
        // cap.py -d @f.txt / --data-ascii @f.txt : CR and LF removed
        check("curl -d @f.txt @U/x", "POST /x HTTP/1.1\n" + BASIC + "\nContent-Length: 8" + form, "l1l2l3 x");
        check("curl --data-ascii @f.txt @U/x", "POST /x HTTP/1.1\n" + BASIC + "\nContent-Length: 8" + form, "l1l2l3 x");
        // cap.py --data-binary @f.txt : bytes untouched
        check("curl --data-binary @f.txt @U/x", "POST /x HTTP/1.1\n" + BASIC + "\nContent-Length: 12" + form,
                "l1\r\nl2\nl3 x\r");
        // cap.py --json @f.txt : like --data-binary
        check("curl --json @f.txt @U/x",
                "POST /x HTTP/1.1\nHost: HOST\nUser-Agent: curl/8.7.1\nContent-Type: application/json\n"
                        + "Accept: application/json\nContent-Length: 12", "l1\r\nl2\nl3 x\r");
        // attached form: -d@f.txt
        check("curl -d@f.txt @U/x", "POST /x HTTP/1.1\n" + BASIC + "\nContent-Length: 8" + form, "l1l2l3 x");
    }

    @Test
    void heredocStdin() throws Exception {
        // printf 'in\nput\r\n' | cap.py --data-binary @-  -> bytes untouched; -d @- -> "input"
        String cmd = "curl %s @U/x <<'EOF'\nin\nput\nEOF\n";
        ParsedCurl p = Curl.parse(String.format(cmd, "--data-binary @-").replace("@U", U));
        assertEquals("in\nput\n", new String(bodyOf(p.build(fake).get(0)), StandardCharsets.ISO_8859_1));
        ParsedCurl p2 = Curl.parse(String.format(cmd, "-d @-").replace("@U", U));
        assertEquals("input", new String(bodyOf(p2.build(fake).get(0)), StandardCharsets.ISO_8859_1));
        // the second @- sees nothing, as with curl reading an exhausted stdin
        ParsedCurl p3 = Curl.parse(String.format(cmd, "--data-binary @- --data-binary @-").replace("@U", U));
        assertEquals("in\nput\n&", new String(bodyOf(p3.build(fake).get(0)), StandardCharsets.ISO_8859_1));
    }

    private static byte[] bodyOf(BuiltRequest r) {
        byte[] raw = r.raw();
        String s = new String(raw, StandardCharsets.ISO_8859_1);
        int i = s.indexOf("\r\n\r\n") + 4;
        return java.util.Arrays.copyOfRange(raw, i, raw.length);
    }

    @Test
    void stdinFromRedirectedFile() throws Exception {
        files.put("in.txt", "in\nput\r\n".getBytes(StandardCharsets.ISO_8859_1));
        ParsedCurl p = Curl.parse("curl -d @- " + U + "/x < in.txt");
        assertEquals(List.of("in.txt"), p.fileRefs());
        // cap.py -d @- (stdin "in\nput\r\n") -> body "input"
        assertEquals("input", new String(bodyOf(p.build(fake).get(0)), StandardCharsets.ISO_8859_1));
        // cap.py --data-urlencode @- -> "in%0Aput%0D%0A"
        ParsedCurl q = Curl.parse("curl --data-urlencode @- " + U + "/x < in.txt");
        assertEquals("in%0Aput%0D%0A", new String(bodyOf(q.build(fake).get(0)), StandardCharsets.ISO_8859_1));
        // cap.py --data-urlencode n@- -> "n=in%0Aput%0D%0A"
        ParsedCurl r = Curl.parse("curl --data-urlencode n@- " + U + "/x < in.txt");
        assertEquals("n=in%0Aput%0D%0A", new String(bodyOf(r.build(fake).get(0)), StandardCharsets.ISO_8859_1));
    }

    // ---- fact 7: --data-urlencode ----

    @Test
    void dataUrlencode() throws Exception {
        String form = "\nContent-Type: application/x-www-form-urlencoded";
        // cap.py --data-urlencode 'a+b=c d+e/~_.-*!é' ...
        check("curl --data-urlencode 'a+b=c d+e/~_.-*!é' @U/p", "POST /p HTTP/1.1\n" + BASIC
                + "\nContent-Length: 30" + form, "a+b=c+d%2Be%2F~_.-%2A%21%C3%A9");
        files.put("g.txt", "a b\n&".getBytes(StandardCharsets.UTF_8));
        // cap.py --data-urlencode n@g.txt --data-urlencode '=a b' --data-urlencode 'a b' --data-urlencode 'x=' ...
        check("curl --data-urlencode n@g.txt --data-urlencode '=a b' --data-urlencode 'a b' --data-urlencode 'x=' @U/x",
                "POST /x HTTP/1.1\n" + BASIC + "\nContent-Length: 22" + form, "n=a+b%0A%26&a+b&a+b&x=");
        // cap.py --data-urlencode @g.txt ...
        check("curl --data-urlencode @g.txt @U/x", "POST /x HTTP/1.1\n" + BASIC + "\nContent-Length: 9" + form,
                "a+b%0A%26");
    }

    // ---- fact 8: --json headers ----

    @Test
    void jsonHeadersComeAfterUserHeaders() throws Exception {
        files.put("f", "{\"a\":1}".getBytes(StandardCharsets.UTF_8));
        // cap.py --json @f -H 'Accept: text/plain' ...
        check("curl --json @f -H 'Accept: text/plain' @U/x",
                "POST /x HTTP/1.1\nHost: HOST\nUser-Agent: curl/8.7.1\nAccept: text/plain\n"
                        + "Content-Type: application/json\nContent-Length: 7", "{\"a\":1}");
        // cap.py --json '{"a":1}' -H 'Accept: text/plain' -H 'Content-Length: 99' ...
        check("curl --json '{\"a\":1}' -H 'Accept: text/plain' -H 'Content-Length: 99' @U/x",
                "POST /x HTTP/1.1\nHost: HOST\nUser-Agent: curl/8.7.1\nAccept: text/plain\nContent-Length: 99\n"
                        + "Content-Type: application/json", "{\"a\":1}");
    }

    @Test
    void customContentHeadersWithBody() throws Exception {
        // cap.py -H 'Content-Type: text/x' -d a ... : Content-Length stays after the custom headers
        check("curl -H 'Content-Type: text/x' -d a @U/x",
                "POST /x HTTP/1.1\n" + BASIC + "\nContent-Type: text/x\nContent-Length: 1", "a");
        // cap.py -d a -H 'Content-Type:' ...
        check("curl -d a -H 'Content-Type:' @U/x", "POST /x HTTP/1.1\n" + BASIC + "\nContent-Length: 1", "a");
        // cap.py -d a -H 'Content-Length:' ...
        check("curl -d a -H 'Content-Length:' @U/x",
                "POST /x HTTP/1.1\n" + BASIC + "\nContent-Type: application/x-www-form-urlencoded", "a");
    }

    // ---- fact 9: -G ----

    @Test
    void getModeAppendsDataToQuery() throws Exception {
        // cap.py -G -d a=1 -d b=2 --data-urlencode 'c=x y/é' 'http://127.0.0.1:@P/p?z=0'
        check("curl -G -d a=1 -d b=2 --data-urlencode 'c=x y/é' '@U/p?z=0'",
                "GET /p?z=0&a=1&b=2&c=x+y%2f%c3%a9 HTTP/1.1\n" + BASIC);
        // cap.py -G -I -d a=1 ...
        check("curl -G -I -d a=1 @U/p", "HEAD /p?a=1 HTTP/1.1\n" + BASIC);
        // cap.py -G -d a=1 'http://127.0.0.1:@P/x?'
        check("curl -G -d a=1 '@U/x?'", "GET /x?a=1 HTTP/1.1\n" + BASIC);
        // cap.py -G -d a=1 'http://127.0.0.1:@P/x?q=1&'
        check("curl -G -d a=1 '@U/x?q=1&'", "GET /x?q=1&a=1 HTTP/1.1\n" + BASIC);
        // cap.py -G -d '' 'http://127.0.0.1:@P/x?q=1'
        check("curl -G -d '' '@U/x?q=1'", "GET /x?q=1& HTTP/1.1\n" + BASIC);
        // cap.py -G -d 'c=%2F%c3%A9' ... : escapes are lower-cased by curl's URL API
        check("curl -G -d 'c=%2F%c3%A9' @U/x", "GET /x?c=%2f%c3%a9 HTTP/1.1\n" + BASIC);
        // cap.py -G --data-urlencode 'a=é&b' ...
        check("curl -G --data-urlencode 'a=é&b' @U/x", "GET /x?a=%c3%a9%26b HTTP/1.1\n" + BASIC);
        // -G without data changes nothing
        check("curl -G @U/x", "GET /x HTTP/1.1\n" + BASIC);
        // cap.py -G --json '{"a":1}' ... : the JSON goes into the URL, its headers are still added
        check("curl -G --json '{\"a\":1}' @U/x",
                "GET /x?{\"a\":1} HTTP/1.1\nHost: HOST\nUser-Agent: curl/8.7.1\n"
                        + "Content-Type: application/json\nAccept: application/json");
    }

    // ---- fact 10: auth ----

    @Test
    void authorization() throws Exception {
        // cap.py --oauth2-bearer tok -u a:b ...
        check("curl --oauth2-bearer tok -u a:b @U/p",
                "GET /p HTTP/1.1\nHost: HOST\nAuthorization: Bearer tok\nUser-Agent: curl/8.7.1\nAccept: */*");
        // cap.py --basic -u a:b --oauth2-bearer t ... : neither is sent
        check("curl --basic -u a:b --oauth2-bearer t @U/x", "GET /x HTTP/1.1\n" + BASIC);
        // cap.py -u 'ü:é' ...
        check("curl -u 'ü:é' @U/x",
                "GET /x HTTP/1.1\nHost: HOST\nAuthorization: Basic w7w6w6k=\nUser-Agent: curl/8.7.1\nAccept: */*");
        // cap.py -u :p ...
        check("curl -u :p @U/x",
                "GET /x HTTP/1.1\nHost: HOST\nAuthorization: Basic OnA=\nUser-Agent: curl/8.7.1\nAccept: */*");
        // cap.py http://u%40x:p%3Aw@127.0.0.1:@P/p
        check("curl 'http://u%40x:p%3Aw@" + H + "/p'",
                "GET /p HTTP/1.1\nHost: HOST\nAuthorization: Basic dUB4OnA6dw==\nUser-Agent: curl/8.7.1\nAccept: */*");
        // cap.py http://u@127.0.0.1:@P/x : empty password
        check("curl 'http://u@" + H + "/x'",
                "GET /x HTTP/1.1\nHost: HOST\nAuthorization: Basic dTo=\nUser-Agent: curl/8.7.1\nAccept: */*");
        // cap.py http://us:pw@127.0.0.1:@P/x -u a:b : the option wins over the URL
        check("curl 'http://us:pw@" + H + "/x' -u a:b",
                "GET /x HTTP/1.1\nHost: HOST\nAuthorization: Basic YTpi\nUser-Agent: curl/8.7.1\nAccept: */*");
        // cap.py -u user -H 'x-a:1' ... : curl prompts for the password, we send an empty one and warn
        List<BuiltRequest> r = buildAll("curl -u user @U/x");
        assertTrue(new String(r.get(0).raw(), StandardCharsets.ISO_8859_1).contains("Authorization: Basic dXNlcjo=\r\n"));
        assertTrue(r.get(0).warnings().stream().anyMatch(w -> w.severity() == Warning.Severity.LOSSY));
    }

    // ---- fact 11 and 12: cookie, UA, referer, range ----

    @Test
    void cookiesRefererRange() throws Exception {
        // cap.py -b a=1 -b b=2 ... -> Cookie: a=1;b=2
        check("curl -b a=1 -b b=2 @U/x", "GET /x HTTP/1.1\n" + BASIC + "\nCookie: a=1;b=2");
        // cap.py -e ';auto' ...
        check("curl -e ';auto' @U/p", "GET /p HTTP/1.1\n" + BASIC);
        // cap.py -e '' ...
        check("curl -e '' @U/x", "GET /x HTTP/1.1\n" + BASIC);
        // cap.py -e 'r;x' ... : only ";auto" is cut
        check("curl -e 'r;x' @U/x", "GET /x HTTP/1.1\n" + BASIC + "\nReferer: r;x".replace("\nReferer", "\nReferer"));
        // cap.py -r 0-99 / -r bytes=1-2
        check("curl -r bytes=1-2 @U/x",
                "GET /x HTTP/1.1\nHost: HOST\nRange: bytes=bytes=1-2\nUser-Agent: curl/8.7.1\nAccept: */*");
    }

    // ---- fact 13: several URLs, --next ----

    @Test
    void severalUrlsAndNext() throws Exception {
        // cap.py URL1 URL2 -H 'A: 1' --next URL3
        List<BuiltRequest> r = buildAll("curl '@U/x' '@U/y' -H 'A: 1' --next '@U/z'");
        assertEquals(3, r.size());
        assertEquals(wire("GET /x HTTP/1.1\n" + BASIC + "\nA: 1", ""), new String(r.get(0).raw(), StandardCharsets.ISO_8859_1));
        assertEquals(wire("GET /y HTTP/1.1\n" + BASIC + "\nA: 1", ""), new String(r.get(1).raw(), StandardCharsets.ISO_8859_1));
        assertEquals(wire("GET /z HTTP/1.1\n" + BASIC, ""), new String(r.get(2).raw(), StandardCharsets.ISO_8859_1));
        assertEquals(wire("GET /x HTTP/1.1\n" + BASIC, ""),
                new String(buildAll("curl --url '@U/x'").get(0).raw(), StandardCharsets.ISO_8859_1));
    }

    // ---- fact 14: glob escapes ----

    @Test
    void chromeEscapedBracketsAreUnescaped() throws Exception {
        // cap.py 'http://127.0.0.1:@P/p\[1\]/\{id\}?f\[a\]=b'
        check("curl 'http://" + H + "/p\\[1\\]/\\{id\\}?f\\[a\\]=b'", "GET /p[1]/{id}?f[a]=b HTTP/1.1\n" + BASIC);
        // cap.py -g 'http://127.0.0.1:@P/p[1]/{id}?f[a]=b'
        check("curl -g 'http://" + H + "/p[1]/{id}?f[a]=b'", "GET /p[1]/{id}?f[a]=b HTTP/1.1\n" + BASIC);
        // cap.py 'http://127.0.0.1:@P/p/\a\\b' : other backslashes stay
        check("curl 'http://" + H + "/p/\\a\\\\b'", "GET /p/\\a\\\\b HTTP/1.1\n" + BASIC);
        // escaped brackets give no glob note
        assertTrue(buildAll("curl 'http://" + H + "/p\\[1-3\\]'").get(0).warnings().isEmpty());
    }

    @Test
    void unescapedGlobGetsANote() throws Exception {
        // cap.py 'http://127.0.0.1:@P/p/{a,b}' sends /p/a and /p/b; 'p/[1-2]' sends /p/1 and /p/2
        for (String u : new String[] {"/p/{a,b}", "/p/[1-2]", "/p/{id}"}) {
            List<BuiltRequest> r = buildAll("curl 'http://" + H + u + "'");
            assertEquals(1, r.size());
            assertTrue(r.get(0).warnings().stream().anyMatch(w -> w.severity() == Warning.Severity.NOTE
                    && w.message().contains("glob")), u);
        }
        assertTrue(buildAll("curl -g 'http://" + H + "/p/{a,b}'").get(0).warnings().isEmpty());
        assertTrue(buildAll("curl 'http://" + H + "/p?x=[]'").get(0).warnings().isEmpty());
    }

    // ---- files ----

    @Test
    void missingFileBecomesPlaceholderAndWarning() throws Exception {
        List<BuiltRequest> r = buildAll("curl -d @nope.txt --data-binary @nope2 @U/x");
        String body = "<<FILE: nope.txt>>&<<FILE: nope2>>";
        assertEquals(wire("POST /x HTTP/1.1\n" + BASIC + "\nContent-Length: " + body.length()
                + "\nContent-Type: application/x-www-form-urlencoded", body),
                new String(r.get(0).raw(), StandardCharsets.ISO_8859_1));
        assertEquals(2, r.get(0).warnings().stream().filter(w -> w.severity() == Warning.Severity.LOSSY).count());
        // a placeholder for --data-urlencode is not encoded
        List<BuiltRequest> u = buildAll("curl --data-urlencode n@nope @U/x");
        assertTrue(new String(u.get(0).raw(), StandardCharsets.ISO_8859_1).endsWith("n=<<FILE: nope>>"));
    }

    @Test
    void fileRefsAreListedInOrderWithoutDuplicates() throws Exception {
        ParsedCurl p = Curl.parse("curl -d @a --data-binary @b --data-urlencode x@a --json @c --data-raw @d " + U);
        assertEquals(List.of("a", "b", "c"), p.fileRefs());
        assertEquals(List.of(), Curl.parse("curl -d x " + U).fileRefs());
    }

    @Test
    void contentLengthCountsBytes() throws Exception {
        check("curl -d 'é' @U/x", "POST /x HTTP/1.1\n" + BASIC
                + "\nContent-Length: 2\nContent-Type: application/x-www-form-urlencoded", "Ã©");
    }

    @Test
    void builtRequestMetadata() throws Exception {
        BuiltRequest r = Curl.parse("curl -X PUT 'https://example.com:8443/a/b?q=1#frag'").build(fake).get(0);
        assertEquals("example.com", r.host());
        assertEquals(8443, r.port());
        assertTrue(r.secure());
        assertEquals("PUT", r.method());
        assertEquals("https://example.com:8443/a/b?q=1", r.url());
        assertFalse(new String(r.raw(), StandardCharsets.ISO_8859_1).contains("frag"));
    }
}
