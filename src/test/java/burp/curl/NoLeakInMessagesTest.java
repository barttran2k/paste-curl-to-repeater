package burp.curl;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * Warnings and exception messages are logged and shown: they may name options, shell variable names, local paths and
 * the --resolve/--connect-to argument, but never an argument value, header, credential, user name, URL, host, body or
 * the text of a command substitution. Every command below carries a unique marker in a different kind of position.
 */
class NoLeakInMessagesTest {
    private static final String M = "s3cr3tM4rk";

    private static final String[] COMMANDS = {
        // -F / --form-string
        "curl -F '@@' http://h.test/",
        "curl -F 'a=b;type=@@' http://h.test/",
        "curl -F 'a=b;type=text/@@;encoder=@@' http://h.test/",
        "curl -F 'a=b;encoder=@@' http://h.test/",
        "curl --form-string '@@' http://h.test/",
        "curl -F 'a=@@@;type=@@' http://h.test/",
        "curl -F 'a=@nofile.txt;headers=@@@-hdr' http://h.test/",
        // credentials
        "curl -u @@ http://h.test/",
        "curl -u @@:@@ http://h.test/",
        "curl --digest -u @@:@@ http://h.test/",
        "curl --ntlm --user @@:@@ http://h.test/",
        "curl --anyauth -u @@:@@ http://h.test/",
        "curl --oauth2-bearer @@ --digest http://h.test/",
        "curl http://@@:@@@h.test/ --digest",
        "curl --basic --digest --oauth2-bearer @@ http://h.test/",
        // dates, headers, simple options
        "curl -z @@ http://h.test/",
        "curl -z 'not a date @@' http://h.test/",
        "curl -H '@@: @@' http://h.test/",
        "curl -H '@@;' -H '@@:' http://h.test/",
        "curl -X @@ http://h.test/",
        "curl -A @@ -e @@ -r @@ http://h.test/",
        "curl -b '@@=@@' http://h.test/",
        "curl --request-target @@ http://h.test/",
        "curl --proto-default @@ @@.test/x",
        "curl -w '@@' -o /dev/null http://h.test/",
        "curl --cacert /x/ca.pem --capath /x/capath http://h.test/",
        // options that only warn
        "curl --unknown-opt-x http://h.test/",
        "curl --unknown-opt-x=@@ http://h.test/",
        "curl -@@ http://h.test/",
        "curl --proxy http://@@:@@@p.test:1 http://h.test/",
        "curl -x @@ --socks5 @@ --preproxy @@ http://h.test/",
        "curl --cert @@:@@ --key @@ http://h.test/",
        "curl --aws-sigv4 aws:amz:@@:@@ http://h.test/",
        "curl --netrc-file /x/netrc -K /x/cfg http://h.test/",
        "curl --unix-socket /tmp/sock http://h.test/",
        "curl --http2 --http3 http://@@.test/",
        // data
        "curl -d '@@' --data-urlencode '@@=@@' --json '{\"@@\":1}' --url-query '@@=@@' http://h.test/",
        "curl -d @/nonexistent/path http://h.test/",
        "curl -d @- http://h.test/",
        "curl -T /nonexistent/up http://h.test/",
        // variables
        "curl --variable '@@' http://h.test/",
        "curl --variable '=@@' http://h.test/",
        "curl --variable '@@ @@' http://h.test/",
        "curl --variable 'v=@@' --expand-data '{{v:bad@@}}' http://h.test/",
        "curl --variable 'v=@@' --expand-data '{{ @@ }}' http://h.test/",
        "curl --variable 'v=@@' --expand-data '{{@@' --expand-url 'http://h.test/{{!@@}}' http://h.test/",
        "curl --variable '%SOME_ENV' --variable '%V=@@' --expand-data '{{@@}}{{V}}' http://h.test/",
        "curl --variable 'v@/nonexistent/path' --expand-data '{{v}}' http://h.test/",
        "curl --variable 'v@/fake/a' --expand-form '{{v}}' --expand-header '{{v}}@@' http://h.test/",
        "curl --variable 'v@/fake/a' --expand-data '@{{v}}' http://h.test/",
        "curl --expand-form '@@' http://h.test/",
        // shell constructs
        "curl \"$(echo @@)\" http://h.test/",
        "curl `echo @@` http://h.test/",
        "curl http://h.test/ -H \"X: $(echo @@)\" -d \"$((1+@@))\" -d \"${TOKEN:-@@}\"",
        "curl http://h.test/ -H \"X: $TOKEN\" -d \"${TOKEN}\" -d \"$TOKEN;$(echo @@)\"",
        "curl http://h.test/ <(echo @@)",
        "curl http://h.test/ -d @- <<'EOF'\n$(echo @@) `echo @@` ${TOKEN:-@@} $TOKEN\nEOF",
        "curl http://h.test/ -d @- <<@@\nbody\n",
        "curl http://h.test/ -d @- <<@@\nbody\n@@\n",
        "curl http://h.test/ -d '@@",
        "curl http://h.test/ -d \"@@",
        "curl http://h.test/ -d $'@@",
        "curl http://h.test/ -d \"$(echo @@",
        "curl http://h.test/ -d ‘@@",
        "echo @@",
        "curl http://h.test/ -d @@ @@",
        // URLs
        "curl @@://h.test/",
        "curl http://h.test:@@/",
        "curl 'http://h @@.test/'",
        "curl 'http://[@@]/'",
        "curl 'http://@@:@@ @h.test/'",
        "curl http://h.test/ ; curl ftp://@@.test/ ; curl 'http://%@@/'",
        "curl ftp://@@.test/f",
        "curl http://h.test/ --next gopher://@@.test/ -d @@",
        "curl http://h.test/ --url-query '+@@\u0001'",
        "curl http://h.test/ -d '@@\u0001' -G",
        "curl -@@ http://h.test/ -d",
        "curl --@@",
        "curl -d",
        // cmd dialect
        "curl.exe -d \"@@\" ^\n  --unknown-x ^\n  -H \"X: @@\" ^\n  http://h.test/ %USERPROFILE%",
        "curl.exe -F \"@@\" ^\n  -u \"@@:@@\" --digest ^\n  http://h.test/",
        "curl.exe -d \"@@ ^\n  http://h.test/",
        "curl.exe ^\"http://h.test/^\" -F ^\"@@^\" -z ^\"@@^\"",
    };

    private static final String[] FAKE_FILES = {"/fake/a"};

    private static void check(String where, String message, List<String> problems) {
        if (message != null && message.contains(M)) {
            problems.add(where + ": " + message);
        }
    }

    @Test
    void noMarkerReachesAWarningOrAnExceptionMessage() {
        List<String> problems = new ArrayList<>();
        int built = 0;
        int failed = 0;
        for (String template : COMMANDS) {
            String cmd = template.replace("@@", M);
            List<FileAccess> accesses = List.of(FileAccess.DENY, path -> {
                if (path.equals(FAKE_FILES[0])) {
                    return "no-equals-sign".getBytes(java.nio.charset.StandardCharsets.UTF_8);
                }
                throw new IOException("denied");
            });
            ParsedCurl p;
            try {
                p = Curl.parse(cmd);
            } catch (CurlParseException e) {
                failed++;
                check("parse exception of [" + cmd + "]", e.getMessage(), problems);
                continue;
            }
            for (Warning w : p.warnings()) {
                check("parse warning of [" + cmd + "]", w.message(), problems);
            }
            for (FileAccess files : accesses) {
                try {
                    for (BuiltRequest r : p.build(files)) {
                        built++;
                        for (Warning w : r.warnings()) {
                            check("build warning of [" + cmd + "]", w.message(), problems);
                        }
                    }
                } catch (CurlParseException e) {
                    failed++;
                    check("build exception of [" + cmd + "]", e.getMessage(), problems);
                }
            }
        }
        if (!problems.isEmpty()) {
            fail(problems.size() + " leaks:\n" + String.join("\n", problems));
        }
        assertTrue(built > 50 && failed > 10, "built " + built + ", failed " + failed);
    }

    @Test
    void messagesStayUsefulForTheCommonCases() throws Exception {
        List<Warning> w = Curl.parse("curl -F nothing http://h.test/").warnings();
        assertTrue(w.stream().anyMatch(x -> x.message().contains("-F") && x.message().contains("name=content")),
                w.toString());
        w = Curl.parse("curl -u bob http://h.test/").build(FileAccess.DENY).get(0).warnings();
        assertTrue(w.stream().anyMatch(x -> x.message().contains("-u") && x.message().contains("password")),
                w.toString());
        w = Curl.parse("curl -z garbage http://h.test/").build(FileAccess.DENY).get(0).warnings();
        assertTrue(w.stream().anyMatch(x -> x.message().contains("-z") && x.message().contains("date")), w.toString());
        w = Curl.parse("curl http://h.test/ -H \"X: $TOKEN\"").warnings();
        assertTrue(w.stream().anyMatch(x -> x.message().contains("$TOKEN")), w.toString());
        w = Curl.parse("curl http://h.test/ -H \"X: $(cat /etc/secret)\"").warnings();
        assertTrue(w.stream().anyMatch(x -> x.message().contains("command substitution")), w.toString());
        assertTrue(w.stream().noneMatch(x -> x.message().contains("/etc/secret")), w.toString());
        w = Curl.parse("curl.exe -d x ^\n http://h.test/ %USERPROFILE%").warnings();
        assertTrue(w.stream().anyMatch(x -> x.message().contains("%USERPROFILE%")), w.toString());
        w = Curl.parse("curl --resolve h.test:80:127.0.0.1 http://h.test/").warnings();
        assertTrue(w.stream().anyMatch(x -> x.message().contains("h.test:80:127.0.0.1")), w.toString());
    }
}
