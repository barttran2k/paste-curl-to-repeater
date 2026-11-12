package burp.curl;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Ground truth test: real bash splits the fragment with printf '%s\0' and we must produce identical bytes.
 * Fragments are written with stand-ins so the table stays readable: S = backslash, P = newline, T = tab
 * (the characters used are the Unicode symbols below).
 * Excluded on purpose: unquoted a&b (bash backgrounds it; the brief keeps it literal), $'\\400' (bash truncates at NUL),
 * and anything with brace/tilde/glob expansion (the brief keeps those literal).
 */
class PosixTokenizerDifferentialTest {
    private static final char BS = '§';   // section sign = backslash
    private static final char NL = '¶';   // pilcrow = line feed
    private static final char TAB = '⇥';  // = tab

    private static final String TABLE = """
            plain
            a b c
            a⇥b
            'single quoted'
            'it'"'"'s'
            'a'§''b'
            -H'x: y'
            -H"x: y"
            "double quoted"
            "a§"b§§c §$x"
            "a§b"
            "a§'b"
            "a§¶b"
            a§ b
            a§'b
            a§"b
            a§§b
            §a§b§c
            ''
            ""
            '' ""
            a''b
            a""b
            '' a ''
            ""x""
            '"'
            "'"
            '§n'
            '§'
            "§n"
            "x§"
            $'a§nb'
            $'tab§there'
            $'§a§b§e§E§f§n§r§t§v'
            $'§§ §' §" §?'
            $'it§'s'
            $'q§"q'
            $'§101§60§7§0101'
            $'§1017'
            $'§x41§x4a§x4A§x4'
            $'§xff§x41§101é'
            $'§xfe§xffZ'
            $'§u00e9§u20ac§u1F600'
            $'§U0001F600§U000000e9§U1F600'
            $'§u41§u4'
            $'§cA§ca§c[§c?'
            $'§q§z§8'
            $'§¶x'
            $'{"name":"O§'Brien","note":"l1§§nl2 -H §'x: y§'"}'
            $'a'b
            $'a''b'
            a$'b'c
            $"dq string"
            $"a§"b"
            $""
            ''$'x'""
            a$
            $ 
            "$"
            '$x'
            "§$x§$y"
            $'$x'
            5$,
            a$%b
            "a$"
            a$/b
            é
            héllo-世界
            😀
            'é😀'
            "é😀"
            a⇥⇥b
            'a⇥b'
            "multi¶line"
            'multi¶line'
            a§¶b
            a§¶  b
            "a§¶b"
            'a§¶b'
            a b§¶c d
            a    b
            x§¶§¶y
            a#b
            '#x'
            §#x
            http://h/p?a=1§&b=2
            'a&b'
            "a;b"
            a§;b
            a§|b
            a§>b
            a§<b
            '>'
            ">"
            [a]
            '*'
            "?"
            a§*b
            -d '{"a":"b c"}'
            -H 'sec-ch-ua: "Chromium";v="130", "Not?A_Brand";v="99"'
            -b 'session=abc123; csrftoken=xyz'
            --data-raw $'{"k":"v§nw"}' --compressed
            'a'"b"c§ d$'e'
            "a  b"  'c  d'
            "§§§§"
            "§§§"§"
            '§§'
            $'§§§§'
            $'§'§''
            """;

    private static String bash;
    private static String locale;
    private static Path workDir;

    @BeforeAll
    static void probe() throws Exception {
        bash = "bash";
        for (String loc : new String[] {"en_US.UTF-8", "C.UTF-8"}) {
            try {
                byte[] out = run(List.of(bash, "-c", "echo \"${BASH_VERSINFO[0]} ${BASH_VERSINFO[1]}\"; printf '%s' $'\\u00e9'"),
                        loc, null);
                String t = new String(out, StandardCharsets.UTF_8);
                String[] lines = t.split("\n", 2);
                String[] v = lines[0].trim().split(" ");
                int maj = Integer.parseInt(v[0]);
                int min = Integer.parseInt(v[1]);
                boolean newEnough = maj > 4 || (maj == 4 && min >= 2);
                if (newEnough && lines.length > 1 && lines[1].equals("é")) {
                    locale = loc;
                    break;
                }
            } catch (Exception e) {
                // try next
            }
        }
        assumeTrue(locale != null, "no bash >= 4.2 with a UTF-8 locale on PATH");
        workDir = Files.createTempDirectory("posixtok-empty");
        workDir.toFile().deleteOnExit();
    }

    private static byte[] run(List<String> cmd, String loc, Path cwd) throws Exception {
        ProcessBuilder pb = new ProcessBuilder(cmd);
        pb.environment().put("LC_ALL", loc);
        pb.environment().remove("BASH_ENV");
        if (cwd != null) pb.directory(cwd.toFile());
        pb.redirectErrorStream(false);
        pb.redirectError(ProcessBuilder.Redirect.DISCARD);
        Process p = pb.start();
        p.getOutputStream().close();
        ByteArrayOutputStream bo = new ByteArrayOutputStream();
        try (InputStream in = p.getInputStream()) {
            in.transferTo(bo);
        }
        assertTrue(p.waitFor(20, TimeUnit.SECONDS));
        return bo.toByteArray();
    }

    static String decode(String line) {
        return line.replace(BS, '\\').replace(NL, '\n').replace(TAB, '\t');
    }

    static Stream<String> fragments() {
        return Arrays.stream(TABLE.split("\n", -1)).filter(l -> !l.isEmpty()).map(PosixTokenizerDifferentialTest::decode);
    }

    @org.junit.jupiter.api.Test
    void atLeastSixtyFragments() {
        assertTrue(fragments().count() >= 60, "count=" + fragments().count());
    }

    @ParameterizedTest
    @MethodSource("fragments")
    void matchesRealBash(String fragment) throws Exception {
        Path script = Files.createTempFile("posixtok", ".sh");
        try {
            Files.write(script, ("printf '%s\\0' " + fragment + "\n").getBytes(StandardCharsets.UTF_8));
            byte[] expected = run(List.of(bash, script.toString()), locale, workDir);
            TokenizeResult r;
            try {
                r = new PosixTokenizer().tokenize(fragment);
            } catch (CurlParseException e) {
                // bash would also have failed to produce anything (syntax error), so expected output must be empty
                assertEquals(0, expected.length, "tokenizer threw but bash produced output for: " + show(fragment));
                return;
            }
            ByteArrayOutputStream actual = new ByteArrayOutputStream();
            for (CommandLine c : r.commands()) {
                for (Token t : c.argv()) {
                    actual.write(t.bytes());
                    actual.write(0);
                }
            }
            assertEquals(HexFormat.of().formatHex(expected), HexFormat.of().formatHex(actual.toByteArray()),
                    "fragment: " + show(fragment));
        } finally {
            Files.deleteIfExists(script);
        }
    }

    private static String show(String f) {
        return f.replace("\n", "<LF>").replace("\t", "<TAB>");
    }
}
