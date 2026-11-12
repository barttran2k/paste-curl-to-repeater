package burp.curl;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import burp.curl.testsupport.Corpus;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * A file is read only when it was listed by {@link ParsedCurl#fileRefs()}: a path that only becomes known from the
 * contents of another file must not be read.
 */
class FileGuardTest {

    private static final class Recording implements FileAccess {
        final Map<String, String> contents;
        final List<String> reads = new ArrayList<>();

        Recording(Map<String, String> contents) {
            this.contents = contents;
        }

        @Override
        public byte[] read(String path) throws IOException {
            reads.add(path);
            String c = contents.get(path);
            if (c == null) {
                throw new NoSuchFileException(path);
            }
            return c.getBytes(StandardCharsets.UTF_8);
        }
    }

    private static String body(BuiltRequest r) {
        String raw = new String(r.raw(), StandardCharsets.ISO_8859_1);
        return raw.substring(raw.indexOf("\r\n\r\n") + 4);
    }

    @Test
    void pathFromFileContentIsNotReadAndBecomesPlaceholder() throws Exception {
        ParsedCurl p = Curl.parse("curl --variable p@/fake/a --expand-data '@{{p}}' http://example.com/");
        assertEquals(List.of("/fake/a"), p.fileRefs());
        Recording files = new Recording(Map.of("/fake/a", "/fake/secret", "/fake/secret", "TOP-SECRET"));
        List<BuiltRequest> built = p.build(files);
        assertEquals(List.of("/fake/a"), files.reads);
        assertEquals("<<FILE: /fake/secret>>", body(built.get(0)));
        assertTrue(built.get(0).warnings().stream().anyMatch(w -> w.severity() == Warning.Severity.LOSSY
                && w.message().contains("/fake/secret") && w.message().contains("contents of a file")),
                built.get(0).warnings().toString());
    }

    @Test
    void emptyPathsAreNeitherListedNorReadAndThePlaceholderSaysSo() throws Exception {
        ParsedCurl p = Curl.parse("curl -d @ -H @ -b '' -F 'a=@' http://example.com/");
        assertFalse(p.fileRefs().contains(""), p.fileRefs().toString());
        Recording files = new Recording(Map.of());
        p.build(files);
        assertEquals(List.of(), files.reads);
    }

    @Test
    void derivedPathsOfEveryKindAreNotListedNorRead() throws Exception {
        String[] options = {"--expand-data '@{{p}}'", "--expand-data-urlencode 'a@{{p}}'", "--expand-url-query '@{{p}}'",
            "--expand-form 'f=@{{p}}'", "--expand-form 'f=<{{p}}'", "--expand-header '@{{p}}'",
            "--expand-cookie '{{p}}'", "--expand-upload-file '{{p}}'", "--expand-variable 'q@{{p}}'"};
        for (String o : options) {
            ParsedCurl p = Curl.parse("curl --variable p@/fake/a " + o + " http://example.com/");
            assertEquals(List.of("/fake/a"), p.fileRefs(), o);
            Recording files = new Recording(Map.of("/fake/a", "/fake/secret", "/fake/secret", "TOP-SECRET"));
            for (BuiltRequest r : p.build(files)) {
                assertFalse(new String(r.raw(), StandardCharsets.ISO_8859_1).contains("TOP-SECRET"), o);
            }
            assertEquals(List.of("/fake/a"), files.reads, o);
        }
    }

    @Test
    void variableChainsKeepTheDerivedPathUnread() throws Exception {
        ParsedCurl p = Curl.parse("curl --variable p@/fake/a --expand-variable 'q={{p}}' --expand-data '@{{q}}' "
                + "http://example.com/");
        assertEquals(List.of("/fake/a"), p.fileRefs());
        Recording files = new Recording(Map.of("/fake/a", "/fake/secret", "/fake/secret", "TOP-SECRET"));
        BuiltRequest r = p.build(files).get(0);
        assertEquals("<<FILE: /fake/secret>>", body(r));
        assertEquals(List.of("/fake/a"), files.reads);
    }

    @Test
    void listedPathsStillWork() throws Exception {
        ParsedCurl p = Curl.parse("curl --variable p=/fake/b --expand-data '@{{p}}' http://example.com/");
        assertEquals(List.of("/fake/b"), p.fileRefs());
        Recording files = new Recording(Map.of("/fake/b", "hello"));
        assertEquals("hello", body(p.build(files).get(0)));
    }

    @Test
    void probeWarningsMatchBuildTimeRealityForExpandForm() throws Exception {
        // the file holds a valid -F argument, so curl accepts it; the probe (empty variable) must not claim otherwise
        ParsedCurl ok = Curl.parse("curl --variable p@/fake/a --expand-form '{{p}}' http://example.com/");
        assertTrue(ok.warnings().stream().noneMatch(w -> w.message().contains("-F")), ok.warnings().toString());
        List<BuiltRequest> built = ok.build(new Recording(Map.of("/fake/a", "name=value")));
        assertTrue(built.get(0).warnings().stream().noneMatch(w -> w.message().contains("-F")));
        assertTrue(body(built.get(0)).contains("name=\"name\"") && body(built.get(0)).contains("value"));

        // the file holds something curl rejects: the warning must appear, at build time
        ParsedCurl bad = Curl.parse("curl --variable p@/fake/a --expand-form '{{p}}' http://example.com/");
        List<BuiltRequest> builtBad = bad.build(new Recording(Map.of("/fake/a", "no-equals-sign")));
        assertTrue(builtBad.get(0).warnings().stream().anyMatch(w -> w.severity() == Warning.Severity.LOSSY
                && w.message().contains("-F")), builtBad.get(0).warnings().toString());
    }

    @Test
    void everyReadOfTheWholeCorpusIsListed() throws Exception {
        Path files = Corpus.filesDir();
        int cases = 0;
        for (String sub : new String[] {"core", "extended"}) {
            for (Corpus.Case c : Corpus.load(sub)) {
                ParsedCurl p;
                try {
                    p = Curl.parse(c.text(1));
                } catch (CurlParseException e) {
                    continue;
                }
                List<String> reads = new ArrayList<>();
                FileAccess rec = path -> {
                    reads.add(path);
                    return Files.readAllBytes(files.resolve(path));
                };
                List<BuiltRequest> built = p.build(rec);
                cases++;
                assertTrue(new HashSet<>(p.fileRefs()).containsAll(reads), c.name() + ": read " + reads
                        + " but fileRefs() is " + p.fileRefs());
                for (BuiltRequest r : built) {
                    for (Warning w : r.warnings()) {
                        assertFalse(w.message().contains("not shown for confirmation"), c.name() + ": " + w);
                    }
                }
            }
        }
        assertTrue(cases > 400, "cases: " + cases);
    }
}
