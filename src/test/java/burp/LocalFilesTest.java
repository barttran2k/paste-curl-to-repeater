package burp;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import static org.junit.jupiter.api.Assertions.*;

class LocalFilesTest {
    /** describe (what the dialog does), then read (what "Read files" does) */
    static byte[] shownThenRead(LocalFiles lf, String path) throws IOException {
        lf.describe(path);
        return lf.read(path);
    }

    @TempDir
    Path home;
    @TempDir
    Path other;

    @Test
    void tildeExpandsToHome() throws IOException {
        Files.writeString(home.resolve("a.txt"), "hi");
        assertEquals("hi", new String(shownThenRead(new LocalFiles(home), "~/a.txt"), StandardCharsets.UTF_8));
        assertEquals(home.toAbsolutePath().normalize(), new LocalFiles(home).resolve("~"));
    }

    @Test
    void relativeResolvesAgainstHome() throws IOException {
        Files.createDirectories(home.resolve("sub"));
        Files.writeString(home.resolve("sub/b.txt"), "rel");
        assertEquals("rel", new String(shownThenRead(new LocalFiles(home), "sub/b.txt"), StandardCharsets.UTF_8));
    }

    @Test
    void absoluteIsUsedAsIs() throws IOException {
        Path f = other.resolve("abs.txt");
        Files.writeString(f, "abs");
        assertEquals("abs", new String(shownThenRead(new LocalFiles(home), f.toString()), StandardCharsets.UTF_8));
    }

    @Test
    void missingFileFails() {
        assertThrows(IOException.class, () -> shownThenRead(new LocalFiles(home), "nope.txt"));
    }

    @Test
    void directoryFails() throws IOException {
        Files.createDirectories(home.resolve("d"));
        assertThrows(IOException.class, () -> shownThenRead(new LocalFiles(home), "d"));
    }

    @Test
    void dashIsNeverAFile() throws IOException {
        Files.writeString(home.resolve("-"), "x");
        assertThrows(IOException.class, () -> shownThenRead(new LocalFiles(home), "-"));
        assertTrue(new LocalFiles(home).describe("-").status().startsWith("cannot be read"));
    }

    @Test
    void sizeCap() throws IOException {
        Path big = home.resolve("big.bin");
        try (RandomAccessFile f = new RandomAccessFile(big.toFile(), "rw")) {
            f.setLength(LocalFiles.MAX_BYTES + 1);
        }
        assertThrows(IOException.class, () -> shownThenRead(new LocalFiles(home), "big.bin"));
        assertTrue(new LocalFiles(home).describe("big.bin").status().startsWith("too large"));
        try (RandomAccessFile f = new RandomAccessFile(big.toFile(), "rw")) {
            f.setLength(LocalFiles.MAX_BYTES);
        }
        assertEquals(LocalFiles.MAX_BYTES, shownThenRead(new LocalFiles(home), "big.bin").length);
    }

    @Test
    void describeReportsStatusWithoutReading() throws IOException {
        Files.writeString(home.resolve("a.txt"), "12345");
        LocalFiles lf = new LocalFiles(home);
        PasteCurlAction.FileInfo i = lf.describe("a.txt");
        assertEquals("a.txt", i.written());
        assertEquals(home.toAbsolutePath().normalize().resolve("a.txt").toString(), i.resolved());
        assertEquals("found, 5 bytes", i.status());
        assertEquals("not found", lf.describe("zzz").status());
        Files.createDirectories(home.resolve("d"));
        assertEquals("is a directory", lf.describe("d").status());
    }

    @Test
    void homeDirectoryIsTheOneUsedToResolve() throws Exception {
        LocalFiles f = new LocalFiles(java.nio.file.Paths.get("/some/home"));
        assertEquals(f.home().toString(), f.homeDirectory());
        assertEquals(f.home().resolve("a.txt"), f.resolve("a.txt"));
    }

    // ---- symbolic links ----

    private static void link(Path link, Path target) throws IOException {
        try {
            Files.createSymbolicLink(link, target);
        } catch (UnsupportedOperationException | IOException | SecurityException e) {
            org.junit.jupiter.api.Assumptions.assumeTrue(false, "file system cannot create symbolic links: " + e);
        }
    }

    @Test
    void neverDescribedPathIsRefused() throws IOException {
        Files.writeString(home.resolve("a.txt"), "x");
        IOException e = assertThrows(IOException.class, () -> new LocalFiles(home).read("a.txt"));
        assertTrue(e.getMessage().contains("not shown"), e.getMessage());
    }

    @Test
    void symlinkedFileIsShownWithItsRealTargetAndReadFromIt() throws IOException {
        Path secret = other.resolve("id_rsa");
        Files.writeString(secret, "PRIVATE");
        link(home.resolve("body.json"), secret);
        LocalFiles lf = new LocalFiles(home);
        PasteCurlAction.FileInfo i = lf.describe("~/body.json");
        assertEquals(secret.toRealPath().toString(), i.symlinkTarget());
        assertEquals(home.resolve("body.json").toString(), i.resolved());
        assertEquals("found, 7 bytes", i.status());
        assertEquals("PRIVATE", new String(lf.read("~/body.json"), StandardCharsets.UTF_8));
        String text = SwingDialogs.fileConfirmationText(java.util.List.of(i), lf.homeDirectory());
        assertTrue(text.contains("\nSymbolic link to: " + secret.toRealPath() + "\n"), text);
    }

    @Test
    void symlinkedParentDirectoryIsShownWithItsRealTarget() throws IOException {
        Files.createDirectories(other.resolve("realdir"));
        Files.writeString(other.resolve("realdir/f.txt"), "in dir");
        link(home.resolve("dl"), other.resolve("realdir"));
        LocalFiles lf = new LocalFiles(home);
        PasteCurlAction.FileInfo i = lf.describe("dl/f.txt");
        assertEquals(other.resolve("realdir/f.txt").toRealPath().toString(), i.symlinkTarget());
        assertEquals("in dir", new String(lf.read("dl/f.txt"), StandardCharsets.UTF_8));
    }

    @Test
    void relativeSymlinkIsResolved() throws IOException {
        Files.createDirectories(home.resolve("a/b"));
        Files.writeString(home.resolve("a/real.txt"), "rel");
        link(home.resolve("a/b/l.txt"), Paths.get("..", "real.txt"));
        LocalFiles lf = new LocalFiles(home);
        PasteCurlAction.FileInfo i = lf.describe("a/b/l.txt");
        assertEquals(home.resolve("a/real.txt").toRealPath().toString(), i.symlinkTarget());
        assertEquals("rel", new String(lf.read("a/b/l.txt"), StandardCharsets.UTF_8));
    }

    @Test
    void plainFileHasNoSymlinkLine() throws IOException {
        Files.writeString(home.resolve("p.txt"), "p");
        PasteCurlAction.FileInfo i = new LocalFiles(home.toRealPath()).describe("p.txt");
        assertNull(i.symlinkTarget());
        assertFalse(SwingDialogs.fileConfirmationText(java.util.List.of(i), null).contains("Symbolic link"));
    }

    @Test
    void danglingSymlinkIsNotFoundAndNotRead() throws IOException {
        link(home.resolve("dangling"), other.resolve("missing"));
        LocalFiles lf = new LocalFiles(home);
        assertTrue(lf.describe("dangling").status().startsWith("not found"));
        assertThrows(IOException.class, () -> lf.read("dangling"));
    }

    @Test
    void symlinkLoopIsRefused() throws IOException {
        link(home.resolve("l1"), home.resolve("l2"));
        link(home.resolve("l2"), home.resolve("l1"));
        LocalFiles lf = new LocalFiles(home);
        assertTrue(lf.describe("l1").status().startsWith("not found"));
        assertThrows(IOException.class, () -> lf.read("l1"));
    }

    @Test
    void symlinkSwappedBetweenDescribeAndReadIsRefused() throws IOException {
        Files.writeString(home.resolve("safe.txt"), "safe");
        Path secret = other.resolve("id_rsa");
        Files.writeString(secret, "PRIVATE");
        Path l = home.resolve("body.json");
        link(l, home.resolve("safe.txt"));
        LocalFiles lf = new LocalFiles(home);
        lf.describe("body.json");
        Files.delete(l);
        link(l, secret);
        IOException e = assertThrows(IOException.class, () -> lf.read("body.json"));
        assertTrue(e.getMessage().contains("changed"), e.getMessage());
    }

    @Test
    void regularFileReplacedBySymlinkAfterDescribeIsRefused() throws IOException {
        Path f = home.resolve("body.json");
        Files.writeString(f, "plain");
        Path secret = other.resolve("id_rsa");
        Files.writeString(secret, "PRIVATE");
        LocalFiles lf = new LocalFiles(home);
        lf.describe("body.json");
        Files.delete(f);
        link(f, secret);
        assertThrows(IOException.class, () -> lf.read("body.json"));
    }

    @Test
    void aFileThatVanishedOrWasDescribedAsMissingIsNotRead() throws IOException {
        Files.writeString(home.resolve("a.txt"), "a");
        LocalFiles lf = new LocalFiles(home);
        lf.describe("a.txt");
        Files.delete(home.resolve("a.txt"));
        assertThrows(IOException.class, () -> lf.read("a.txt"));
        Files.writeString(home.resolve("a.txt"), "a");
        assertEquals("not found", describeMissing(lf));
    }

    private static String describeMissing(LocalFiles lf) throws IOException {
        // a path described as missing never becomes readable, even if the file appears later
        PasteCurlAction.FileInfo i = lf.describe("zzz.txt");
        Files.writeString(lf.home().resolve("zzz.txt"), "late");
        assertThrows(IOException.class, () -> lf.read("zzz.txt"));
        return i.status();
    }
}
