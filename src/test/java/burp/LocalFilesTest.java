package burp;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

class LocalFilesTest {
    @TempDir
    Path home;
    @TempDir
    Path other;

    @Test
    void tildeExpandsToHome() throws IOException {
        Files.writeString(home.resolve("a.txt"), "hi");
        assertEquals("hi", new String(new LocalFiles(home).read("~/a.txt"), StandardCharsets.UTF_8));
        assertEquals(home.toAbsolutePath().normalize(), new LocalFiles(home).resolve("~"));
    }

    @Test
    void relativeResolvesAgainstHome() throws IOException {
        Files.createDirectories(home.resolve("sub"));
        Files.writeString(home.resolve("sub/b.txt"), "rel");
        assertEquals("rel", new String(new LocalFiles(home).read("sub/b.txt"), StandardCharsets.UTF_8));
    }

    @Test
    void absoluteIsUsedAsIs() throws IOException {
        Path f = other.resolve("abs.txt");
        Files.writeString(f, "abs");
        assertEquals("abs", new String(new LocalFiles(home).read(f.toString()), StandardCharsets.UTF_8));
    }

    @Test
    void missingFileFails() {
        assertThrows(IOException.class, () -> new LocalFiles(home).read("nope.txt"));
    }

    @Test
    void directoryFails() throws IOException {
        Files.createDirectories(home.resolve("d"));
        assertThrows(IOException.class, () -> new LocalFiles(home).read("d"));
    }

    @Test
    void dashIsNeverAFile() throws IOException {
        Files.writeString(home.resolve("-"), "x");
        assertThrows(IOException.class, () -> new LocalFiles(home).read("-"));
        assertTrue(new LocalFiles(home).describe("-").status().startsWith("cannot be read"));
    }

    @Test
    void sizeCap() throws IOException {
        Path big = home.resolve("big.bin");
        try (RandomAccessFile f = new RandomAccessFile(big.toFile(), "rw")) {
            f.setLength(LocalFiles.MAX_BYTES + 1);
        }
        assertThrows(IOException.class, () -> new LocalFiles(home).read("big.bin"));
        assertTrue(new LocalFiles(home).describe("big.bin").status().startsWith("too large"));
        try (RandomAccessFile f = new RandomAccessFile(big.toFile(), "rw")) {
            f.setLength(LocalFiles.MAX_BYTES);
        }
        assertEquals(LocalFiles.MAX_BYTES, new LocalFiles(home).read("big.bin").length);
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
}
