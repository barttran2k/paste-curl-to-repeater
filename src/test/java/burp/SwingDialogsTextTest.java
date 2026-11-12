package burp;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertTrue;

class SwingDialogsTextTest {
    @Test
    void fileTextListsWrittenResolvedStatusAndHomeNotice() {
        String t = SwingDialogs.fileConfirmationText(
                List.of(new PasteCurlAction.FileInfo("~/a.json", "/home/u/a.json", "found, 12 bytes")), "/home/u");
        assertTrue(t.contains("As written: ~/a.json"));
        assertTrue(t.contains("Resolves to: /home/u/a.json"));
        assertTrue(t.contains("Status: found, 12 bytes"));
        assertTrue(t.contains("home directory (/home/u)"));
        assertTrue(t.contains("working directory"));
    }

    @Test
    void withoutAHomeDirectoryNoDirectoryIsNamed() {
        String t = SwingDialogs.fileConfirmationText(
                List.of(new PasteCurlAction.FileInfo("a.json", "-", "cannot be read")), null);
        assertTrue(!t.contains("home directory"));
        assertTrue(t.contains("As written: a.json"));
    }
}
