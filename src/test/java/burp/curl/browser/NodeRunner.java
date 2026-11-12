package burp.curl.browser;

import burp.curl.browser.BrowserGenerators.Flavor;
import burp.curl.browser.BrowserGenerators.Hdr;
import burp.curl.browser.BrowserGenerators.Req;
import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

/** Runs the verbatim browser JavaScript under node (see src/test/resources/browser/js/SOURCES.md). */
final class NodeRunner {
    private NodeRunner() {
    }

    /** @return true when a working node is on PATH */
    static boolean available() {
        try {
            Process p = new ProcessBuilder("node", "--version").redirectErrorStream(true).start();
            p.getInputStream().readAllBytes();
            return p.waitFor(20, TimeUnit.SECONDS) && p.exitValue() == 0;
        } catch (IOException | InterruptedException e) {
            return false;
        }
    }

    static String tok(String s) {
        if (s == null) {
            return "N";
        }
        StringBuilder b = new StringBuilder("S");
        for (int i = 0; i < s.length(); i++) {
            b.append(String.format("%04x", (int) s.charAt(i)));
        }
        return b.toString();
    }

    static String untok(String t) {
        StringBuilder b = new StringBuilder();
        for (int i = 1; i + 4 <= t.length(); i += 4) {
            b.append((char) Integer.parseInt(t.substring(i, i + 4), 16));
        }
        return b.toString();
    }

    static String line(Flavor f, Req r) {
        StringBuilder b = new StringBuilder();
        switch (f) {
            case CHROME_BASH, CHROME_CMD -> b.append("C ").append(f.cmd() ? "win" : "unix").append(' ')
                    .append(tok(r.method())).append(' ').append(tok(r.url())).append(' ').append(tok(r.body()))
                    .append(' ').append(r.insecure() ? 1 : 0);
            case FIREFOX_BASH, FIREFOX_CMD -> b.append("F ").append(f.cmd() ? "WINNT" : "Linux").append(' ')
                    .append(tok(r.method())).append(' ').append(tok(r.url())).append(' ').append(tok(r.body()))
                    .append(' ').append(r.respEncoded() ? 1 : 0);
            case SAFARI_BASH -> b.append("S ").append(tok(r.method())).append(' ').append(tok(r.url())).append(' ')
                    .append(tok(r.body())).append(' ').append(tok(r.safariContentType()));
            default -> throw new IllegalStateException();
        }
        b.append(' ').append(r.headers().size());
        for (Hdr h : r.headers()) {
            b.append(' ').append(tok(h.name())).append(' ').append(tok(h.value()));
        }
        return b.toString();
    }

    /**
     * @param lines case lines
     * @return one result per line: the generated text, or "ERROR:" followed by the message
     * @throws Exception on infrastructure failure
     */
    static List<String> run(List<String> lines) throws Exception {
        Path dir;
        try {
            dir = Path.of(NodeRunner.class.getResource("/browser/js/harness.mjs").toURI()).getParent();
        } catch (URISyntaxException e) {
            throw new IOException(e);
        }
        Path in = Files.createTempFile("node-cases", ".txt");
        try {
            Files.write(in, (String.join("\n", lines) + "\n").getBytes(StandardCharsets.US_ASCII));
            Process p = new ProcessBuilder("node", dir.resolve("harness.mjs").toString(), dir.toString())
                    .redirectInput(in.toFile()).redirectError(ProcessBuilder.Redirect.INHERIT).start();
            byte[] out = p.getInputStream().readAllBytes();
            if (!p.waitFor(120, TimeUnit.SECONDS) || p.exitValue() != 0) {
                throw new IOException("node harness failed with exit " + p.exitValue());
            }
            List<String> res = new ArrayList<>();
            for (String l : new String(out, StandardCharsets.US_ASCII).split("\n")) {
                if (l.isEmpty()) {
                    continue;
                }
                res.add(l.charAt(0) == 'E' ? "ERROR:" + untok(l) : untok(l));
            }
            return res;
        } finally {
            Files.deleteIfExists(in);
        }
    }
}
