package burp.curl.browser;

import burp.curl.browser.BrowserGenerators.Flavor;
import burp.curl.browser.BrowserGenerators.Gen;
import burp.curl.browser.BrowserGenerators.Req;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Regenerates src/test/resources/browser/fixtures from {@link FixtureRequests}: the clipboard texts come from the
 * node-validated generator ports, the .expected.http files from the real bash + curl against a loopback capture
 * server (the cmd flavours reuse the bash flavour's bytes after proving the two mean the same thing).
 *
 * <p>Run after {@code mvn -q test-compile}:
 * {@code java -cp target/classes:target/test-classes burp.curl.browser.FixtureGenerator src/test/resources/browser/fixtures}
 */
final class FixtureGenerator {
    private FixtureGenerator() {
    }

    /**
     * @param args the fixtures directory
     * @throws Exception on failure
     */
    public static void main(String[] args) throws Exception {
        if (!RealCurlBatch.available()) {
            throw new IllegalStateException("needs curl, bash >= 4.2 and a UTF-8 locale");
        }
        generate(Path.of(args[0]));
    }

    static String ext(Flavor f) {
        return f.cmd() ? "cmd" : "sh";
    }

    static String dir(Flavor f) {
        return switch (f) {
            case CHROME_BASH -> "chrome-bash";
            case CHROME_CMD -> "chrome-cmd";
            case FIREFOX_BASH -> "firefox-bash";
            case FIREFOX_CMD -> "firefox-cmd";
            case SAFARI_BASH -> "safari-bash";
        };
    }

    static Flavor[] flavors(String browser) {
        return switch (browser) {
            case "chrome" -> new Flavor[] {Flavor.CHROME_BASH, Flavor.CHROME_CMD};
            case "firefox" -> new Flavor[] {Flavor.FIREFOX_BASH, Flavor.FIREFOX_CMD};
            default -> new Flavor[] {Flavor.SAFARI_BASH};
        };
    }

    static Req withHost(Req r, String hostPort) {
        return r.withUrl(r.url().replace(FixtureRequests.HP, hostPort));
    }

    static void generate(Path root) throws Exception {
        for (Map.Entry<String, List<FixtureRequests.Fx>> e : FixtureRequests.all().entrySet()) {
            Flavor bash = flavors(e.getKey())[0];
            List<FixtureRequests.Fx> reqs = e.getValue();
            for (Flavor f : flavors(e.getKey())) {
                // the real curl runs the browser's bash text; for a cmd flavour that is lossy for the request (multipart
                // bodies lose their CR) it runs the bash text of exactly what the cmd text means
                List<Boolean> same = new ArrayList<>();
                for (FixtureRequests.Fx fx : reqs) {
                    same.add(!f.cmd() || Expectation.sameMeaning(bash, f, bash.gen(fx.req()), f.gen(fx.req())));
                }
                RealCurlBatch.Outcome o = RealCurlBatch.run(port -> {
                    List<String> cmds = new ArrayList<>();
                    for (int i = 0; i < reqs.size(); i++) {
                        Req r = reqs.get(i).req();
                        String text = same.get(i) ? bash.gen(r).text() : Expectation.bashOfCmdMeaning(f, f.gen(r));
                        cmds.add(text.replace(FixtureRequests.HP, "127.0.0.1:" + port));
                    }
                    return cmds;
                });
                for (int i = 0; i < reqs.size(); i++) {
                    FixtureRequests.Fx fx = reqs.get(i);
                    byte[] raw = o.requests().get(i);
                    if (raw == null) {
                        throw new IllegalStateException("real curl sent no request for " + fx.name() + "\n" + o.diagnostics());
                    }
                    String wire = new String(raw, StandardCharsets.ISO_8859_1)
                            .replace("127.0.0.1:" + o.ports().get(i), FixtureRequests.HP);
                    String name = String.format("%02d-%s", i + 1, fx.name());
                    Gen g = f.gen(fx.req());
                    Path d = Files.createDirectories(root.resolve(dir(f)));
                    Files.writeString(d.resolve(name + "." + ext(f)), g.text(), StandardCharsets.UTF_8);
                    Files.write(d.resolve(name + ".expected.http"), wire.getBytes(StandardCharsets.ISO_8859_1));
                }
            }
        }
    }
}
