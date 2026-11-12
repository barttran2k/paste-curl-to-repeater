package burp.curl;

import burp.curl.testsupport.DifferentialHarness;
import java.io.IOException;
import java.util.stream.Stream;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;

/** Core corpus: the pasted text is run by the real shell and curl, and the bytes curl sends must equal ours. */
class CurlDifferentialTest {
    @TestFactory
    Stream<DynamicTest> coreCorpus() throws IOException {
        return DifferentialHarness.tests("core");
    }
}
