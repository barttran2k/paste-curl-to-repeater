package burp.curl;

import burp.curl.testsupport.DifferentialHarness;
import java.io.IOException;
import java.util.stream.Stream;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;

/** Extended corpus: forms, uploads, variables and other wave-3 features. */
@Disabled("extended semantics are implemented in wave 3")
class CurlDifferentialExtendedTest {
    @TestFactory
    Stream<DynamicTest> extendedCorpus() throws IOException {
        return DifferentialHarness.tests("extended");
    }
}
