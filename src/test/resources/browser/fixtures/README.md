# Browser clipboard fixtures

One file per clipboard text, grouped by flavour: `chrome-bash/`, `chrome-cmd/`, `firefox-bash/`, `firefox-cmd/`,
`safari-bash/` (`.sh` = bash flavour, `.cmd` = Windows cmd flavour). Every text has a sibling `<name>.expected.http`:
the raw request (CRLF, exact bytes) that the REAL curl 8.7.1 sent when bash ran the bash flavour of the same logical
request against a loopback capture server. The cmd flavour reuses the bash flavour's bytes when both mean the same bytes
(`BrowserVsRealCurlTest.sameMeaning`). Where the cmd generator itself loses information (a multipart body written with
CRLF reaches cmd as LF only), the real curl runs the bash text of exactly what the cmd text means, and the cmd fixture
is compared with that.

The texts are produced by the Java ports of the browsers' generators (`BrowserGenerators`, validated byte for byte
against the real JavaScript by `BrowserGeneratorsNodeTest`) from the logical requests in `FixtureRequests`.
Credentials, cookies and tokens are fake. `__HOSTPORT__` stands for the capture server's `127.0.0.1:<port>` in both
the text and the expected bytes; `BrowserFixturesTest` substitutes an arbitrary loopback port. Multipart boundaries and
the version of the default `User-Agent: curl/x.y.z` are normalised when comparing (as in the differential harness).

Regenerate (needs curl, bash >= 4.2, a UTF-8 locale):
`mvn -q test -Dtest=BrowserFixturesTest#regenerateWhenAsked -Dbrowser.fixtures.regenerate=true`
