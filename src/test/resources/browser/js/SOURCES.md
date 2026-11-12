# Browser "Copy as cURL" generators, verbatim

Fetched 2026-11-12 from the `main` branch of each project (raw.githubusercontent.com). The files in this directory
are byte-for-byte copies (or, for the two Chrome files and the ParsedURL excerpt, exact line ranges) of the originals.
`BrowserGeneratorsNodeTest` runs them under `node` and compares them with the Java ports in
`src/test/java/burp/curl/browser/BrowserGenerators.java`.

| file here | origin | last commit touching the file | repo HEAD at fetch time |
|---|---|---|---|
| `chrome-NetworkLogView.generateCurlCommand.ts.txt` | ChromeDevTools/devtools-frontend `front_end/panels/network/NetworkLogView.ts`, lines 2586-2723 (`generateCurlCommand`, with `escapeStringWin` / `escapeStringPosix`) | `4f5cdad6571799250fac91474143ed64b9b41fc4` (2026-11-10) | `cd1f58822ea26f67df27d648821ad6ec7d3499d5` |
| `chrome-NetworkLogView.getValidClipboardUrl.ts.txt` | same file, lines 2479-2487 (`#getValidClipboardUrl`) | same | same |
| `chrome-ParsedURL.excerpt.ts.txt` | `front_end/core/common/ParsedURL.ts`, lines 41-80 (`schemeIs`, `WEB_SAFE_SCHEMES`, `parseUnwrappedURL`, `hasWebSafeScheme`) | `88f023ee633d231e47bcba17df61164b280caf3a` | same |
| `firefox-curl.js` | mozilla-firefox/firefox `devtools/client/shared/curl.js` (whole file) | `48389b47510c301293a5f7c3c4e67a41e644488f` (2026-01-13) | `2024e90df3e55391b89122d6a9d317a1026c90f8` |
| `safari-ResourceUtilities.js` | WebKit/WebKit `Source/WebInspectorUI/UserInterface/Models/ResourceUtilities.js` (whole file; `WI.ResourceUtilities.generateCURLCommand`. The old `Resource.js` only delegates to it) | `485d754b0dd5e783973cf9eb29b27e1ccaad4962` (2026-01-31) | `c7f5427ad1eb2884a0540924a51902bd8e33dfdc` |

SHA-256 of the complete original files: NetworkLogView.ts `31709512f59ff419221f3cdaa95b28cff355f824e507fca29887fd29d79ce621`,
ParsedURL.ts `e665e547d9dccba59d01fd93f22c44ec87dc165932f8f674ca917018ee0ddc04`,
curl.js `919e1f271eaa5ff95f8135e25062eb3755e4a987a9674e745869c1cb727cc287`,
ResourceUtilities.js `1e585ccacc815852caee8df807cb568da5df5058ac48ae47823785f21b556ccb`.

`harness.mjs` is ours (not an upstream file): it wraps the verbatim code with the minimum stubs (`i18nString`,
`Protocol`, `WI`, `Services`) and a request mock per browser, and evaluates cases from stdin.
Case line format (space separated tokens, `N` = null/undefined, otherwise `S` + hex of the UTF-16 code units):

    C <unix|win> method url body insecure(0/1) nHeaders (name value)*              Chrome
    F <WINNT|Linux> method url body respContentEncoded(0/1) nHeaders (name value)* Firefox
    S method url body requestDataContentType nHeaders (name value)*                Safari

Output: one line per case, `S` + hex of the UTF-16 code units of the generated text, or `E` + hex of the error text.
