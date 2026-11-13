# burp-suite-paste-curl

Burp Suite extension that turns a pasted cURL command into a request in Repeater. The request is built the way the
curl binary would send it (headers, order, body encoding, cookies, multipart, ...), not just parsed into a few fields.

Original extension by augustd. The cURL core was rewritten later; the credit for the idea and the first version
stays with the original author.

## Usage

1. Copy a cURL command (browser "Copy as cURL", API docs, a terminal, Postman, ...).
2. Right-click in a place where requests are shown (Proxy, Repeater, ...).
3. Choose Extensions -> Paste cURL -> Paste cURL command.

A new Repeater tab opens with the request, sent to the host, port and scheme named in the command.

- A command that contains several requests (several `curl` commands, or `--next`) opens one tab per request,
  named `curl 1/3`, `curl 2/3`, ... At most 20 tabs are opened per paste.
- If the command reads local files (`-d @file`, `--data-binary @file`, `-F name=@file`, `-T file`, ...), a dialog lists
  every path, the absolute path it resolves to and whether it exists. Nothing is read until you choose "Read files".
  "Use placeholders" puts `<<FILE: path>>` into the request instead. Relative paths are resolved against your home
  directory, because curl would use the shell's working directory and Burp does not know it. Files over 20 MB are refused.
  If a path is a symbolic link (or lies in a linked directory), the dialog adds a "Symbolic link to:" line with the real
  file; "Read files" reads exactly the real file that was shown and refuses a path whose target changed meanwhile.
- If the request in Repeater may differ from what curl would send, a warning dialog says why. Less important notes go
  to the extension's Output tab. The pasted command itself is never written to the log.
- A command that cannot be parsed shows the reason and, when known, the line and column in the text and a masked excerpt
  (only whitespace, quotes, backslashes, `$` and curl option names are shown; every other character is `·`), so that
  tokens and passwords in the command never appear in the dialog.
- Clipboard text over 10 MB (10 * 1024 * 1024 characters) is refused before parsing.
- A command without a User-Agent (no `-A`, no `User-Agent` header) gets a current desktop Chrome User-Agent for the
  local operating system, in Chrome's reduced format (for example `Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)
  AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0 Safari/537.36`). This intentionally differs from what curl
  would send (`curl/x.y.z`); a note in the Output tab says so and where the version came from. The Chrome major
  version is read from the installed Chrome (macOS `Info.plist`, Windows version directory under Program Files or
  LocalAppData; on Linux `google-chrome --version` or `chromium --version` is run once), otherwise it is estimated
  from the date using Chrome's release schedule. This lookup runs once, in a background thread, when the extension
  loads; a paste before it finishes uses the estimate. `-A ...` and `-H 'User-Agent: ...'` in the command always win,
  and `-A ''` / `-H 'User-Agent:'` still send no User-Agent. `Accept: */*` and everything else stay as curl sends them.

## What is supported

- bash and zsh syntax: quoting, `$'...'`, line continuations, heredocs, `NAME=value` assignments and wrappers such as
  `sudo`, `env` or `time` in front of the command, several commands. Shell expansions (`$VAR`, `$(...)`, backticks,
  and `%VAR%` in cmd) are not evaluated: they stay as literal text and a warning says so.
- Windows cmd syntax: "Copy as cURL (cmd)" from Chrome and Edge, "Copy as cURL (Windows)" from Firefox, and
  hand-written cmd commands (bare-quoted arguments follow the rules of the Microsoft C runtime, so backslashes are
  literal unless they precede a quote).
- "Copy as cURL" from Chrome, Firefox and Safari, and cURL commands exported by Postman.
- Multi-line commands.
- Several commands or `--next` groups, each becoming its own tab.
- `@file` arguments, with the confirmation described above.
- The curl options listed in `src/main/resources/curl-options.tsv` (request line, headers, cookies, data, forms, basic
  and bearer auth, `--json`, `--compressed`, `-G`, ...). Options that only affect curl itself are accepted and ignored.
- Raw bytes that are not valid UTF-8 are kept as they are in headers, cookies, the URL, form fields, credentials and
  bodies.

## How fidelity is checked

Three layers, all run by `mvn test`:

- A differential test: each of the 617 cases in a corpus of cURL commands (`src/test/resources/differential`) is run
  through the real shell and the real curl binary against a local capture server, and the bytes curl sent are compared
  with the bytes this extension builds.
- Round-trip tests: ports of the Chrome, Firefox and Safari "Copy as cURL" generators produce commands that must come
  back as the original request. The ports are validated against the original JavaScript under node.
- A seeded fuzz test: random command lines must either build well-formed requests or end in a parse error.

The differential and generator tests need `curl` and `bash` 4.2 or newer on the machine; the generator validation also
needs `node`. When a tool is missing those parts are skipped.

## Known limitations

- PowerShell syntax is not supported.
- URL globbing (`[1-5]`, `{a,b}`) is not expanded.
- Digest, NTLM, Negotiate and AWS SigV4 authentication are not computed and the warning dialog says so. With Digest
  or `--anyauth` no `Authorization` header is sent on the request, as in curl's first request; for NTLM and Negotiate
  curl's initial token is not reproduced.
- `-K` / `--config` files are not read.
- `-z <file>` (a time condition taken from a file's modification time) is not applied.
- `-F name=...;encoder=...` is rejected with a warning and the field is skipped.
- Cookie files (`-b <file>`) are evaluated at paste time, against the current time.
- A path that only appears inside the contents of another file (for example through `--variable name@file`) is never
  read; it becomes a `<<FILE: path>>` placeholder with a warning.
- IDN host names are sent as punycode (a curl built without libidn2 sends the raw UTF-8 name in `Host:`).
- For stdin uploads (`-T -`) the request carries `Transfer-Encoding: chunked` and `Expect: 100-continue`, as curl sends
  them.
- The HTTP protocol version is left to Burp (the request is written as HTTP/1.1; `--http2` and friends are not applied).
- Anything that depends on the network or on the machine (redirects, proxies, DNS overrides, TLS options, timeouts) is
  not applied by Repeater.

## Build

Requires Java 17 and Maven.

```
mvn package
```

The extension is `target/burp-suite-paste-curl-1.0-SNAPSHOT.jar` (not the `original-` one). It does not bundle the
Montoya API; Burp provides it.

`mvn package -DskipTests` builds without running the tests.

## Install

1. Build the jar (see Build).
2. In Burp: Extensions -> Installed -> Add.
3. Extension type: Java. Select the jar. Next.
4. The extension "Paste cURL" appears in the list. The menu item is under Extensions -> Paste cURL when you right-click.
