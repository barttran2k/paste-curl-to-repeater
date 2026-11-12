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
- If the request in Repeater may differ from what curl would send, a warning dialog says why. Less important notes go
  to the extension's Output tab. The pasted command itself is never written to the log.
- A command that cannot be parsed shows the reason and, when known, the place in the text.

## What is supported

- bash and zsh syntax: quoting, `$'...'`, line continuations, heredocs, `$VAR` assignments in front of the command,
  several commands.
- Windows cmd syntax, as produced by "Copy as cURL (cmd)" in Chrome and Edge.
- "Copy as cURL" from Chrome, Firefox and Safari, and cURL commands exported by Postman.
- Multi-line commands.
- Several commands or `--next` groups, each becoming its own tab.
- `@file` arguments, with the confirmation described above.
- The curl options listed in `src/main/resources/curl-options.tsv` (request line, headers, cookies, data, forms, basic
  and bearer auth, `--json`, `--compressed`, `-G`, ...). Options that only affect curl itself are accepted and ignored.

## How fidelity is checked

The test suite contains a differential test: each case in a corpus of cURL commands is run through the real shell and
the real curl binary against a local capture server, and the bytes curl sent are compared with the bytes this
extension builds. The tests need `curl` and `bash` on the machine and run as part of `mvn test`.

## Known limitations

- PowerShell syntax is not supported.
- URL globbing (`[1-5]`, `{a,b}`) is not expanded.
- Digest, NTLM, Negotiate and AWS SigV4 authentication are not computed; the request is built without the
  computed credentials and the warning dialog says so.
- `-K` / `--config` files are not read.
- Raw non-UTF-8 bytes inside header values are not preserved; they are preserved in bodies.
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

1. Build the jar, or download a release.
2. In Burp: Extensions -> Installed -> Add.
3. Extension type: Java. Select the jar. Next.
4. The extension "Paste cURL" appears in the list. The menu item is under Extensions -> Paste cURL when you right-click.
