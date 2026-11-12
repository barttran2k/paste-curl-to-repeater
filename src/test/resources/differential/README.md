# Differential corpus

Each `*.curl` file is one pasted text exactly as a user would paste it (multi-line, several commands, heredocs and
pipes allowed). `CurlDifferentialTest` (`core/`) and `CurlDifferentialExtendedTest` (`extended/`) run it twice:

1. with the real `bash` (from PATH, must be >= 4.2) and the real `curl` (from PATH), in a fresh temp directory holding
   a copy of `files/`, stdin = /dev/null, against a loopback capture server that records the raw request bytes;
2. through `Curl.parse(text).build(files)`, `files` reading relative paths from a pristine copy of `files/`.

The number of requests and every request must be byte-for-byte equal. The only normalisation is multipart boundaries
(`-{24}[A-Za-z0-9]{22}`, numbered in order of appearance) and the version of the default `User-Agent: curl/x.y.z`.

## Placeholders

`__BASE__` = `http://127.0.0.1:<port>`, `__HOSTPORT__` = `127.0.0.1:<port>`, `__PORT__` = `<port>`. The capture
server listens on 127.0.0.1 and, when available, ::1 on the same port. A corpus file must use a placeholder for every
target; other hosts may appear only with the reserved TLDs `.example`, `.invalid`, `.test` (`CorpusSanityTest`
enforces it). The runner also points every proxy variable at a dead port, so nothing can leave the machine.

## Directives

Leading lines starting with `#!` are harness directives and are not part of the pasted text:

- `#! requires-ipv6` - skip when ::1 cannot be bound.
- `#! skip-curl-version < 8.3` - skip when the installed curl is older than the given version.

## Rules

- File names are unique across `core/` and `extended/`, lowercase kebab-case.
- The case must exit 0 and send at least one request with the real curl (`CorpusSanityTest`).
- Only POSIX-shell syntax; Windows cmd is tested elsewhere. Fake credentials only.
- Never write outside the working directory. `files/` holds the fixtures (text, binary, UTF-8, cookie files, ...).
- `--opt=value`, abbreviated long options, `--http2` over plain http and `-z <file>` are not in the corpus: curl 8.7.1
  rejects the first two, `--http2` makes curl send an h2c Upgrade, and `-z <file>` needs the file's mtime.

## Fixtures with names git cannot carry everywhere

A tracked file name must not contain `\ : * ? " < > |`, end in a space or dot, or be a Windows device name
(`TrackedFileNamesTest` enforces it). Fixtures that need such names (a backslash or colon in a file name) are listed
in `special-files.tsv` instead: one `name<TAB>content` per line, `#` starts a comment, and both fields use `%XX`
escapes (`%25` for `%`, `%5C` backslash, `%3A` colon, `%09` tab, `%0A` newline). The harness writes them next to the
copy of `files/` in each fresh working directory, for the real curl and for our `FileAccess`. On a file system that
cannot create such a name the cases that mention it are skipped with an assumption that names the reason.
