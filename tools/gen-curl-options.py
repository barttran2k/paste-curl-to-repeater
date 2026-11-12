#!/usr/bin/env python3
"""Regenerate src/main/resources/curl-options.tsv.

Usage:
  python3 tools/gen-curl-options.py <tool_getparam.c> <curl-help-all.txt> [outdir]

Inputs : curl master src/tool_getparam.c (aliases[] table) and the output of
         `curl --help all`.
Outputs: <repo>/src/main/resources/curl-options.tsv
         <repo>/src/test/resources/curl-master-options.txt
Handling groups (A/B/C/D) are assigned from the lists below (see the plan,
section "Toan bo option cua curl").  Unlisted options abort the run so a new
curl option must be classified consciously.
"""
import os
import re
import sys

A = """url url-query request-target path-as-is proto-default globoff disallow-username-in-url
request head get upload-file header user-agent referer cookie range time-cond compressed tr-encoding
user basic oauth2-bearer data data-ascii data-raw data-binary data-urlencode json form form-string
form-escape crlf http1.0 http1.1 http2 http2-prior-knowledge http3 http3-only next variable""".split()

B = """digest ntlm ntlm-wb negotiate anyauth aws-sigv4 delegation service-name login-options netrc
netrc-file netrc-optional httpsig-algo httpsig-headers httpsig-key httpsig-keyid config continue-at
etag-compare haproxy-protocol haproxy-clientip upload-flags resolve connect-to proxy unix-socket
abstract-unix-socket cert key""".split()

C = """preproxy proxy1.0 proxy-user proxy-header proxytunnel noproxy proxy-anyauth proxy-basic proxy-digest
proxy-negotiate proxy-ntlm proxy-http2 proxy-http3 proxy-insecure proxy-cacert proxy-capath
proxy-ca-native proxy-cert proxy-cert-type proxy-ciphers proxy-crlfile proxy-key proxy-key-type
proxy-pass proxy-pinnedpubkey proxy-service-name proxy-ssl-allow-beast proxy-ssl-auto-client-cert
proxy-tls13-ciphers proxy-tlsauthtype proxy-tlspassword proxy-tlsuser proxy-tlsv1 socks4 socks4a
socks5 socks5-hostname socks5-basic socks5-gssapi socks5-gssapi-nec socks5-gssapi-service
suppress-connect-headers
dns-interface dns-ipv4-addr dns-ipv6-addr dns-servers doh-url doh-insecure doh-cert-status interface
local-port ipv4 ipv6 happy-eyeballs-timeout-ms tcp-fastopen tcp-nodelay mptcp keepalive
keepalive-time keepalive-cnt ip-tos vlan-priority alt-svc hsts ipfs-gateway
insecure cacert capath ca-native cert-type cert-status key-type pass ciphers tls13-ciphers curves
sigalgs crlfile pinnedpubkey engine egd-file random-file ech false-start alpn npn sessionid ssl
ssl-reqd ssl-allow-beast ssl-auto-client-cert ssl-no-revoke ssl-revoke-best-effort ssl-sessions
tls-earlydata tls-max tlsv1 tlsv1.0 tlsv1.1 tlsv1.2 tlsv1.3 sslv2 sslv3 tlsauthtype tlsuser
tlspassword dump-ca-embed proto proto-redir
output remote-name remote-name-all remote-header-name output-dir create-dirs create-file-mode
clobber skip-existing out-null remote-time remove-on-error xattr dump-header cookie-jar
junk-session-cookies etag-save include show-headers silent show-error verbose trace trace-ascii
trace-config trace-ids trace-time stderr write-out progress-bar progress-meter styled-output buffer
libcurl fail fail-early fail-with-body help manual version metalink disable
connect-timeout max-time expect100-timeout retry retry-delay retry-max-time retry-all-errors
retry-connrefused limit-rate rate speed-limit speed-time max-filesize parallel parallel-immediate
parallel-max parallel-max-host
location follow location-trusted max-redirs post301 post302 post303 raw ignore-content-length
http0.9 append use-ascii test-duphandle test-event wdebug""".split()

D = """ftp-account ftp-alternative-to-user ftp-create-dirs ftp-method ftp-pasv ftp-port ftp-pret
ftp-skip-pasv-ip ftp-ssl ftp-ssl-ccc ftp-ssl-ccc-mode ftp-ssl-control ftp-ssl-reqd disable-eprt
disable-epsv eprt epsv list-only quote krb krb4
mail-auth mail-from mail-rcpt mail-rcpt-allowfails sasl-authzid sasl-ir pubkey hostpubmd5
hostpubsha256 knownhosts compressed-ssh tftp-blksize tftp-no-options telnet-option""".split()

# Decisions for options the hand-written spec list does not name.  Each entry
# is reported to the integrator.  Keep this table small and justified.
EXTRA = {
    # fill from the generator run
}

KIND = {"ARG_NONE": "NONE", "ARG_BOOL": "BOOL", "ARG_STRG": "STRING", "ARG_FILE": "FILE",
        "ARG_SECS": "NUM", "ARG_UNUM": "NUM"}


def parse_master(path):
    s = open(path, encoding="utf-8").read()
    a = s[s.index("aliases[] = {"):]
    a = a[:a.index("\n};")]
    out = []
    for name, flags, short, _cmd in re.findall(
            r"\{\"([^\"]+)\",\s*([A-Za-z_|]+),\s*'(.)',\s*(C_\w+)\}", a):
        toks = flags.split("|")
        types = [t for t in toks if t in KIND]
        if len(types) != 1:
            sys.exit("unknown type flag in %s: %s" % (name, flags))
        out.append((name, "" if short == " " else short, KIND[types[0]],
                    KIND[types[0]] == "BOOL" or "ARG_NO" in toks))
    n = a.count('{"')
    if n != len(out):
        sys.exit("regex missed entries: %d vs %d" % (len(out), n))
    return out


def parse_help(path):
    res = []
    for line in open(path, encoding="utf-8").read().split("\n")[1:]:
        m = re.match(r"^ (?:-(\S), |    )--(\S+)( [<\[])?", line)
        if m:
            res.append((m.group(2), m.group(1) or "", bool(m.group(3))))
        elif line.strip():
            sys.exit("unparsed help line: " + line)
    return res


def main():
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    root = sys.argv[3] if len(sys.argv) > 3 else os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
    master = parse_master(sys.argv[1])
    names = {m[0] for m in master}
    rows = list(master)
    extras = []
    for name, short, takes in parse_help(sys.argv[2]):
        if name in names:
            continue
        if name.startswith("no-") and name[3:] in {m[0] for m in master if m[3]}:
            continue
        if name.startswith("no-"):
            base = name[3:]
            if base not in names:
                rows.append((base, short, "BOOL", True))
                names.add(base)
                extras.append(base)
            continue
        kind = "STRING" if takes else "NONE"
        rows.append((name, short, kind, False))
        names.add(name)
        extras.append(name)
    groups = {}
    for g, lst in (("A", A), ("B", B), ("C", C), ("D", D), ("X", list(EXTRA))):
        for n in lst:
            if n in groups and g != "X":
                sys.exit("listed twice: %s (%s, %s)" % (n, groups[n], g))
            groups[n] = EXTRA[n] if g == "X" else g
    # compressed-ssh, ftp-pasv etc. appear once; resolve overlaps above by hand
    missing = sorted(n for n in names if n not in groups)
    if missing:
        sys.exit("unclassified options: " + " ".join(missing))
    unused = sorted(n for n in groups if n not in names)
    if unused:
        print("note: listed but not in table:", " ".join(unused), file=sys.stderr)
    rows.sort(key=lambda r: r[0])
    with open(os.path.join(root, "src/main/resources/curl-options.tsv"), "w", encoding="utf-8", newline="\n") as f:
        f.write("#long\tshort\tkind\tnegatable\thandling\n")
        for n, s, k, neg in rows:
            f.write("%s\t%s\t%s\t%d\t%s\n" % (n, s, k, 1 if neg else 0, groups[n]))
    with open(os.path.join(root, "src/test/resources/curl-master-options.txt"), "w", encoding="utf-8", newline="\n") as f:
        for m in master:
            f.write(m[0] + "\n")
    print("master=%d help-only extras=%d (%s) total=%d" % (len(master), len(extras), " ".join(extras), len(rows)))
    print("EXTRA decisions:", {n: groups[n] for n in EXTRA})


main()
