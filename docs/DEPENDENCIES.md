# Dependencies

authz is one Go module, `github.com/laiwf94/authz`, built on the standard
library first. Every module listed in `go.mod` has to be justified here: what
it is for, why the standard library is not enough, where it is confined and
when, if ever, it goes away. A change that adds a requirement without a
section in this file does not pass review.

The module targets Go 1.27.4 (`go` directive in `go.mod`), the same version
grantd, wicket and toolgate each used before the merge, so the toolchain did
not move with the tree.

## Direct requirements

| Module | Version | Used by | Since | Planned exit |
|---|---|---|---|---|
| github.com/beevik/etree | v1.8.1 | SAML (internal/authn/saml, internal/authn/fakeidp) | wicket, carried in week 1 | none planned |
| github.com/russellhaering/goxmldsig | v1.6.1 | SAML signature verification and signing (same packages) | wicket, carried in week 1 | none planned |

grantd (now the module root) and toolgate brought no third-party
requirements. The two requirements above are wicket's, at the versions
wicket pinned; wicket's third, github.com/jonboulle/clockwork, is indirect
since week 2 (below), and `go.sum` is wicket's `go.sum` unchanged.

### github.com/beevik/etree

An XML element tree with namespace-aware lookups and serialisation that
keeps attribute order and namespace declarations. SAML assertions are
signed with XML Signature over exclusive canonical XML, which has to be
computed over the document as received, including namespace prefixes that
`encoding/xml` rewrites or drops on a round trip. `encoding/xml` has no tree
model and cannot reproduce the input faithfully, so it cannot feed a
canonicaliser. etree is also the tree type goxmldsig operates on.

Confinement: imported only by the SAML packages. Documents reach it through
`parseStrict` (internal/authn/saml/xml.go), which first bounds size and
depth and rejects DTDs and entity declarations, so etree never sees an
input the strict parser has not accepted.

### github.com/russellhaering/goxmldsig

XML Signature (XML-DSig) verification and signing: exclusive C14N, the
enveloped-signature transform, digest and signature checks against a
trusted certificate set. Getting canonicalisation or reference resolution
wrong is how signature-wrapping attacks against SAML service providers
work, so authz uses a library that is widely deployed, actively maintained
and has been through public security review and advisories, instead of a
new implementation. wicket narrows it further: the accepted signature
algorithms are an allow list of RSA and ECDSA with SHA-256 or stronger,
the signed reference must name the element being trusted, and the attack
suite in internal/authn/saml covers wrapping, comment injection and
duplicated IDs.

Confinement: imported only by the SAML packages.

## Indirect and test-only modules

### github.com/jonboulle/clockwork

A fake clock, v0.5.0, now `// indirect`. goxmldsig checks certificate
validity against a `*dsig.Clock`, and its own root package
(`clock.go`) imports clockwork to build one. wicket called clockwork
directly, `dsig.NewFakeClock(clockwork.NewFakeClockAt(now))`, so that
signature checks use the same `now` as the rest of assertion validation.

Since week 2 (authn track) no authz package imports clockwork: the platform
has its own injectable clock, internal/platform/clock, and the SAML package
asks goxmldsig for a fixed clock with `dsig.NewFakeClockAt(now)`, with the
SAML suite passing unchanged as the proof that certificate lifetimes are
still checked against the assertion's `now`. The roadmap had it leaving
`go.mod` altogether that week; it cannot while authz imports goxmldsig's
root package, which is where its signature verification lives, so the
requirement stays as goxmldsig's and goes when goxmldsig drops it or the
SAML packages stop importing it. It is compiled into the binary only
through goxmldsig.

### Test-only modules

`go list -m all` also shows github.com/stretchr/testify,
github.com/davecgh/go-spew, github.com/pmezard/go-difflib,
gopkg.in/yaml.v3, github.com/kr/pretty and gopkg.in/check.v1. They are
requirements of goxmldsig's own tests and of testify. None of authz's
packages imports them and none is compiled into a binary; testify,
go-spew, go-difflib and yaml.v3 are recorded in `go.sum` only so the
module graph can be verified.

## Checking

`go mod tidy` must leave `go.mod` and `go.sum` unchanged, `go list -deps
./...` must show no module outside the table above, and govulncheck
runs over the whole module in CI.

## Tools

The gate runs two tools with `go run PKG@VERSION`, so neither is a
requirement in `go.mod` and neither is compiled into the binary:
golang.org/x/vuln/cmd/govulncheck v1.9.0 and
honnef.co/go/tools/cmd/staticcheck v0.8.2 (scripts/staticcheck.sh, which
builds it with the toolchain `go.mod` names). Both versions are pinned in
the workflow and the script.
