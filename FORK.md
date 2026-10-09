# AutoCAR-maintained uTLS

This repository retains the history and BSD-3-Clause license of
[refraction-networking/utls](https://github.com/refraction-networking/utls).
It is not an upstream release and is not endorsed or maintained by upstream.

## Baseline and patch scope

The initial baseline is upstream commit
`ff1b50fbbe9a6dff1dcb1cfc0493bd5b0f073f67` (2026-10-06), which includes the
upstream Go 1.27.1 TLS synchronization. The local patch queue is intentionally
limited to custom QUIC compatibility and reviewed Go TLS security backports:

- Wake the blocked handshake when `UQUICConn.Close` cancels it, matching the
  standard QUIC connection's channel protocol.
- Keep explicitly supplied QUIC transport-parameter bytes in the active
  ClientHello extension after preset cloning, without sharing mutable presets.
- Validate ECH outer-extension references using the exact Go 1.27.2 fix
  described below; retain its deterministic regression tests.
- Propagate cancellation while a QUIC client is paused on a session-resume
  event, and run custom ClientHello construction errors through the common
  handshake cleanup. Forward a terminal `QUICErrorEvent` exactly once, using
  the standard QUIC connection's event protocol. These changes prevent
  `Start`, event draining, or `Close` from stranding handshake goroutines.

No cipher or certificate-verification policy is weakened. These corrections do
not prove browser equivalence, passive indistinguishability, or new H3 session
resumption support. Browser profiles remain explicit consumer choices.

### Go 1.27.2 ECH security backport (2026-10-09)

The production change in `ech.go` is copied from Go release commit
[`f022e61963529d5e691f0e42a87fd5b520f01636`](https://github.com/golang/go/commit/f022e61963529d5e691f0e42a87fd5b520f01636),
`crypto/tls: validate ECH outer extension references`, fixing
[GO-2026-6607](https://pkg.go.dev/vuln/GO-2026-6607) /
CVE-2026-97031. It is present in the exact
[`go1.27.2` release comparison](https://github.com/golang/go/compare/go1.27.1...go1.27.2),
whose tag points to `022c8636110ebac86a9b88724cda168ed713c21f`.
This is a targeted security backport, not a new TLS subtree synchronization;
the existing upstream ancestry and Go copyright/license headers are retained.

The imported `TestDecodeInnerClientHelloOuterExtensions` regression covers
valid ordered references, duplicate references, forbidden ECH references,
multiple reference-list extensions, odd-length lists, and empty lists. Fork
cases additionally cover no references, single or subset references,
out-of-order or absent references, and trailing list bytes, and assert the
reconstructed fields on valid inputs. These tests decode bounded in-memory
messages and do not contact external systems. The patch changes the shared
inner-ClientHello decoder used for server ECH input and for local ECH client
transcript reconstruction (`UConn.echTranscriptMsg`); it does not change client
browser templates or transport parameters.

As of this review, AutoCAR uses this fork only for client handshakes; its H2/H3
servers use `crypto/tls`, and its fixed browser profiles use GREASE ECH rather
than configured real ECH. The external-input vulnerability affects server ECH
processing, so the current consumer configuration limits reachability; this
is not a reason to leave the shared decoder unpatched. An upstream
module advisory query returning no records does not cover vulnerabilities
published only against the Go standard library. Upgrading the Go toolchain
does not update the TLS source copied into this repository.

CI and validation use Go 1.27.2. The `go.mod` language/API minimum remains
Go 1.27 because this backport introduces no newer API; consumers must still
build with a supported, security-patched Go toolchain and resolve their other
dependencies separately. This narrow backport preserves the upstream module
dependency baseline; AutoCAR separately selects `golang.org/x/net` v0.60.0
through Go's minimum-version selection for the contemporaneous HTTP/2 fixes.

## Module identity

The module remains `github.com/refraction-networking/utls` so transitive QUIC
consumers share its types. Consumers use an explicit remote replacement to
`github.com/cppla/utls` at a verified, published commit pseudo-version. Never
release with a local-directory replacement, floating branch, or both module
paths imported as separate libraries. The consuming repository owns its exact
version and checksum pin.

## Updating and validating

1. Fetch upstream and review its commits, security notices, and Go TLS changes.
   Preserve upstream ancestry; follow `CONTRIBUTORS_GUIDE.md` for any Go TLS
   subtree synchronization. Do not reset the maintained branch over local fixes.
2. Re-evaluate each local patch against the new baseline; remove a patch only
   when an upstream equivalent and its regression tests are verified.
3. Run `go build ./...`, `go test ./... -count=1 -timeout=5m`, and
   `go test -race ./... -count=1 -timeout=5m` with Go 1.27.2 or the explicitly
   reviewed successor. Require Linux, macOS, and Windows CI, plus consumer
   H2/H3 wire, resumption, shutdown, authentication, and cancellation tests.
4. Publish through a reviewed PR in **this fork**. Consumers update to the final
   merged commit only after checksum resolution and their own regression gates.
   Do not silently track upstream HEAD or reinterpret a named browser profile.

`govulncheck` can query a replacement's fork path instead of the upstream module
path. A clean fork scan is therefore insufficient: separately query and review
advisories for `github.com/refraction-networking/utls` at the baseline and for
the Go TLS/toolchain, and retain the dated applicability decision. Security
updates must be actively reviewed; this fork is not an automatic security-sync
service. The original upstream `SECURITY.md` remains upstream reporting guidance;
for vulnerabilities introduced by this fork or affecting AutoCAR, use
[AutoCAR private vulnerability reporting](https://github.com/cppla/autocar/security/advisories/new),
not a public PR containing exploit details.
