# AutoCAR-maintained uTLS

This repository retains the history and BSD-3-Clause license of
[refraction-networking/utls](https://github.com/refraction-networking/utls).
It is not an upstream release and is not endorsed or maintained by upstream.

## Baseline and patch scope

The initial baseline is upstream commit
`ff1b50fbbe9a6dff1dcb1cfc0493bd5b0f073f67` (2026-10-06), which includes the
upstream Go 1.27.1 TLS synchronization. The local patch queue is intentionally
limited to custom QUIC compatibility:

- Wake the blocked handshake when `UQUICConn.Close` cancels it, matching the
  standard QUIC connection's channel protocol.
- Keep explicitly supplied QUIC transport-parameter bytes in the active
  ClientHello extension after preset cloning, without sharing mutable presets.

No cipher or certificate-verification policy is weakened. These corrections do
not prove browser equivalence, passive indistinguishability, or new H3 session
resumption support. Browser profiles remain explicit consumer choices.

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
   `go test -race ./... -count=1 -timeout=5m` with Go 1.27.1 or the explicitly
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
