# certguard

Defensive Go library that screens a client certificate's raw DER **before** the
standard library fully parses it, rejecting abusive structures cheaply.

## Why

Go's `crypto/tls` parses a peer's certificate chain before any application
callback runs. A hostile client can send a certificate packed with thousands of
tiny SubjectAltName entries — each a couple of bytes on the wire but far more to
hold once parsed — for a large pre-authentication memory amplification. certguard
caps certificate size and SAN count with an **allocation-free DER walker** (reads
each element's tag/length and skips the body; never one heap object per entry).

## Use

```go
if err := certguard.Inspect(rawDER, certguard.DefaultLimits); err != nil {
    // reject the connection
}
```

## Where it must sit

`crypto/tls` calls `x509.ParseCertificate` on every client certificate
(`processCertsFromClient`) **before** it calls `VerifyPeerCertificate` or
`VerifyConnection`. By the time any `tls.Config` callback runs, the parse and its
allocations have already happened. Calling `Inspect`/`InspectParsed` there can
still reject the connection, log or count, but it protects nothing.
`Inspect` protects only when it sees the raw DER before something parses it.
`example_test.go` has runnable versions of each case below.

| Placement | Protects? | Catch |
|---|---|---|
| `VerifyPeerCertificate` / `VerifyConnection` callback (`Example_tls13CallbackIsTooLate`) | **No** | The parse already happened. Policy and logging only. |
| Record-layer screen under `tls.Server`, TLS 1.2 only (`Example_tls12RecordPeek`) | Yes | Example code in `example_test.go` (`certScreenConn`), not exported by certguard. Requires `MaxVersion: tls.VersionTLS12`. TLS 1.3 encrypts the client Certificate, so the screen sees nothing. Without the pin, an attacker negotiates 1.3 and walks past it. |
| TLS-terminating proxy forwards the raw cert; Go backend runs `Inspect` before parsing (`Example_terminatingProxy`) | Yes, for the Go backend | The proxy's own parser is out of reach, so set its own client-cert size limits. If the terminator is Go `crypto/tls`, it has the same problem. Trust the header only from the proxy. |

Also: don't request client certificates on listeners that don't need them.
With `ClientAuth: tls.NoClientCert`, `crypto/tls` never calls
`x509.ParseCertificate` on a client certificate in TLS 1.2 or 1.3. Both gate
certificate handling on `ClientAuth >= RequestClientCert`, so an unsolicited
Certificate message is rejected as unexpected while it is still raw bytes. If you need client certs over TLS 1.3,
`crypto/tls` has no in-process hook today that runs before the parse.

## Status

Born out of a Go `crypto/x509` finding (disclosed to the Go security team,
Nov 2026). Defensive only.
