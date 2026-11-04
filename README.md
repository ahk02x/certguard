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

Strongest placement is a TLS terminator/proxy that screens the raw client
Certificate message ahead of Go's TLS stack.

## Status

Born out of a Go `crypto/x509` finding (disclosed to the Go security team,
Nov 2026). Defensive only.
