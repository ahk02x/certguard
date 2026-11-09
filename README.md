# certguard

certguard is a small Go library that checks a TLS client certificate before
Go's parser reads it. If the certificate is too big or lists too many names,
certguard says no.

I wrote it after finding a memory bug in Go's certificate parser:
[golang/go#82858](https://github.com/golang/go/issues/82858).

It only protects a server if it runs before Go parses the certificate. Some
setups allow that and some don't, including TLS 1.3 servers that need client
certificates. [Where it must sit](#where-it-must-sit) says which.

## Why

A certificate lists the names it's valid for, called SubjectAltNames (SANs).
Go's `x509.ParseCertificate` builds an object for every one of them, and
there's no limit on how many a certificate can have. An empty URI name is only
2 bytes in the certificate, but each one becomes its own object in memory.

A 260 KB certificate with 130,000 empty URI names makes Go allocate about
24 MB and keep about 20 MB. That's around 76 times the size of the certificate.

This matters for servers that ask for client certificates. Go's `crypto/tls`
parses the client's certificate before any of your checks run, so the server
pays that cost even for a client it's about to reject. In my test it was about
27 MB per handshake.

I reported it to the Go security team first. They said it isn't a security
issue, so I filed it as a regular bug.

## Install

```
go get github.com/ahk02x/certguard
```

## Use

```go
if err := certguard.Inspect(rawDER, certguard.DefaultLimits); err != nil {
	// reject the connection
}
```

`rawDER` is the certificate's raw bytes, before anything has parsed them.
`Inspect` returns an error that matches `certguard.ErrTooLarge` or
`certguard.ErrTooManySANs` (check with `errors.Is`) when a certificate breaks a
limit, and nil when it doesn't.

The defaults are 16 KB per certificate and 64 names. Real client certificates
have a handful. To use your own limits:

```go
err := certguard.Inspect(rawDER, certguard.Limits{
	MaxCertBytes:  32 * 1024,
	MaxSANEntries: 128,
})
```

A field left at zero uses the default.

The check can't have the same problem as the parser, so it doesn't build
anything per name. It walks the certificate down to the list of names, reads
each entry's type and length, counts it, and skips over the rest. On the same
260 KB certificate, even with the size limit lifted so it has to count all
130,000 names, it says no in 3 allocations and about 100 bytes.

If a certificate is broken partway through, certguard still checks the names
it counted before the broken part. If it can't make sense of the certificate at
all, it returns nil and leaves the real error to Go's parser.

## Where it must sit

This is the part that matters most. certguard only protects a server if it
sees the certificate **before** Go parses it.

- **In `VerifyPeerCertificate` or `VerifyConnection`: too late.** Go has
  already parsed the certificate when these run. You can still reject, log or
  count there with `InspectParsed`, but the memory is already spent
  (`Example_tls13CallbackIsTooLate`).
- **In front of `tls.Server`, TLS 1.2 only: works.** In TLS 1.2 the client
  sends its certificate unencrypted, so you can check the raw bytes as they
  arrive (`Example_tls12RecordPeek`). That code is an example in
  `example_test.go`, not part of the library. You have to set
  `MaxVersion: tls.VersionTLS12`. TLS 1.3 encrypts the certificate, so without
  that setting a client just picks 1.3 and skips the check.
- **Behind a proxy that handles TLS: works for the Go service.** The proxy
  passes the raw certificate along, and the Go service runs `Inspect` before
  parsing it (`Example_terminatingProxy`). Only trust that value when it comes
  from the proxy. Give the proxy its own size limits too. If the proxy is
  written in Go, it has the same problem.
- **TLS 1.3 servers that need client certificates: not covered.** Go has no
  hook today that runs before the parse.

The simplest fix is not asking for a certificate you don't need. With
`ClientAuth: tls.NoClientCert`, Go never parses a client certificate in TLS 1.2
or 1.3. If a client sends one anyway, Go rejects it while it's still raw bytes.

## Tests

```
go test ./...
go test -run '^$' -fuzz=FuzzInspect -fuzztime=60s
```

The tests feed it bad input on purpose: garbage bytes, structures that never
say how long they are, nested structures, a SAN extension marked critical, and
long runs of empty names. They check that it doesn't crash, hang or undercount. The fuzz test
checks that certguard never counts fewer names than Go's own parser keeps.

## Status

It works and has tests. The Go issue is open. certguard is defensive only: it
looks at a certificate you already received and decides whether to keep going.

## License

BSD 3-Clause, the same license Go uses. See [LICENSE](LICENSE).
