// Package certguard hardens TLS servers against malicious client certificates.
//
// The Go standard library parses a peer's certificate chain before any
// application callback (VerifyPeerCertificate / VerifyConnection) runs. A
// hostile client can exploit that: a certificate packed with thousands of tiny
// SubjectAltName entries costs ~2 bytes each on the wire but far more to hold in
// memory once parsed, giving a large pre-authentication amplification. See the
// Go class of "parsing allocates too much" DoS fixes.
//
// certguard screens the raw DER *before* full parsing, using golang.org/x/crypto
// style lightweight scanning via encoding/asn1 only where cheap, and rejects
// certificates whose structure is abusive. It is defensive only: it inspects a
// certificate you already received and decides whether to keep going.
package certguard

import (
	"crypto/x509"
	"errors"
	"fmt"
)

// Limits bounds how much structure a client certificate may contain before it
// is rejected. Zero values mean "use the default".
type Limits struct {
	// MaxCertBytes rejects a single certificate larger than this many bytes of
	// DER. The stdlib caps a whole TLS handshake message at 256 KiB; a single
	// legitimate leaf certificate is almost always well under 16 KiB.
	MaxCertBytes int
	// MaxSANEntries rejects a certificate whose SubjectAltName extension holds
	// more than this many general names. Real certificates carry a handful.
	MaxSANEntries int
}

// DefaultLimits are conservative values safe for almost all real deployments.
var DefaultLimits = Limits{
	MaxCertBytes:  16 * 1024,
	MaxSANEntries: 64,
}

func (l Limits) withDefaults() Limits {
	if l.MaxCertBytes <= 0 {
		l.MaxCertBytes = DefaultLimits.MaxCertBytes
	}
	if l.MaxSANEntries <= 0 {
		l.MaxSANEntries = DefaultLimits.MaxSANEntries
	}
	return l
}

var (
	// ErrTooLarge means the certificate DER exceeded Limits.MaxCertBytes.
	ErrTooLarge = errors.New("certguard: certificate too large")
	// ErrTooManySANs means the SubjectAltName extension held too many entries.
	ErrTooManySANs = errors.New("certguard: too many SubjectAltName entries")
)

// Inspect screens one raw DER certificate cheaply. It returns nil if the
// certificate is within limits, or a sentinel error (ErrTooLarge /
// ErrTooManySANs) if it is abusive. It never fully materializes the SAN entries,
// so a hostile certificate costs O(number of entries) counting, not O(entries)
// heap objects.
func Inspect(der []byte, limits Limits) error {
	l := limits.withDefaults()
	if len(der) > l.MaxCertBytes {
		return fmt.Errorf("%w: %d bytes > %d", ErrTooLarge, len(der), l.MaxCertBytes)
	}
	n, _ := scanSANCount(der)
	// Check the count even when the walk did not finish cleanly: a SAN list of
	// N well-formed names followed by one malformed element still makes the
	// stdlib allocate N entries before it fails, so a partial count is real.
	if n > l.MaxSANEntries {
		return fmt.Errorf("%w: %d > %d", ErrTooManySANs, n, l.MaxSANEntries)
	}
	// Otherwise a certificate we cannot scan structurally is not our problem to
	// diagnose; let the stdlib produce the real parse error downstream.
	return nil
}

// InspectParsed re-screens an already-parsed certificate against limits. The
// stdlib has already paid the parse cost by this point, so this is for logging,
// metrics, and enforcing a policy inside a VerifyPeerCertificate callback — not
// for saving the allocation. For true pre-parse protection, apply Inspect to the
// raw client Certificate message at a proxy/terminator ahead of Go's TLS stack.
func InspectParsed(cert *x509.Certificate, limits Limits) error {
	return Inspect(cert.Raw, limits)
}
