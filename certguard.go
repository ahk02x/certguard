// Package certguard checks a TLS client certificate before Go's parser reads
// it, and says no if the certificate is too big or lists too many names.
//
// Go's crypto/tls parses a client's certificate before VerifyPeerCertificate
// or VerifyConnection runs. x509.ParseCertificate builds an object for every
// SubjectAltName entry, with no limit on how many there are. An empty URI name
// is 2 bytes in the certificate, but a 260 KB certificate with 130,000 of them
// makes the parser allocate about 24 MB. See
// https://github.com/golang/go/issues/82858.
//
// Inspect reads only each element's type and length and skips over the rest,
// so it doesn't allocate per name. It only protects a server when it runs
// before anything parses the certificate. The README and the examples show
// where that's possible. It is defensive only: it looks at a certificate you
// already received and decides whether to keep going.
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

// Inspect checks one raw DER certificate against limits. It returns nil if the
// certificate is within limits, or an error matching ErrTooLarge or
// ErrTooManySANs (check with errors.Is) if it isn't. It counts SAN entries
// without building them, so its memory use stays small however many entries a
// certificate has.
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

// InspectParsed checks a certificate that has already been parsed. Go has
// already spent the memory by then, so this is for logging, metrics, or
// rejecting the connection inside a VerifyPeerCertificate callback. It doesn't
// save the memory. To do that, run Inspect on the raw certificate before
// anything parses it, for example behind a proxy that handles TLS.
func InspectParsed(cert *x509.Certificate, limits Limits) error {
	return Inspect(cert.Raw, limits)
}
