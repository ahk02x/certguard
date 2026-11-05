package certguard

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"net"
	"net/url"
	"testing"
	"time"
)

var oidSAN = asn1.ObjectIdentifier{2, 5, 29, 17}

// FuzzInspect checks three properties on arbitrary input:
//
//  1. Inspect never panics (the fuzz engine reports any panic) and never hangs
//     (it must return within a deadline).
//
//  2. Inspect's verdict matches its own scanner: under DefaultLimits it returns
//     ErrTooManySANs exactly when scanSANCount reports more than MaxSANEntries.
//     Inspect returns only an error, so the count compared below comes from
//     scanSANCount, the function Inspect itself uses.
//
//  3. Whenever x509.ParseCertificate succeeds on input within the default
//     size cap, the scanner never undercounts the stdlib:
//
//     scanned >= len(DNSNames)+len(EmailAddresses)+len(IPAddresses)+len(URIs)
//
//     This is the no-bypass property. When the stdlib actually processed a
//     SAN extension (it appears in cert.Extensions), the scanned count equals
//     the number of GeneralNames in that extension, checked against an
//     independent encoding/asn1 decode.
//
// Why the four-field sum is not always EQUAL to the scanned count: there are
// two places where the scanner counts entries that never reach those fields.
//
//   - Other GeneralName types. x509 fills the four fields only from primitive
//     context tags [1] rfc822Name, [2] dNSName, [6] URI, [7] iPAddress
//     (crypto/x509/parser.go forEachSAN/parseSANExtension). otherName [0],
//     x400Address [3], directoryName [4], ediPartyName [5] and registeredID [8]
//     are accepted and dropped. certguard counts every GeneralName, because each
//     one is wire bytes the parser walks. The fuzz target checks that the sum
//     equals the count of [1]/[2]/[6]/[7] elements, and that the scanned count
//     equals the count of all elements.
//   - Extensions the stdlib skips. If the TBS version is not v3, x509 does not
//     read the [3] extensions block at all (parser.go: "if cert.Version == 3").
//     The scanner does not check the version, so it still counts those SANs.
//     That over-count is deliberate: overcounting can only make certguard
//     stricter, never let a hostile certificate through.
func FuzzInspect(f *testing.F) {
	// Seeds: the certificates the unit tests build...
	for _, n := range []int{0, 1, 3, 5, 40} {
		f.Add(makeCert(f, n))
	}
	for _, n := range []int{64, 65, 500} { // at the limit, just over, well over
		f.Add(makeEmptyURICert(f, n))
	}
	f.Add(makeMixedCert(f))
	f.Add(makeOtherNamesCert(f))
	// ...and the hand-built malformed inputs from adversarial_test.go and
	// critical_test.go.
	for _, in := range [][]byte{
		nil, {}, {0x30}, {0x30, 0x80}, {0x30, 0x84, 0xff, 0xff, 0xff, 0xff},
		{0x30, 0x03, 0x02, 0x01}, {0xa3, 0x80}, {0x1f, 0x1f, 0x1f, 0x1f},
		{0x30, 0x05, 0x30, 0x03, 0x06, 0x01, 0x55},
		{0x30, 0x80, 0x00, 0x00},
		criticalSANExtensions(),
	} {
		f.Add(in)
	}

	f.Fuzz(func(t *testing.T, der []byte) {
		// (1) No hang.
		done := make(chan error, 1)
		go func() { done <- Inspect(der, DefaultLimits) }()
		var inspectErr error
		select {
		case inspectErr = <-done:
		case <-time.After(5 * time.Second):
			t.Fatalf("Inspect did not return within 5s on a %d-byte input", len(der))
		}

		scanned, _ := scanSANCount(der)

		// (2) The verdict matches the scanner.
		if len(der) > DefaultLimits.MaxCertBytes {
			if !errors.Is(inspectErr, ErrTooLarge) {
				t.Fatalf("%d-byte input not rejected as too large: %v", len(der), inspectErr)
			}
			return // the size cap answers before any SAN counting
		}
		wantReject := scanned > DefaultLimits.MaxSANEntries
		if got := errors.Is(inspectErr, ErrTooManySANs); got != wantReject {
			t.Fatalf("scanned=%d: Inspect rejected=%v, want %v (err=%v)", scanned, got, wantReject, inspectErr)
		}
		if inspectErr != nil && !errors.Is(inspectErr, ErrTooManySANs) {
			t.Fatalf("unexpected Inspect error: %v", inspectErr)
		}

		// (3) Agreement with the stdlib.
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return
		}
		stdlib := len(cert.DNSNames) + len(cert.EmailAddresses) + len(cert.IPAddresses) + len(cert.URIs)
		if scanned < stdlib {
			t.Fatalf("BYPASS: scanner counted %d SAN entries, x509 materialized %d", scanned, stdlib)
		}

		var sanValue []byte
		for _, e := range cert.Extensions {
			if e.Id.Equal(oidSAN) {
				sanValue = e.Value
				break
			}
		}
		if sanValue == nil {
			if stdlib != 0 {
				t.Fatalf("x509 reported %d SAN entries without a SAN extension", stdlib)
			}
			return // e.g. a non-v3 certificate: the stdlib skipped the extensions, see above
		}
		// Trailing bytes after the GeneralNames SEQUENCE are ignored, because
		// x509 ignores them too: forEachSAN reads one SEQUENCE and never checks
		// that the extension value is then empty. The scanner likewise reads
		// only the first element. (Regression: testdata/fuzz/FuzzInspect/d7dc37d140ba1ba9.)
		var names []asn1.RawValue
		if _, err := asn1.Unmarshal(sanValue, &names); err != nil {
			t.Fatalf("encoding/asn1 could not decode a SAN that x509 accepted: %v", err)
		}
		if scanned != len(names) {
			t.Fatalf("scanner counted %d GeneralNames, encoding/asn1 sees %d", scanned, len(names))
		}
		materialized := 0
		for _, n := range names {
			if n.Class == asn1.ClassContextSpecific && !n.IsCompound {
				switch n.Tag {
				case 1, 2, 6, 7: // rfc822Name, dNSName, URI, iPAddress
					materialized++
				}
			}
		}
		if stdlib != materialized {
			t.Fatalf("x509 fields sum to %d, but %d GeneralNames are of type [1]/[2]/[6]/[7]", stdlib, materialized)
		}
	})
}

// TestOtherNameTypesCountedNotMaterialized pins the documented divergence:
// certguard counts every GeneralName, x509 materializes only four types.
func TestOtherNameTypesCountedNotMaterialized(t *testing.T) {
	der := makeOtherNamesCert(t)
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	sum := len(cert.DNSNames) + len(cert.EmailAddresses) + len(cert.IPAddresses) + len(cert.URIs)
	scanned, ok := scanSANCount(der)
	if !ok || scanned != 4 || sum != 1 {
		t.Fatalf("scanned=%d ok=%v x509 sum=%d; want 4, true, 1", scanned, ok, sum)
	}
}

// makeMixedCert carries all four name types x509 materializes.
func makeMixedCert(t testing.TB) []byte {
	t.Helper()
	u, _ := url.Parse("spiffe://example.org/workload")
	return signTemplate(t, &x509.Certificate{
		DNSNames:       []string{"a.example", "b.example"},
		EmailAddresses: []string{"ops@example.com"},
		IPAddresses:    []net.IP{net.ParseIP("192.0.2.1"), net.ParseIP("2001:db8::1")},
		URIs:           []*url.URL{u},
	})
}

// makeOtherNamesCert has a critical SAN extension mixing a dNSName with
// GeneralName types x509 drops: registeredID [8], directoryName [4] and
// otherName [0]. The scanner should count 4; the x509 field sum is 1.
func makeOtherNamesCert(t testing.TB) []byte {
	t.Helper()
	names := []byte{
		0x82, 0x09, 'a', '.', 'e', 'x', 'a', 'm', 'p', 'l', 'e', // [2] dNSName
		0x88, 0x02, 0x2a, 0x03, // [8] registeredID 1.2.3
		0xa4, 0x02, 0x30, 0x00, // [4] directoryName, empty Name
		0xa0, 0x0a, 0x06, 0x03, 0x2a, 0x03, 0x04, 0xa0, 0x03, 0x0c, 0x01, 'x', // [0] otherName
	}
	value := append([]byte{0x30, byte(len(names))}, names...)
	return signTemplate(t, &x509.Certificate{
		ExtraExtensions: []pkix.Extension{{Id: oidSAN, Critical: true, Value: value}},
	})
}

func signTemplate(t testing.TB, tmpl *x509.Certificate) []byte {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	tmpl.SerialNumber = big.NewInt(1)
	tmpl.Subject = pkix.Name{CommonName: "x"}
	tmpl.NotBefore = time.Now().Add(-time.Hour)
	tmpl.NotAfter = time.Now().Add(time.Hour)
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, priv.Public(), priv)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	return der
}

// criticalSANExtensions is the hand-built Extensions SEQUENCE from
// critical_test.go (a critical SAN of three empty URIs), used as a raw seed.
func criticalSANExtensions() []byte {
	names := []byte{0x30, 0x06, 0x86, 0x00, 0x86, 0x00, 0x86, 0x00}
	octet := append([]byte{0x04, byte(len(names))}, names...)
	inner := append([]byte{0x06, 0x03, 0x55, 0x1d, 0x11, 0x01, 0x01, 0xff}, octet...)
	ext := append([]byte{0x30, byte(len(inner))}, inner...)
	return append([]byte{0x30, byte(len(ext))}, ext...)
}
