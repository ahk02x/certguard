package certguard

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/url"
	"testing"
	"time"
)

func makeCert(t testing.TB, nSANs int) []byte {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	uris := make([]*url.URL, nSANs)
	for i := range uris {
		uris[i] = &url.URL{Scheme: "https", Host: "example.com"}
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "x"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		URIs:         uris,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, priv.Public(), priv)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	return der
}

func makeEmptyURICert(t testing.TB, nSANs int) []byte {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	uris := make([]*url.URL, nSANs)
	for i := range uris {
		uris[i] = &url.URL{} // the hostile shape: empty URI, 2 bytes on the wire
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "x"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		URIs:         uris,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, priv.Public(), priv)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	return der
}

func TestNormalCertPasses(t *testing.T) {
	der := makeCert(t, 3)
	if err := Inspect(der, DefaultLimits); err != nil {
		t.Fatalf("normal cert rejected: %v", err)
	}
}

func TestCountMatchesReality(t *testing.T) {
	for _, n := range []int{1, 5, 40} { // n=0 has no SAN extension at all; covered separately
		der := makeCert(t, n)
		got, ok := scanSANCount(der)
		if !ok {
			t.Fatalf("n=%d scan failed", n)
		}
		if got != n {
			t.Errorf("n=%d: counted %d SAN entries, want %d", n, got, n)
		}
	}
}

func TestHostileCertRejectedBySANCount(t *testing.T) {
	der := makeEmptyURICert(t, 5000)
	err := Inspect(der, Limits{MaxCertBytes: 1 << 20, MaxSANEntries: 64})
	if err == nil {
		t.Fatal("hostile cert with 5000 SANs was not rejected")
	}
	t.Logf("rejected as expected: %v", err)
}

func TestHostileCertRejectedBySize(t *testing.T) {
	der := makeEmptyURICert(t, 50000)
	err := Inspect(der, DefaultLimits) // 16 KiB default size cap
	if err == nil {
		t.Fatal("oversize hostile cert was not rejected")
	}
	t.Logf("rejected as expected: %v", err)
}

// TestInspectIsCheap proves the screen does NOT build one object per SAN entry:
// inspecting a cert with 100k empty URIs allocates a tiny, bounded amount,
// unlike x509.ParseCertificate which retains ~144 bytes per entry.
func TestInspectIsCheap(t *testing.T) {
	der := makeEmptyURICert(t, 100000)
	allocs := testing.AllocsPerRun(5, func() {
		_ = Inspect(der, Limits{MaxCertBytes: 1 << 20, MaxSANEntries: 64})
	})
	t.Logf("Inspect on 100k-SAN cert: %.0f allocs/op", allocs)
	if allocs > 100 {
		t.Errorf("Inspect allocated %.0f objects; expected a small bounded number", allocs)
	}
}
