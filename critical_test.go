package certguard

import "testing"

// A SAN extension may carry an optional critical=TRUE BOOLEAN before the OCTET
// STRING. scanExtensionsForSAN must skip it and still find the names. We build
// the extension bytes by hand: SEQUENCE { OID 2.5.29.17, BOOLEAN TRUE, OCTET
// STRING { SEQUENCE OF { [6] len0 x3 } } }.
func TestCriticalBooleanSkipped(t *testing.T) {
	names := []byte{0x30, 0x06, 0x86, 0x00, 0x86, 0x00, 0x86, 0x00} // SEQ of 3 empty URIs
	octet := append([]byte{0x04, byte(len(names))}, names...)
	oid := []byte{0x06, 0x03, 0x55, 0x1d, 0x11}
	boolTrue := []byte{0x01, 0x01, 0xff}
	extInner := append(append(append([]byte{}, oid...), boolTrue...), octet...)
	ext := append([]byte{0x30, byte(len(extInner))}, extInner...)
	extsSeq := append([]byte{0x30, byte(len(ext))}, ext...)
	n, ok := scanExtensionsForSAN(extsSeq)
	if !ok {
		t.Fatal("scanExtensionsForSAN failed to parse critical-marked SAN")
	}
	if n != 3 {
		t.Fatalf("counted %d names, want 3 (critical BOOLEAN likely not skipped)", n)
	}
}
