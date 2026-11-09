package certguard

import "errors"

// This file implements an allocation-free DER walker. It never decodes contents;
// it only reads each element's tag byte and length, then skips the body. That is
// what keeps screening a hostile certificate O(1) in allocations regardless of
// how many SAN entries it carries.

var errTruncated = errors.New("certguard: truncated DER")

// tlv is one DER element: its tag/class/constructed flag, and the byte slices
// for its contents and for everything after it. No heap object per element.
type tlv struct {
	class       int
	tag         int
	constructed bool
	body        []byte // contents (inside the length)
	rest        []byte // bytes after this element
}

const (
	classUniversal       = 0
	classContextSpecific = 2
	tagSequence          = 16
	tagOID               = 6
	tagBoolean           = 1
	tagOctetString       = 4
)

// readTLV parses one element header from b without allocating.
func readTLV(b []byte) (tlv, error) {
	if len(b) < 2 {
		return tlv{}, errTruncated
	}
	first := b[0]
	class := int(first >> 6)
	constructed := first&0x20 != 0
	tag := int(first & 0x1f)
	i := 1
	if tag == 0x1f { // high-tag-number form
		tag = 0
		for {
			if i >= len(b) {
				return tlv{}, errTruncated
			}
			tag = tag<<7 | int(b[i]&0x7f)
			more := b[i]&0x80 != 0
			i++
			if !more {
				break
			}
		}
	}
	if i >= len(b) {
		return tlv{}, errTruncated
	}
	ln := int(b[i])
	i++
	length := 0
	if ln&0x80 == 0 {
		length = ln // short form
	} else {
		nbytes := ln & 0x7f
		if nbytes == 0 || nbytes > 4 {
			return tlv{}, errTruncated // indefinite or absurd length
		}
		if i+nbytes > len(b) {
			return tlv{}, errTruncated
		}
		for j := 0; j < nbytes; j++ {
			length = length<<8 | int(b[i+j])
		}
		i += nbytes
	}
	// length < 0 catches a 4-byte length that overflows int on 32-bit
	// platforms; comparing against len(b)-i avoids overflow in i+length.
	if length < 0 || length > len(b)-i {
		return tlv{}, errTruncated
	}
	return tlv{
		class:       class,
		tag:         tag,
		constructed: constructed,
		body:        b[i : i+length],
		rest:        b[i+length:],
	}, nil
}

// scanSANCount walks a certificate's DER and counts top-level SAN general names,
// allocation-free. Returns (count, true) if a SAN extension was found and
// scanned, or (0, false) if there is none or the structure could not be walked
// (in which case the caller defers to the stdlib for the real error).
func scanSANCount(der []byte) (int, bool) {
	cert, err := readTLV(der) // Certificate SEQUENCE
	if err != nil || !cert.constructed {
		return 0, false
	}
	tbs, err := readTLV(cert.body) // tbsCertificate SEQUENCE
	if err != nil || !tbs.constructed {
		return 0, false
	}
	// Walk TBS fields for the [3] EXPLICIT extensions wrapper.
	rest := tbs.body
	for len(rest) > 0 {
		f, err := readTLV(rest)
		if err != nil {
			return 0, false
		}
		if f.class == classContextSpecific && f.tag == 3 {
			return scanExtensionsForSAN(f.body)
		}
		rest = f.rest
	}
	return 0, false
}

func scanExtensionsForSAN(b []byte) (int, bool) {
	seq, err := readTLV(b) // Extensions SEQUENCE OF
	if err != nil || !seq.constructed {
		return 0, false
	}
	rest := seq.body
	for len(rest) > 0 {
		ext, err := readTLV(rest) // Extension SEQUENCE
		if err != nil {
			return 0, false
		}
		rest = ext.rest
		// extnID OID is the first element.
		idTLV, err := readTLV(ext.body)
		if err != nil || idTLV.tag != tagOID {
			continue
		}
		if !oidBytesEqualSAN(idTLV.body) {
			continue
		}
		// Next is optional critical BOOLEAN, then extnValue OCTET STRING.
		after := idTLV.rest
		next, err := readTLV(after)
		if err != nil {
			return 0, false
		}
		if next.tag == tagBoolean && next.class == classUniversal {
			next, err = readTLV(next.rest)
			if err != nil {
				return 0, false
			}
		}
		if next.tag != tagOctetString {
			return 0, false
		}
		// Inside the OCTET STRING: GeneralNames SEQUENCE.
		names, err := readTLV(next.body)
		if err != nil || !names.constructed {
			return 0, false
		}
		return countTLVElements(names.body)
	}
	return 0, false
}

// subjectAltName OID 2.5.29.17 DER-encoded content bytes: 55 1d 11
var sanOIDBytes = []byte{0x55, 0x1d, 0x11}

func oidBytesEqualSAN(b []byte) bool {
	if len(b) != len(sanOIDBytes) {
		return false
	}
	for i := range b {
		if b[i] != sanOIDBytes[i] {
			return false
		}
	}
	return true
}

// countTLVElements counts elements by walking headers only, with no allocation.
func countTLVElements(b []byte) (int, bool) {
	count := 0
	rest := b
	for len(rest) > 0 {
		v, err := readTLV(rest)
		if err != nil {
			return count, false
		}
		count++
		rest = v.rest
	}
	return count, true
}
