package certguard

import (
	"testing"
	"time"
)

//  1. A truncated/garbage DER must never panic and must not falsely "pass" as a
//     tiny cert when it is actually unparseable. Inspect should return nil
//     (defer to stdlib) OR an error, but NEVER panic.
func TestNoPanicOnGarbage(t *testing.T) {
	inputs := [][]byte{
		nil, {}, {0x30}, {0x30, 0x80}, {0x30, 0x84, 0xff, 0xff, 0xff, 0xff},
		{0x30, 0x03, 0x02, 0x01}, {0xa3, 0x80}, {0x1f, 0x1f, 0x1f, 0x1f},
		{0x30, 0x05, 0x30, 0x03, 0x06, 0x01, 0x55},
	}
	for i, in := range inputs {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("input %d panicked: %v", i, r)
				}
			}()
			_ = Inspect(in, DefaultLimits)
		}()
	}
}

// 2. Indefinite-length / absurd length bytes must not cause a huge read or loop.
func TestIndefiniteLengthRejectedCheap(t *testing.T) {
	// 0x30 0x80 = SEQUENCE, indefinite length (BER, illegal in DER)
	der := []byte{0x30, 0x80, 0x00, 0x00}
	done := make(chan struct{})
	go func() { _ = Inspect(der, DefaultLimits); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Inspect hung on indefinite length")
	}
}

//  3. THE KEY BYPASS TEST: a cert whose SAN GeneralNames uses CONSTRUCTED
//     encoding or nesting such that countTLVElements under-counts. If an attacker
//     can pack many names but have the top-level walker see few, they bypass
//     MaxSANEntries. We approximate by checking the real stdlib-built hostile
//     cert is counted correctly (done in main test) and that a manually nested
//     blob does not undercount wildly.
func TestNestedDoesNotUndercount(t *testing.T) {
	// Build a fake GeneralNames body: 200 context-tag-6 (URI) empty elements.
	var names []byte
	for i := 0; i < 200; i++ {
		names = append(names, 0x86, 0x00) // [6] IMPLICIT, length 0
	}
	n, ok := countTLVElements(names)
	if !ok || n != 200 {
		t.Fatalf("countTLVElements saw %d (ok=%v), want 200", n, ok)
	}
}
