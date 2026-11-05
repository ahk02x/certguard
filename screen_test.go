package certguard_test

import (
	"bytes"
	"errors"
	"io"
	"net"
	"testing"

	"github.com/ahk02x/certguard"
)

// fakeConn serves a fixed byte stream as the client side of a connection.
type fakeConn struct {
	net.Conn
	r io.Reader
}

func (f *fakeConn) Read(p []byte) (int, error) { return f.r.Read(p) }
func (f *fakeConn) Close() error               { return nil }

// tls12Stream encodes a Certificate message for ders, followed in the same
// handshake stream by a stand-in ClientKeyExchange. It fragments the stream
// into handshake records of at most frag bytes, so messages both span
// records and share them.
func tls12Stream(frag int, ders ...[]byte) []byte {
	u24 := func(n int) []byte { return []byte{byte(n >> 16), byte(n >> 8), byte(n)} }
	var list []byte
	for _, d := range ders {
		list = append(append(list, u24(len(d))...), d...)
	}
	body := append(u24(len(list)), list...)
	hs := append(append([]byte{11}, u24(len(body))...), body...)
	hs = append(hs, 16, 0, 0, 2, 0xaa, 0xbb) // ClientKeyExchange stand-in
	var out []byte
	for len(hs) > 0 {
		n := min(frag, len(hs))
		out = append(out, 22, 3, 3, byte(n>>8), byte(n))
		out = append(out, hs[:n]...)
		hs = hs[n:]
	}
	return out
}

func TestCertScreenReassembly(t *testing.T) {
	benign, _ := newCert(3, false)
	hostile, _ := newCert(5000, true)

	for _, frag := range []int{1, 7, 100, 16384} {
		// Benign chain of two: every byte is delivered unchanged.
		in := tls12Stream(frag, benign, benign)
		c := &certScreenConn{Conn: &fakeConn{r: bytes.NewReader(in)}, limits: certguard.DefaultLimits}
		got, err := io.ReadAll(c)
		if err != nil || !bytes.Equal(got, in) || c.certMsgs != 1 {
			t.Fatalf("frag=%d benign: err=%v delivered=%d/%d certMsgs=%d", frag, err, len(got), len(in), c.certMsgs)
		}

		// Hostile cert second in the chain: rejected, and the record that
		// completes the Certificate message is withheld from the reader.
		in = tls12Stream(frag, benign, hostile)
		c = &certScreenConn{Conn: &fakeConn{r: bytes.NewReader(in)}, limits: certguard.DefaultLimits}
		got, err = io.ReadAll(c)
		if !errors.Is(err, certguard.ErrTooManySANs) {
			t.Fatalf("frag=%d hostile: err=%v, want ErrTooManySANs", frag, err)
		}
		certMsgLen := 4 + 3 + 3 + len(benign) + 3 + len(hostile)
		if delivered := handshakeBytes(got); delivered >= certMsgLen {
			t.Fatalf("frag=%d hostile: %d handshake bytes delivered, the full %d-byte Certificate message got through", frag, delivered, certMsgLen)
		}
	}
}

// handshakeBytes sums the record bodies in a stream of complete records.
func handshakeBytes(stream []byte) int {
	total := 0
	for len(stream) >= 5 {
		n := int(stream[3])<<8 | int(stream[4])
		total += n
		stream = stream[5+n:]
	}
	return total
}
