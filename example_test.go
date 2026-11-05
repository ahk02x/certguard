package certguard_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"time"

	"github.com/ahk02x/certguard"
)

// Where certguard has to sit.
//
// crypto/tls calls x509.ParseCertificate on every client certificate in
// (*Conn).processCertsFromClient, and only then calls VerifyPeerCertificate and
// VerifyConnection. By the time any tls.Config callback runs, the parse and
// the allocation it causes have already happened. Calling Inspect from a
// callback is policy and logging, not protection. Inspect protects only when
// it runs on the raw DER before something parses it. The examples below show
// the two placements where that holds, and the one where it does not.

func ExampleInspect() {
	der, _ := newCert(100, true) // 100 empty URI SANs: ~200 bytes of names on the wire
	err := certguard.Inspect(der, certguard.DefaultLimits)
	fmt.Println(errors.Is(err, certguard.ErrTooManySANs))
	fmt.Println(err)
	// Output:
	// true
	// certguard: too many SubjectAltName entries: 100 > 64
}

// Placement 1: a TLS 1.2-only listener that screens the client's Certificate
// message at the record layer before crypto/tls reads it.
//
// This works only because TLS 1.2 sends the client Certificate in plaintext.
// The listener must set MaxVersion: tls.VersionTLS12. Without that, an
// attacker negotiates TLS 1.3, where the client Certificate is encrypted and
// the screen never sees it (next example). Pinning to TLS 1.2 is a real
// trade-off, so weigh it before you adopt this placement.
func Example_tls12RecordPeek() {
	serverCert, roots := newServerCert()
	cfg := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAnyClientCert,
		MaxVersion:   tls.VersionTLS12, // required: TLS 1.3 hides the client Certificate
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			// Reaching this callback means x509.ParseCertificate already ran.
			fmt.Printf("  VerifyPeerCertificate ran: crypto/tls already parsed %d certificate(s)\n", len(raw))
			return nil
		},
	}

	fmt.Println("benign client (3 SANs):")
	r := runHandshake(cfg, newClientCert(3, false), roots)
	fmt.Printf("  screened %d Certificate message(s); handshake ok: %v\n", r.certMsgs, r.serverErr == nil)

	fmt.Println("hostile client (5000 empty URI SANs):")
	r = runHandshake(cfg, newClientCert(5000, true), roots)
	fmt.Printf("  screened %d Certificate message(s); rejected before parsing: %v\n", r.certMsgs, r.screenErr)
	// Output:
	// benign client (3 SANs):
	//   VerifyPeerCertificate ran: crypto/tls already parsed 1 certificate(s)
	//   screened 1 Certificate message(s); handshake ok: true
	// hostile client (5000 empty URI SANs):
	//   screened 1 Certificate message(s); rejected before parsing: certguard: too many SubjectAltName entries: 5000 > 64
}

// The limitation: under TLS 1.3 (Go's default), the record screen sees no
// Certificate message, because it is encrypted. The only hook left is a
// tls.Config callback, and by then x509.ParseCertificate has already
// materialized every SAN entry. InspectParsed still rejects the connection,
// but the allocation it was meant to prevent has already happened.
func Example_tls13CallbackIsTooLate() {
	serverCert, roots := newServerCert()
	cfg := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAnyClientCert, // MaxVersion unset: TLS 1.3 is negotiated
		VerifyConnection: func(cs tls.ConnectionState) error {
			fmt.Printf("VerifyConnection: x509 already materialized %d URIs\n", len(cs.PeerCertificates[0].URIs))
			return certguard.InspectParsed(cs.PeerCertificates[0], certguard.DefaultLimits)
		},
	}
	r := runHandshake(cfg, newClientCert(5000, true), roots)
	fmt.Printf("record screen saw %d Certificate message(s) under TLS 1.3\n", r.certMsgs)
	fmt.Println("rejected, but only after parsing:", errors.Is(r.serverErr, certguard.ErrTooManySANs))
	// Output:
	// VerifyConnection: x509 already materialized 5000 URIs
	// record screen saw 0 Certificate message(s) under TLS 1.3
	// rejected, but only after parsing: true
}

// Placement 2: a TLS-terminating proxy in front of a Go backend. The proxy
// does the TLS 1.3 handshake and forwards the client certificate as raw bytes,
// for example nginx's $ssl_client_escaped_cert (URL-escaped PEM) in a header.
// The Go backend runs Inspect on that DER before x509.ParseCertificate.
//
// What this does and does not protect:
//   - It protects the Go backend's parse.
//   - It does nothing for the proxy's own parse. Bound that with the proxy's
//     own limits, such as a maximum client certificate or chain size. If the
//     terminator is itself Go crypto/tls, it has exactly the problem above.
//   - The backend must accept the header only from the proxy, and the proxy
//     must strip any client-supplied copy of it.
func Example_terminatingProxy() {
	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		escaped := r.Header.Get("X-Client-Cert")
		pemText, err := url.QueryUnescape(escaped)
		block, _ := pem.Decode([]byte(pemText))
		if err != nil || block == nil {
			http.Error(w, "no client certificate", http.StatusBadRequest)
			return
		}
		if err := certguard.Inspect(block.Bytes, certguard.DefaultLimits); err != nil {
			http.Error(w, err.Error(), http.StatusForbidden) // never reaches the parser
			return
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			http.Error(w, "bad certificate", http.StatusBadRequest)
			return
		}
		fmt.Fprintf(w, "hello %s", cert.Subject.CommonName)
	})

	for _, c := range []struct {
		name  string
		nSANs int
		empty bool
	}{{"benign", 3, false}, {"hostile", 5000, true}} {
		der, _ := newCert(c.nSANs, c.empty)
		pemText := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("X-Client-Cert", url.QueryEscape(string(pemText))) // what the proxy would set
		rec := httptest.NewRecorder()
		backend.ServeHTTP(rec, req)
		fmt.Printf("%s: %d %s\n", c.name, rec.Code, rec.Body.String())
	}
	// Output:
	// benign: 200 hello client
	// hostile: 403 certguard: too many SubjectAltName entries: 5000 > 64
}

// ---- record-layer screen used by Example_tls12RecordPeek ----

// certScreenConn wraps the raw server-side connection, beneath crypto/tls. It
// reads the client's records one at a time and reassembles plaintext
// handshake messages, whether they are fragmented across records or several
// share one record. It runs certguard.Inspect on every certificate in a
// Certificate message. A record is handed to crypto/tls only after it has been
// screened, so the record that completes a rejected Certificate message is
// never delivered, and crypto/tls never parses that chain. After the client's
// ChangeCipherSpec everything is encrypted, so it stops screening and passes
// bytes through.
type certScreenConn struct {
	net.Conn
	limits    certguard.Limits
	pending   []byte // screened bytes not yet read by crypto/tls
	hs        []byte // handshake reassembly buffer
	encrypted bool   // client sent ChangeCipherSpec
	certMsgs  int
	err       error // sticky screening error
}

const (
	recordChangeCipherSpec = 20
	recordHandshake        = 22
	handshakeCertificate   = 11
	maxRecordBody          = 16384 + 2048 // TLS 1.2 TLSCiphertext limit
	maxHandshakeMsg        = 256 << 10    // crypto/tls's own cap on a Certificate message
)

var errMalformed = errors.New("certscreen: malformed TLS record or handshake message")

func (c *certScreenConn) Read(p []byte) (int, error) {
	for len(c.pending) == 0 {
		if c.err != nil {
			return 0, c.err
		}
		if c.encrypted {
			return c.Conn.Read(p)
		}
		var hdr [5]byte
		if _, err := io.ReadFull(c.Conn, hdr[:]); err != nil {
			return 0, err
		}
		n := int(binary.BigEndian.Uint16(hdr[3:]))
		if n > maxRecordBody {
			c.fail(errMalformed)
			continue
		}
		rec := make([]byte, 5+n)
		copy(rec, hdr[:])
		if _, err := io.ReadFull(c.Conn, rec[5:]); err != nil {
			return 0, err
		}
		if err := c.screen(rec[0], rec[5:]); err != nil {
			c.fail(err) // the record is dropped, not delivered
			continue
		}
		c.pending = rec
	}
	n := copy(p, c.pending)
	c.pending = c.pending[n:]
	return n, nil
}

func (c *certScreenConn) fail(err error) {
	c.err = err
	c.Conn.Close()
}

func (c *certScreenConn) screen(typ byte, body []byte) error {
	switch typ {
	case recordChangeCipherSpec:
		c.encrypted = true
	case recordHandshake:
		c.hs = append(c.hs, body...)
		for len(c.hs) >= 4 {
			n := int(c.hs[1])<<16 | int(c.hs[2])<<8 | int(c.hs[3])
			if n > maxHandshakeMsg {
				return errMalformed // crypto/tls would refuse it too; don't buffer it
			}
			if len(c.hs) < 4+n {
				break // wait for the next fragment
			}
			if c.hs[0] == handshakeCertificate {
				c.certMsgs++
				if err := screenCertificateMsg(c.hs[4:4+n], c.limits); err != nil {
					return err
				}
			}
			c.hs = c.hs[4+n:]
		}
	}
	return nil
}

// screenCertificateMsg walks a TLS 1.2 Certificate body (RFC 5246 7.4.2):
// a 24-bit-length list of 24-bit-length DER certificates. Every certificate
// is screened, because crypto/tls parses every one.
func screenCertificateMsg(msg []byte, limits certguard.Limits) error {
	if len(msg) < 3 || int(msg[0])<<16|int(msg[1])<<8|int(msg[2]) != len(msg)-3 {
		return errMalformed
	}
	for list := msg[3:]; len(list) > 0; {
		if len(list) < 3 {
			return errMalformed
		}
		n := int(list[0])<<16 | int(list[1])<<8 | int(list[2])
		if len(list) < 3+n {
			return errMalformed
		}
		if err := certguard.Inspect(list[3:3+n], limits); err != nil {
			return err
		}
		list = list[3+n:]
	}
	return nil
}

// ---- test plumbing ----

type handshakeResult struct {
	certMsgs  int   // Certificate messages the screen saw
	screenErr error // why the screen rejected, if it did
	serverErr error // what tls.Conn.Handshake returned on the server
}

// runHandshake runs one real TLS handshake over loopback TCP, with the server
// side wrapped in certScreenConn.
func runHandshake(cfg *tls.Config, clientCert tls.Certificate, roots *x509.CertPool) handshakeResult {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	defer ln.Close()

	clientDone := make(chan struct{})
	go func() {
		defer close(clientDone)
		raw, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			return
		}
		raw.SetDeadline(time.Now().Add(10 * time.Second))
		c := tls.Client(raw, &tls.Config{
			ServerName:   "server.test",
			RootCAs:      roots,
			Certificates: []tls.Certificate{clientCert},
		})
		if c.Handshake() == nil {
			c.Read(make([]byte, 1)) // wait for the server's verdict (TLS 1.3 client finishes first)
		}
		c.Close()
	}()

	raw, err := ln.Accept()
	if err != nil {
		panic(err)
	}
	raw.SetDeadline(time.Now().Add(10 * time.Second))
	screen := &certScreenConn{Conn: raw, limits: certguard.DefaultLimits}
	server := tls.Server(screen, cfg)
	serverErr := server.Handshake()
	server.Close()
	<-clientDone
	return handshakeResult{certMsgs: screen.certMsgs, screenErr: screen.err, serverErr: serverErr}
}

// newCert returns a self-signed client certificate with nSANs URI entries
// (empty URIs when empty is true: the 2-bytes-per-entry hostile shape).
func newCert(nSANs int, empty bool) ([]byte, *ecdsa.PrivateKey) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	uris := make([]*url.URL, nSANs)
	for i := range uris {
		uris[i] = &url.URL{Scheme: "https", Host: "client.test"}
		if empty {
			uris[i] = &url.URL{}
		}
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "client"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		URIs:         uris,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	return der, key
}

func newClientCert(nSANs int, empty bool) tls.Certificate {
	der, key := newCert(nSANs, empty)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// newServerCert returns a self-signed server certificate for "server.test" and
// a pool that trusts it, so the client verifies the server properly.
func newServerCert() (tls.Certificate, *x509.CertPool) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "server.test"},
		DNSNames:     []string{"server.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		panic(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, roots
}
