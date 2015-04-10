package main

import (
	"crypto/rand"
	"flag"
	"fmt"
	"golang.org/x/crypto/nacl/box"
	"io"
	"log"
	"net"
	"os"
)

type SecureReader struct {
	r    io.Reader
	priv *[32]byte
	pub  *[32]byte
}

func (sr *SecureReader) Read(p []byte) (n int, err error) {
	n, r := sr.r.Read(p)
	nonce := new([24]byte)
	_, err = io.ReadFull(rand.Reader, nonce[:])
	if err != nil {
		panic(err)
	}
	nonce = &[24]byte{'t'}
	decrypt, _ := box.Open(nil, p[:n], nonce, sr.pub, sr.priv)
	buf := make([]byte, 1024)
	copy(p, buf)
	copy(p[:n], decrypt)
	return len(decrypt), r
}

// NewSecureReader instantiates a new SecureReader overwrite function write (line 20 writes to NewSecure
func NewSecureReader(r io.Reader, priv, pub *[32]byte) io.Reader {
	nsr := &SecureReader{r, priv, pub}
	nsr.priv = priv
	nsr.pub = pub
	return nsr
}

type SecureWriter struct {
	w    io.Writer
	priv *[32]byte
	pub  *[32]byte
}

func (sw *SecureWriter) Write(p []byte) (n int, err error) {
	nonce2 := &[24]byte{'t'}
	nonce := new([24]byte)
	_, err = io.ReadFull(rand.Reader, nonce[:])
	if err != nil {
		panic(err)
	}
	enc := box.Seal(nil, p, nonce2, sw.pub, sw.priv)
	n, err = sw.w.Write(enc)
	return n, err
}

// https://github.com/mperham/gobox
// NewSecureWriter instantiates a new SecureWriter
func NewSecureWriter(w io.Writer, priv, pub *[32]byte) io.Writer {
	nsw := &SecureWriter{w, priv, pub}
	nsw.priv = priv
	nsw.pub = pub
	return nsw
}

// Dial generates a private/public key pair,
// connects to the server, perform the handshake
// and return a reader/writer.
func Dial(addr string) (io.ReadWriteCloser, error) {
	return nil, nil
}

// Serve starts a secure echo server on the given listener.
func Serve(l net.Listener) error {
	return nil
}

func main() {
	port := flag.Int("l", 0, "Listen mode. Specify port")
	flag.Parse()

	// Server mode
	if *port != 0 {
		l, err := net.Listen("tcp", fmt.Sprintf(":%d", *port))
		if err != nil {
			log.Fatal(err)
		}
		defer l.Close()
		log.Fatal(Serve(l))
	}

	// Client mode
	if len(os.Args) != 3 {
		log.Fatalf("Usage: %s <port> <message>", os.Args[0])
	}
	conn, err := Dial("localhost:" + os.Args[1])
	if err != nil {
		log.Fatal(err)
	}
	if _, err := conn.Write([]byte(os.Args[2])); err != nil {
		log.Fatal(err)
	}
	buf := make([]byte, len(os.Args[2]))
	n, err := conn.Read(buf)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%s\n", buf[:n])
}
