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

// SecureReader is bla
// needs comments because its exported (because uppercase)
type SecureReader struct {
	io.Reader
	priv *[32]byte
	pub  *[32]byte //new marker if multiple reads are necessary
}

func (sr *SecureReader) Read(p []byte) (n int, err error) {
	n, r := sr.Reader.Read(p)
	nonceBack := new([24]byte)
	copy(nonceBack[:], p[:24])
	decrypt, _ := box.Open(nil, p[24:n], nonceBack, sr.pub, sr.priv)
	buf := make([]byte, 1024)
	copy(p, buf)
	copy(p[:n], decrypt)
	return len(decrypt), r
}

// NewSecureReader instantiates a new SecureReader
func NewSecureReader(r io.Reader, priv, pub *[32]byte) io.Reader {
	nsr := &SecureReader{r, priv, pub}
	nsr.priv = priv
	nsr.pub = pub
	return nsr
}

// SecureWriter needs also a comment
type SecureWriter struct {
	io.Writer
	priv *[32]byte
	pub  *[32]byte
}

func (sw *SecureWriter) Write(p []byte) (n int, err error) {
	nonce := new([24]byte)
	_, err = io.ReadFull(rand.Reader, nonce[:])
	if err != nil {
		panic(err)
	}
	enc := box.Seal(nil, p, nonce, sw.pub, sw.priv)
	encWithNonce := append(nonce[:], enc...)
	n, err = sw.Writer.Write(encWithNonce)
	return n, err
}

// NewSecureWriter instantiates a new SecureWriter
// https://github.com/mperham/gobox
func NewSecureWriter(w io.Writer, priv, pub *[32]byte) io.Writer {
	nsw := &SecureWriter{w, priv, pub}
	nsw.priv = priv
	nsw.pub = pub
	return nsw
}

type secureReadWriteCloser struct {
	io.Writer
	io.Reader
}

func (srwc secureReadWriteCloser) Close() (err error) {
	return nil
}

// Dial generates a private/public key pair,
// connects to the server, perform the handshake
// and return a reader/writer.
func Dial(addr string) (io.ReadWriteCloser, error) {
	pub, priv, err := box.GenerateKey(rand.Reader)
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		panic(err)
	}
	secureR := NewSecureReader(conn, priv, pub)
	secureW := NewSecureWriter(conn, priv, pub)

	var rwc secureReadWriteCloser
	rwc.Writer = secureW
	rwc.Reader = secureR

	return rwc, err
}

// Serve starts a secure echo server on the given listener.
func Serve(l net.Listener) error {
	for {
		c, err := l.Accept()
		if err != nil {
			fmt.Printf("i have an error %v\n", err)
			panic(err)
		}
		go io.Copy(c, c)
		return nil

	}
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
