package main

import (
	// 	"bytes"
	"crypto/rand"
	"flag"
	"fmt"
	"golang.org/x/crypto/nacl/box"
	"io"
	"log"
	"net"
	"os"
	// 	"strconv"
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
	// 	fmt.Printf("bekomme ich was leeres %v\n", p)
	// 	fmt.Printf("bekomme ich was leeres %v\n", string(p))
	nonceBack := new([24]byte)
	copy(nonceBack[:], p[:24])
	decrypt, erfolg := box.Open(nil, p[24:n], nonceBack, sr.pub, sr.priv)
	if !erfolg {
		fmt.Println("entschlusseln klappt nicht")
	}
	buf := make([]byte, 1024)
	copy(p, buf)
	copy(p[:n], decrypt)
	// 	fmt.Printf("entschlussekt wurd %v\n", p)
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
	// 	fmt.Printf("i want encrypted %v\n", string(p))
	// 	fmt.Printf("i want encrypted %v\n", p)
	fmt.Printf("nonce is  %v\n", nonce[0:3])

	enc := box.Seal(nil, p, nonce, sw.pub, sw.priv)
	encWithNonce := append(nonce[:], enc...)

	// 	fmt.Printf("encrypted sieht es so aus %v\n", encWithNonce)

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

type secureConnection struct {
	io.Writer
	io.Reader
}

func (sc secureConnection) Close() error {
	// 	err := sc.Close()
	return nil
}

// Dial generates a private/public key pair,
// connects to the server, perform the handshake
// and return a reader/writer.
func Dial(addr string) (io.ReadWriteCloser, error) {
	pub, priv, err := box.GenerateKey(rand.Reader)
	// 	fmt.Printf("priv is %v\n", priv)
	fmt.Printf("pub is %v\n", pub)
	if err != nil {
		panic(err)
	}
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		panic(err)
	}
	header := &[64]byte{'p', 'r', 'i', 'v', 'p', 'u', 'b'}

	buf := make([]byte, 96)
	copy(buf[:64], header[:64])
	copy(buf[64:], pub[0:32])
	fmt.Printf("what is the end%v\n", pub[32:])
	fmt.Printf("combination %v\n", buf)
	conn2, err := net.Dial("tcp", addr)
	if err != nil {
		panic(err)
	}
	conn2.Write(buf)
	conn2.Close()
	var rwc secureConnection
	secureR := NewSecureReader(conn, priv, pub)
	secureW := NewSecureWriter(conn, priv, pub)
	rwc = secureConnection{secureW, secureR}
	return rwc, err
}

// Serve starts a secure echo server on the given listener.
func Serve(l net.Listener) error {
	// ckr := make(chan *KeyRequests)
	// Listen for an incoming connection.
	for {
		conn, err := l.Accept()
		if err != nil {
			fmt.Println("Error accepting: ", err.Error())
			return err
			panic(err)
		}

		//logs an incoming message
		fmt.Printf("Received message %s -> %s \n", conn.RemoteAddr(), conn.LocalAddr())

		// Handle connections in a new goroutine.
		go handleRequest(conn)
	}
	return nil
}

// Handles incoming requests.
func handleRequest(conn net.Conn) {
	buf := make([]byte, 1024)
	// Read the incoming connection into the buffer.
	reqLen, err := conn.Read(buf)
	fmt.Print("I read %v\n", buf)
	if err != nil {
		panic(err)
	}
	if reqLen == 96 {
		fmt.Println("i found the key")
	} else {
		conn.Write(buf)
		conn.Close()
	}
}

type KeyRequests struct {
	ask  net.Addr
	answ chan [32]byte
}

func ControlKeys(queue chan *KeyRequests) {
	knownKeys := make(map[net.Addr][32]byte)
	for r := range queue {
		i, ok := knownKeys[r.ask]
		if ok != true {
			r.answ <- [32]byte{}
		} else {
			r.answ <- i
		}
	}
}
func handleRequestNewKey(conn net.Conn, ckr chan *KeyRequests) {
	// Make a buffer to hold incoming data.
	buf := make([]byte, 1024)
	// Read the incoming connection into the buffer.
	reqLen, err := conn.Read(buf)
	if err != nil {
		fmt.Println("Error reading:", err.Error())
	}
	// Write the message in the connection channel.
	conn.Write(buf[:reqLen])
	// Close the connection when you're done with it.
	//conn.Close()
}

func handleRequestEncrypt(conn net.Conn, ckr chan *KeyRequests) {
	// Make a buffer to hold incoming data.
	buf := make([]byte, 1024)
	// Read the incoming connection into the buffer.
	reqLen, err := conn.Read(buf)
	if err != nil {
		fmt.Println("Error reading:", err.Error())
	}
	// Write the message in the connection channel.
	conn.Write(buf[:reqLen])
	// Close the connection when you're done with it.
	conn.Close()
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
