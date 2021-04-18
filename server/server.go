package server

import (
	"bytes"
	"crypto/rsa"
	"io"
	"log"
	"net"
	"os"
	"time"

	"github.com/mehiX/crypto-rsa-tcp/crypto"
)

type RSADecryptFunc func([]byte, *rsa.PrivateKey) ([]byte, error)

type server struct {
	Addr        string
	Key         *rsa.PrivateKey
	DecryptFunc RSADecryptFunc
}

func (s *server) Listen() error {

	l, err := net.Listen("tcp", s.Addr)
	if err != nil {
		return err
	}

	for {
		conn, err := l.Accept()
		if err != nil {
			log.Println(err)
			continue
		}

		go decryptAndPrint(conn, s.Key, s.DecryptFunc)

	}
}

func decryptAndPrint(conn net.Conn, key *rsa.PrivateKey, f RSADecryptFunc) {
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(5 * time.Second))

	var buf bytes.Buffer
	_, err := io.Copy(&buf, conn)
	if err != nil {
		log.Println(err)
		return
	}

	data := buf.Bytes()

	dec, err := f(data, key)
	if err != nil {
		log.Println(err)
		return
	}

	os.Stdout.Write(dec)

}

func NewServer(addr string, keyLocation string, f func([]byte, *rsa.PrivateKey) ([]byte, error)) *server {
	key, err := crypto.PrivateKey(keyLocation)
	if err != nil {
		log.Fatal(err)
	}

	return &server{
		Addr:        addr,
		Key:         key,
		DecryptFunc: f,
	}
}
