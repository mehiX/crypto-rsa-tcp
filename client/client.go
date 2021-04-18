package client

import (
	"bytes"
	"crypto/rsa"
	"fmt"
	"io"
	"log"
	"net"

	"github.com/mehiX/crypto-rsa-tcp/crypto"
)

type client struct {
	ServerAddr  string
	PublicKey   *rsa.PublicKey
	EncryptFunc func([]byte, *rsa.PublicKey) ([]byte, error)
}

func NewClient(srvrAddr, keyLocation string, f func([]byte, *rsa.PublicKey) ([]byte, error)) *client {
	var k *rsa.PublicKey
	var err error

	if keyLocation != "" {
		k, err = crypto.PublicKey(keyLocation)
		if err != nil {
			log.Fatal(err)
		}
	}

	return &client{
		ServerAddr:  srvrAddr,
		PublicKey:   k,
		EncryptFunc: f,
	}
}

func (c *client) Send(txt []byte) error {

	var buf bytes.Buffer

	if c.EncryptFunc != nil {
		data, err := c.EncryptFunc(txt, c.PublicKey)
		if err != nil {
			log.Printf("Enc error: %v\n", err)
			return err
		}
		buf.Write(data)
	} else {
		buf.Write(txt)
	}

	conn, err := net.Dial("tcp", c.ServerAddr)
	if err != nil {
		return err
	}
	defer conn.Close()

	n, err := io.Copy(conn, &buf)
	if err != nil {
		return err
	}
	fmt.Printf("Sent %d bytes\n", n)

	return nil

}
