package main

/*
Encryption (no -d flag): Receives input as text and outputs it encrypted with RSA and encoded in base64.
Decryption (with -d flag): Receives input at base64 encoded text, encrypted with RSA and outputs it as clear text
*/
import (
	"encoding/base64"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/mehiX/crypto-rsa-tcp/crypto"
)

var decrypt = flag.Bool("d", false, "Decrypt")
var keyfile = flag.String("k", "", "Key file")

func main() {

	flag.Parse()

	data, err := ioutil.ReadAll(os.Stdin)
	if err != nil {
		log.Fatal(err)
	}

	// decrypt message
	var buf []byte
	var n int

	var ret []byte

	if *decrypt {
		buf = make([]byte, base64.StdEncoding.DecodedLen(len(data)))
		n, err = base64.StdEncoding.Decode(buf, data)
		if err != nil {
			log.Fatal(err)
		}

		pk, err := crypto.PrivateKey(*keyfile)
		if err != nil {
			log.Fatal(fmt.Errorf("key error: %v", err))
		}

		ret, err = crypto.DecryptRSA(buf[:n], pk)
		if err != nil {
			log.Fatal(err)
		}

		os.Stdout.Write(ret)

	} else {
		// encrypt message
		buf = data
		n = len(data)

		pk, err := crypto.PublicKey(*keyfile)
		if err != nil {
			log.Fatal(fmt.Errorf("key error: %v", err))
		}

		ret, err = crypto.EncryptRSA(buf[:n], pk)
		if err != nil {
			log.Fatal(err)
		}

		if _, err := os.Stdout.WriteString(base64.StdEncoding.EncodeToString(ret)); err != nil {
			log.Fatal(err)
		}
	}
}
