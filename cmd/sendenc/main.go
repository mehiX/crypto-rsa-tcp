package main

/**
Read message from standard input and send it to a remote server
**/

import (
	"io/ioutil"
	"log"
	"os"

	"github.com/mehiX/crypto-rsa-tcp/client"
	"github.com/mehiX/crypto-rsa-tcp/crypto"
)

func main() {

	// read first the message. No need to create a client if there is nothing to send
	msg, err := ioutil.ReadAll(os.Stdin)
	if err != nil {
		log.Fatal(err)
	}

	// check that we do have something to send
	if len(msg) == 0 {
		log.Fatalln("nothing to send")
	}

	sender := client.NewClient("localhost:7878", "test.pub", crypto.EncryptRSA)

	if err := sender.Send(msg); err != nil {
		log.Fatal(err)
	}
}
