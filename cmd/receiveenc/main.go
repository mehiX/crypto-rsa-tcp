package main

import (
	"log"

	"github.com/mehiX/crypto-rsa-tcp/crypto"
	"github.com/mehiX/crypto-rsa-tcp/server"
)

func main() {
	srvr := server.NewServer("localhost:7878", "test", crypto.DecryptRSA)

	if err := srvr.Listen(); err != nil {
		log.Fatal(err)
	}
}
