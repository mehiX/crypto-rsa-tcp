package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"io/ioutil"

	"golang.org/x/crypto/ssh"
)

func PublicKey(loc string) (*rsa.PublicKey, error) {
	data, err := ioutil.ReadFile(loc)
	if err != nil {
		return nil, err
	}

	k, _, _, _, err := ssh.ParseAuthorizedKey(data)
	if err != nil {
		return nil, err
	}

	if _, ok := k.(ssh.CryptoPublicKey); !ok {
		return nil, fmt.Errorf("not a crypto public key")
	}

	pk := ((k.(ssh.CryptoPublicKey)).CryptoPublicKey())

	if v, ok := pk.(*rsa.PublicKey); ok {
		return v, nil
	}

	return nil, fmt.Errorf("not a valid RSA public key")
}

func PrivateKey(loc string) (*rsa.PrivateKey, error) {
	data, err := ioutil.ReadFile(loc)
	if err != nil {
		return nil, err
	}

	k, err := ssh.ParseRawPrivateKey(data)
	if err != nil {
		return nil, err
	}

	if v, ok := k.(*rsa.PrivateKey); ok {
		return v, nil
	}

	return nil, fmt.Errorf("not a valid RSA private key: %q", loc)
}

func DecryptRSA(data []byte, pk *rsa.PrivateKey) ([]byte, error) {

	lbl := []byte("sha256")
	hasher := sha256.New()

	step := pk.PublicKey.Size()
	var decBytes []byte

	msglen := len(data)

	for pos := 0; pos < msglen; pos += step {
		finish := pos + step
		if finish > msglen {
			finish = msglen
		}

		decBlkBytes, err := rsa.DecryptOAEP(hasher, rand.Reader, pk, data[pos:finish], lbl)
		if err != nil {
			return nil, err
		}

		decBytes = append(decBytes, decBlkBytes...)
	}

	return decBytes, nil
}

func EncryptRSA(data []byte, key *rsa.PublicKey) ([]byte, error) {

	msglen := len(data)

	hasher := sha256.New()
	lbl := []byte("sha256")
	step := key.Size() - 2*hasher.Size() - 2
	var encBytes []byte

	for pos := 0; pos < msglen; pos += step {
		finish := pos + step
		if finish > msglen {
			finish = msglen
		}

		encBlkBytes, err := rsa.EncryptOAEP(hasher, rand.Reader, key, data[pos:finish], lbl)
		if err != nil {
			return nil, err
		}

		encBytes = append(encBytes, encBlkBytes...)
	}

	return encBytes, nil

}
