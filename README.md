# crypto-rsa-tcp
Practice project: send short messages over tcp using encrytion with ssh keys

Uses openssh key pairs, not protected by password

Create private and public keys:

```bash
ssh-keygen -t rsa -b 2048 -f ./test
```

Build the project:

```bash
go vet ./...
go build ./cmd/sendenc
go build ./cmd/receiveenc
```

## Use the TCP sender/receiver

Start the receiver:

```bash
./receiveenc
```

Send a short message:

```bash
echo "This is my message" | ./sendenc

# sample output
# Sent XXX bytes

```

## Use the encoder/decoder

```bash
cat README.md | go run ./cmd/rsawithkey -k ./test.pub | go run ./cmd/rsawithkey -d -k ./test
```