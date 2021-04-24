ascon
--------

[![GoDoc](https://godoc.org/lukechampine.com/ascon?status.svg)](https://godoc.org/lukechampine.com/ascon)
[![Go Report Card](http://goreportcard.com/badge/lukechampine.com/ascon)](https://goreportcard.com/report/lukechampine.com/ascon)

```
go get lukechampine.com/ascon
```

This repo contains a pure-Go implementation of [ASCON-128](https://ascon.iaik.tugraz.at),
a lightweight authenticated encryption algorithm. (ASCON is a family of algorithms, 
but currently this repo only implements ASCON-128.)


## Usage

`ascon.AEAD` implements the `cipher.AEAD` interface, so usage should be familiar:

```go
import "lukechampine.com/ascon"

func main() {
    key := make([]byte, ascon.KeySize) // in practice, read this from crypto/rand
    aead, _ := ascon.New(key)
    nonce := make([]byte, ascon.NonceSize)
    plaintext := []byte("Hello, world!")
    ciphertext := aead.Seal(nil, nonce, plaintext, nil)
    recovered, _ := aead.Open(nil, nonce, ciphertext, nil)
    println(string(recovered)) // Hello, world!
}
```


## Benchmarks

The pure Go code is pretty underwhelming; expect 100-200 MB/s. Maybe I'll add an
asm implementation someday.
