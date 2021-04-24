package ascon

import (
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"math/bits"
)

const (
	// KeySize is the size of an ASCON key, in bytes.
	KeySize = 16

	// NonceSize is the size of an ASCON nonce, in bytes.
	NonceSize = 16

	// TagSize is the size of an ASCON tag, in bytes.
	TagSize = 16

	rate     = 8
	paRounds = 12
	pbRounds = 6

	initX0 = uint64((KeySize*8)<<24|(rate*8)<<16|paRounds<<8|pbRounds<<0) << 32
)

func insertByte(b byte, n int) uint64  { return uint64(b) << (8 * (7 - n)) }
func extractByte(u uint64, n int) byte { return byte(u >> (8 * (7 - n))) }

func insert64(b []byte, u uint64) { binary.BigEndian.PutUint64(b, u) }
func extract64(b []byte) uint64   { return binary.BigEndian.Uint64(b) }

func append64(dst []byte, u uint64) []byte {
	buf := make([]byte, 8)
	insert64(buf, u)
	return append(dst, buf...)
}

func rotr(u uint64, n int) uint64 { return bits.RotateLeft64(u, -n) }

func round(c, x0, x1, x2, x3, x4 uint64) (uint64, uint64, uint64, uint64, uint64) {
	t0 := x0 ^ x4
	t1 := x1
	t2 := x2 ^ x1 ^ c
	t3 := x3
	t4 := x4 ^ x3
	x0 = t0 ^ t2&^t1
	x2 = t2 ^ t4&^t3
	x4 = t4 ^ t1&^t0
	x1 = t1 ^ t3&^t2
	x3 = t3 ^ t0&^t4
	x1 ^= x0
	t1 = x1
	x1 = rotr(x1, 39)
	x3 ^= x2
	t2 = x2
	x2 = rotr(x2, 1)
	t4 = x4
	t2 ^= x2
	x2 = rotr(x2, 5)
	t3 = x3
	t1 ^= x1
	x3 = rotr(x3, 10)
	x0 ^= x4
	x4 = rotr(x4, 7)
	t3 ^= x3
	x2 ^= t2
	x1 = rotr(x1, 22)
	t0 = x0
	x2 = ^x2
	x3 = rotr(x3, 7)
	t4 ^= x4
	x4 = rotr(x4, 34)
	x3 ^= t3
	x1 ^= t1
	x0 = rotr(x0, 19)
	x4 ^= t4
	t0 ^= x0
	x0 = rotr(x0, 9)
	x0 ^= t0
	return x0, x1, x2, x3, x4
}

func p12(x0, x1, x2, x3, x4 uint64) (uint64, uint64, uint64, uint64, uint64) {
	x0, x1, x2, x3, x4 = round(0xF0, x0, x1, x2, x3, x4)
	x0, x1, x2, x3, x4 = round(0xE1, x0, x1, x2, x3, x4)
	x0, x1, x2, x3, x4 = round(0xD2, x0, x1, x2, x3, x4)
	x0, x1, x2, x3, x4 = round(0xC3, x0, x1, x2, x3, x4)
	x0, x1, x2, x3, x4 = round(0xB4, x0, x1, x2, x3, x4)
	x0, x1, x2, x3, x4 = round(0xA5, x0, x1, x2, x3, x4)
	x0, x1, x2, x3, x4 = round(0x96, x0, x1, x2, x3, x4)
	x0, x1, x2, x3, x4 = round(0x87, x0, x1, x2, x3, x4)
	x0, x1, x2, x3, x4 = round(0x78, x0, x1, x2, x3, x4)
	x0, x1, x2, x3, x4 = round(0x69, x0, x1, x2, x3, x4)
	x0, x1, x2, x3, x4 = round(0x5A, x0, x1, x2, x3, x4)
	x0, x1, x2, x3, x4 = round(0x4B, x0, x1, x2, x3, x4)
	return x0, x1, x2, x3, x4
}

func p6(x0, x1, x2, x3, x4 uint64) (uint64, uint64, uint64, uint64, uint64) {
	x0, x1, x2, x3, x4 = round(0x96, x0, x1, x2, x3, x4)
	x0, x1, x2, x3, x4 = round(0x87, x0, x1, x2, x3, x4)
	x0, x1, x2, x3, x4 = round(0x78, x0, x1, x2, x3, x4)
	x0, x1, x2, x3, x4 = round(0x69, x0, x1, x2, x3, x4)
	x0, x1, x2, x3, x4 = round(0x5A, x0, x1, x2, x3, x4)
	x0, x1, x2, x3, x4 = round(0x4B, x0, x1, x2, x3, x4)
	return x0, x1, x2, x3, x4
}

// AEAD is an instance of the ASCON AEAD cipher.
type AEAD struct {
	key []byte
}

// Seal implements cipher.AEAD.
func (c *AEAD) Seal(dst, nonce, plaintext, data []byte) []byte {
	if len(nonce) != NonceSize {
		panic("ascon: bad nonce length")
	}

	if total := len(dst) + len(plaintext) + TagSize; cap(dst) < total {
		dst = append(make([]byte, 0, total), dst...)
	}

	k0 := extract64(c.key[:8])
	k1 := extract64(c.key[8:])

	// initialization
	x0 := initX0
	x1 := k0
	x2 := k1
	x3 := extract64(nonce[:8])
	x4 := extract64(nonce[8:])
	x0, x1, x2, x3, x4 = p12(x0, x1, x2, x3, x4)
	x3 ^= k0
	x4 ^= k1

	// process associated data
	if len(data) > 0 {
		for len(data) >= 8 {
			x0 ^= extract64(data[:8])
			x0, x1, x2, x3, x4 = p6(x0, x1, x2, x3, x4)
			data = data[8:]
		}
		for i, b := range data {
			x0 ^= insertByte(b, i)
		}
		x0 ^= insertByte(0x80, len(data))
		x0, x1, x2, x3, x4 = p6(x0, x1, x2, x3, x4)
	}
	x4 ^= 1

	// process plaintext
	for len(plaintext) >= 8 {
		x0 ^= extract64(plaintext[:8])
		dst = append64(dst, x0)
		x0, x1, x2, x3, x4 = p6(x0, x1, x2, x3, x4)
		plaintext = plaintext[8:]
	}
	for i, b := range plaintext {
		x0 ^= insertByte(b, i)
		dst = append(dst, extractByte(x0, i))
	}
	x0 ^= insertByte(0x80, len(plaintext))

	// finalization
	x1 ^= k0
	x2 ^= k1
	x0, x1, x2, x3, x4 = p12(x0, x1, x2, x3, x4)
	x3 ^= k0
	x4 ^= k1

	// tag
	dst = append64(dst, x3)
	dst = append64(dst, x4)

	return dst
}

// Open implements cipher.AEAD.
func (c *AEAD) Open(dst, nonce, ciphertext, data []byte) ([]byte, error) {
	if len(nonce) != NonceSize {
		panic("wrong nonce size")
	} else if len(ciphertext) < TagSize {
		return nil, errors.New("message authentication failed")
	}
	ciphertext, tag := ciphertext[:len(ciphertext)-TagSize], ciphertext[len(ciphertext)-TagSize:]

	k0 := extract64(c.key[:8])
	k1 := extract64(c.key[8:])

	// initialization
	x0 := initX0
	x1 := k0
	x2 := k1
	x3 := extract64(nonce[:8])
	x4 := extract64(nonce[8:])
	x0, x1, x2, x3, x4 = p12(x0, x1, x2, x3, x4)
	x3 ^= k0
	x4 ^= k1

	// process associated data
	if len(data) > 0 {
		for len(data) >= rate {
			x0 ^= extract64(data)
			x0, x1, x2, x3, x4 = p6(x0, x1, x2, x3, x4)
			data = data[8:]
		}
		for i, b := range data {
			x0 ^= insertByte(b, i)
		}
		x0 ^= insertByte(0x80, len(data))
		x0, x1, x2, x3, x4 = p6(x0, x1, x2, x3, x4)
	}
	x4 ^= 1

	// process plaintext
	for len(ciphertext) >= rate {
		c := extract64(ciphertext[:8])
		ciphertext = ciphertext[8:]
		dst = append64(dst, x0^c)
		x0 = c
		x0, x1, x2, x3, x4 = p6(x0, x1, x2, x3, x4)
	}
	for i, b := range ciphertext {
		dst = append(dst, extractByte(x0, i)^b)
		x0 &^= insertByte(0xFF, i)
		x0 |= insertByte(b, i)
	}
	x0 ^= insertByte(0x80, len(ciphertext))

	// finalization
	x1 ^= k0
	x2 ^= k1
	x0, x1, x2, x3, x4 = p12(x0, x1, x2, x3, x4)
	x3 ^= k0
	x4 ^= k1

	// check tag
	check := make([]byte, TagSize)
	insert64(check[:8], x3)
	insert64(check[8:], x4)
	if subtle.ConstantTimeCompare(tag, check) == 0 {
		return nil, errors.New("message authentication failed")
	}

	return dst, nil
}

// NonceSize implements cipher.AEAD.
func (c *AEAD) NonceSize() int { return NonceSize }

// TagSize implements cipher.AEAD.
func (c *AEAD) TagSize() int { return TagSize }

// New returns an AEAD instance for the given key.
func New(key []byte) (*AEAD, error) {
	if len(key) != KeySize {
		return nil, errors.New("bad key length")
	}
	return &AEAD{key}, nil
}
