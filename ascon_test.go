package ascon

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func fromHex(s string) []byte {
	b, _ := hex.DecodeString(s)
	return b
}

func TestASCON(t *testing.T) {
	vectors := []struct {
		key, nonce, plaintext, data, ciphertext []byte
	}{
		{
			key:        fromHex("00000000000000000000000000000000"),
			nonce:      fromHex("00000000000000000000000000000000"),
			plaintext:  nil,
			data:       nil,
			ciphertext: fromHex("42213f50a811d2d1d7e4092aa2a42ba4"),
		},
		{
			key:        fromHex("000102030405060708090a0b0c0d0e0f"),
			nonce:      fromHex("000102030405060708090a0b0c0d0e0f"),
			plaintext:  []byte("hello world"),
			data:       []byte("data"),
			ciphertext: fromHex("018ecdf5e742eefa7e395491bc2a139bc11c8dd2f9165bf9df2631"),
		},
		{
			key:        fromHex("985f42f4dbc6755e6a32acbfa2f25038"),
			nonce:      fromHex("bcf951b8a21b46d02c5affd1b0e812a9"),
			plaintext:  fromHex("c48954441374fb339126a256f13e6a1456baab00a7131a44d6bcb6929bb61351653862d000c222003e9290b39edbbf3b19801505975cfde0c8527748acae03460a"),
			data:       fromHex("ca4fc2cb57cb4b1bd9dad47938b332a06aa154dc1d0aac66179cd8e168ea7280e6a152adb7f5e17dfa9b3e63cf87dd6cfea3558fd9a38bf2c056b29cc21135caff"),
			ciphertext: fromHex("18c849bb183d12682f74d06b75e418dc7406a247dea529372d09c5da39adb6c39d205716f31312a44a362aab6bbe0e8def01b5f70e322b3beb5295443a89c9de1ab5526a52c511a1e010916c4312b8b28c"),
		},
	}

	for _, v := range vectors {
		aead, err := New(v.key)
		if err != nil {
			t.Fatal(err)
		}
		ciphertext := aead.Seal(nil, v.nonce, v.plaintext, v.data)
		if !bytes.Equal(ciphertext, v.ciphertext) {
			t.Errorf("expected %x, got %x", v.ciphertext, ciphertext)
		}
		plaintext, err := aead.Open(nil, v.nonce, ciphertext, v.data)
		if err != nil {
			t.Error(err)
		}
		if !bytes.Equal(plaintext, v.plaintext) {
			t.Errorf("expected %x, got %x", v.plaintext, plaintext)
		}
	}
}

func BenchmarkSeal(b *testing.B) {
	aead, _ := New(make([]byte, KeySize))
	plaintext := make([]byte, 1024)
	nonce := make([]byte, NonceSize)
	dst := make([]byte, len(plaintext)+TagSize)

	b.ReportAllocs()
	b.SetBytes(int64(len(plaintext)))
	for i := 0; i < b.N; i++ {
		_ = aead.Seal(dst[:0], nonce, plaintext, nil)
	}
}

func BenchmarkOpen(b *testing.B) {
	aead, _ := New(make([]byte, KeySize))
	plaintext := make([]byte, 1024)
	nonce := make([]byte, NonceSize)
	ciphertext := aead.Seal(nil, nonce, plaintext, nil)
	dst := make([]byte, len(plaintext))

	b.ReportAllocs()
	b.SetBytes(int64(len(plaintext)))
	for i := 0; i < b.N; i++ {
		aead.Open(dst[:0], nonce, ciphertext, nil)
	}
}
