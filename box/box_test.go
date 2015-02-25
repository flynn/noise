package box

import (
	"encoding/hex"
	"errors"
	"testing"

	. "gopkg.in/check.v1"
)

func Test(t *testing.T) { TestingT(t) }

type S struct{}

var _ = Suite(&S{})

func (s *S) TestRoundtrip(c *C) {
	enc, dec := newCrypters()

	plain := []byte("yellow submarines")
	padLen := 2
	ciphertext, err := enc.EncryptBox(nil, nil, plain, padLen, 0)
	c.Assert(err, IsNil)

	expectedLen := len(plain) + padLen + (2 * Noise255.DHLen()) + (2 * Noise255.MACLen()) + 4
	c.Assert(ciphertext, HasLen, expectedLen, Commentf("expected: %d", expectedLen))

	plaintext, err := dec.DecryptBox(ciphertext, 0)
	c.Assert(err, IsNil)
	c.Assert(plaintext, DeepEquals, plain)

	plain[0] = 'Y'
	ciphertext, err = enc.EncryptBox(nil, nil, plain, 0, 1)
	c.Assert(err, IsNil)

	plaintext, err = dec.DecryptBox(ciphertext, 1)
	c.Assert(err, IsNil)
	c.Assert(plaintext, DeepEquals, plain)
}

func newCrypters() (*Crypter, *Crypter) {
	recvKey, _ := Noise255.GenerateKey(nil)
	sendKey, _ := Noise255.GenerateKey(nil)

	enc := &Crypter{
		Cipher:  Noise255,
		Key:     sendKey,
		PeerKey: recvKey,
	}
	enc.PeerKey.Private = nil

	dec := &Crypter{
		Cipher:  Noise255,
		Key:     recvKey,
		PeerKey: sendKey,
	}
	dec.PeerKey.Private = nil

	return enc, dec
}

func (s *S) TestInvalidPadLen(c *C) {
	pubKey, _ := hex.DecodeString("3e111ccd6d51cf24cc8e24812d9c032a98119bad49611024cdddbe1f5e8eb511")
	privKey, _ := hex.DecodeString("d023aabb62c4fed87d44f3b808fa4dadc3acc9fb5e23edfcffb68bce8a783e46")
	dec := &Crypter{
		Cipher: Noise255,
		Key:    Key{Public: pubKey, Private: privKey},
	}
	encrypted, _ := hex.DecodeString("56cc175a5b73d218e486b0d6e2cf56b6bc44a595a50f220090fa83011c2df25e782c46bd8c96a1df37c44ce8a4d8bb9b207889b8db777a24692682a891859ea043bd397ee1f0e785d34ed66024af039b77118478399977c849da57c0bb2000642f2ad2e9dd9425e060364d754f350b6252b6f8a8aa1135afc8db22")

	decrypted, err := dec.DecryptBox(encrypted, 0)
	c.Assert(decrypted, IsNil)
	c.Assert(err, DeepEquals, errors.New("box: invalid padding length"))
}

func BenchmarkEncryptBox(b *testing.B) {
	enc, _ := newCrypters()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		enc.EncryptBox(nil, nil, []byte("yellow submarine"), 0, 0)
	}
}

func (s *S) TestKDFVectors(c *C) {
	// Vectors from: https://github.com/stouset/go.noise/blob/e84dad9373d43bd187fd0313d9bec1fa48d4a263/ciphersuite/kdf_test.go
	vectors := []struct {
		expected []byte

		secret []byte
		extra  []byte
		info   []byte
		outLen int
	}{
		{
			[]byte("\x39\xa9\x19\x6f\x32\xae\xe7\x39"),
			nil,
			nil,
			nil,
			8,
		},
		{
			[]byte("\xc4\x90\xf6\xe4\x6a\xe8\x1a\xbb"),
			[]byte{0x00},
			[]byte{0x00},
			[]byte{0x00},
			8,
		},
		{
			[]byte("\xc4\x90\xf6\xe4\x6a\xe8\x1a\xbb\x59\x01\x32\xc6\xf1\x40\xb3\x7e"),
			[]byte{0x00},
			[]byte{0x00},
			[]byte{0x00},
			16,
		},
		{
			[]byte("\xad\x5c\x1b\x3f\x13\xce\x4b\x45"),
			[]byte("secret"),
			[]byte("extra"),
			[]byte("info"),
			8,
		},
		{
			[]byte("\x8d\x60\xe9\x6a\x29\xb6\x96\x2f\xf4\x59\xea\xf0\x5a\x3e\xd2\xf1\x82\x80\x63\xc6\xee\x93\x66\x2d\x89\xab\xb2\xff\x56\xb6\x97\xd2\x78\x27\xbe\x44\xf9\xc4\xab\xad\x58\x0d\x4f\xfe\x86\x68\x80\xba\xb4\xbd\x5f\xc1\xa3\xec\xd9\x48\xa3\x24\x35\xa2\xde\x5e\xab\x1d\x76\x86\xc2\x3c\x4f\xf9\x88\xc1\xf8\x1d\x10\xe8\x94\x41\x8e\xe2\x5a\xa8\x59\xaf\xad\x08\xea\x4f\xfe\x5f\x5c\x66\x91\x13\xde\x4a\x75\xc9\x16\xd3\x9e\x72\x67\x8b\x7f\x04\x10\x4b\x0c\x66\x34\xcc\x37\x1a\xe7\x0e\x8d\x4a\x46\x9d\x1f\x54\xe6\x9e\xf7\x33\x63\x3b"),
			[]byte("\xff\xff\xff\xff"),
			[]byte("\xee\xee\xee\xee"),
			[]byte("\xdd\xdd\xdd\xdd"),
			128,
		},
	}

	for i, v := range vectors {
		res := DeriveKey(v.secret, v.extra, v.info, v.outLen)
		c.Assert(res, DeepEquals, v.expected, Commentf("n = %d", i))
	}
}
