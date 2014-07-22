package box

import (
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

func BenchmarkEncryptBox(b *testing.B) {
	enc, _ := newCrypters()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		enc.EncryptBox(nil, nil, []byte("yellow submarine"), 0, 0)
	}
}
