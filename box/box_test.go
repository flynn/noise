package box

import (
	"crypto/rand"
	"testing"

	. "gopkg.in/check.v1"
)

func Test(t *testing.T) { TestingT(t) }

type S struct{}

var _ = Suite(&S{})

func (s *S) TestRoundtrip(c *C) {
	recvKey, _ := Noise255.GenerateKey(rand.Reader)
	sendKey, _ := Noise255.GenerateKey(rand.Reader)

	enc := &Crypter{
		Cipher:      Noise255,
		SenderKey:   sendKey,
		ReceiverKey: recvKey,
	}
	enc.ReceiverKey.Private = nil

	dec := &Crypter{
		Cipher:      Noise255,
		SenderKey:   sendKey,
		ReceiverKey: recvKey,
	}
	dec.SenderKey.Private = nil

	plain := []byte("yellow submarines")
	padLen := 2
	ciphertext, err := enc.Encrypt(nil, nil, plain, padLen)
	c.Assert(err, IsNil)

	expectedLen := len(plain) + padLen + (2 * Noise255.DHLen()) + (2 * Noise255.MACLen()) + 4
	c.Assert(ciphertext, HasLen, expectedLen, Commentf("expected: %d", expectedLen))

	plaintext, err := dec.Decrypt(ciphertext)
	c.Assert(err, IsNil)
	c.Assert(plaintext, DeepEquals, plain)

	plain[0] = 'Y'
	ciphertext, err = enc.Encrypt(nil, nil, plain, 0)
	c.Assert(err, IsNil)

	plaintext, err = dec.Decrypt(ciphertext)
	c.Assert(err, IsNil)
	c.Assert(plaintext, DeepEquals, plain)
}
