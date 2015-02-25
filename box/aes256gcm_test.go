package box

import (
	"encoding/hex"

	. "gopkg.in/check.v1"
)

func (s *S) TestRoundtripAES256(c *C) {
	enc, dec := newCryptersAES256()

	plain := []byte("yellow submarines")
	padLen := 2
	ciphertext, err := enc.EncryptBox(nil, nil, plain, padLen, 0)
	c.Assert(err, IsNil)

	expectedLen := len(plain) + padLen + (2 * Noise255AES256GCM.DHLen()) + (2 * Noise255AES256GCM.MACLen()) + 4
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

func newCryptersAES256() (*Crypter, *Crypter) {
	recvKey, _ := Noise255AES256GCM.GenerateKey(nil)
	sendKey, _ := Noise255AES256GCM.GenerateKey(nil)

	enc := &Crypter{
		Cipher:  Noise255AES256GCM,
		Key:     sendKey,
		PeerKey: recvKey,
	}
	enc.PeerKey.Private = nil

	dec := &Crypter{
		Cipher:  Noise255AES256GCM,
		Key:     recvKey,
		PeerKey: sendKey,
	}
	dec.PeerKey.Private = nil

	return enc, dec
}

func (s *S) TestEncryptAES256GCM(c *C) {
	key, _ := hex.DecodeString("4C973DBC7364621674F8B5B89E5C15511FCED9216490FB1C1A2CAA0FFE0407E5")
	plaintext, _ := hex.DecodeString("08000F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748490008")
	authData, _ := hex.DecodeString("68F2E77696CE7AE8E2CA4EC588E54D002E58495C")
	iv, _ := hex.DecodeString("7AE8E2CA4EC500012E58495C")

	expectedCiphertext, _ := hex.DecodeString("BA8AE31BC506486D6873E4FCE460E7DC57591FF00611F31C3834FE1C04AD80B66803AFCF5B27E6333FA67C99DA47C2F0CED68D531BD741A943CFF7A6713BD0")
	expectedTag, _ := hex.DecodeString("2611CD7DAA01D61C5C886DC1A8170107")

	expected := append(expectedCiphertext, expectedTag...)

	cc := append(key, iv...)
	crypter := Noise255AES256GCM.NewCipher(cc)

	dst := crypter.Encrypt(nil, plaintext, authData)
	c.Assert(dst, DeepEquals, expected)
}

func (s *S) TestDecryptAES256GCM(c *C) {
	key, _ := hex.DecodeString("4C973DBC7364621674F8B5B89E5C15511FCED9216490FB1C1A2CAA0FFE0407E5")
	ciphertext, _ := hex.DecodeString("BA8AE31BC506486D6873E4FCE460E7DC57591FF00611F31C3834FE1C04AD80B66803AFCF5B27E6333FA67C99DA47C2F0CED68D531BD741A943CFF7A6713BD0")
	tag, _ := hex.DecodeString("2611CD7DAA01D61C5C886DC1A8170107")
	authData, _ := hex.DecodeString("68F2E77696CE7AE8E2CA4EC588E54D002E58495C")
	iv, _ := hex.DecodeString("7AE8E2CA4EC500012E58495C")

	ciphertext = append(ciphertext, tag...)
	expectedPlaintext, _ := hex.DecodeString("08000F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748490008")

	cc := append(key, iv...)
	crypter := Noise255AES256GCM.NewCipher(cc)

	dst, err := crypter.Decrypt(ciphertext, authData)
	c.Assert(err, IsNil)
	c.Assert(dst, DeepEquals, expectedPlaintext)
}
