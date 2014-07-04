package box

import (
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"io"
	"strconv"

	"code.google.com/p/go.crypto/curve25519"
	"code.google.com/p/go.crypto/poly1305"
	"github.com/codahale/chacha20"
)

type Ciphersuite interface {
	AppendName(dst []byte) []byte
	DHLen() int
	CCLen() int
	MACLen() int
	GenerateKey(io.Reader) (Key, error)

	DH(privkey, pubkey []byte) []byte
	NewCipher(cv []byte) CipherContext
}

type CipherContext interface {
	Encrypt(dst, authtext, plaintext []byte) []byte
	Decrypt(authtext, ciphertext []byte) ([]byte, error)
}

const cvLen = 48

type Key struct {
	Public  []byte
	Private []byte
}

func noiseBody(cc CipherContext, dst []byte, padLen int, appData, header []byte) []byte {
	plaintext := make([]byte, len(appData)+padLen+4)
	copy(plaintext, appData)
	if _, err := io.ReadFull(rand.Reader, plaintext[len(appData):len(appData)+padLen]); err != nil {
		panic(err)
	}
	binary.BigEndian.PutUint32(plaintext[len(appData)+padLen:], uint32(padLen))
	return cc.Encrypt(dst, header, plaintext)
}

type Crypter struct {
	Cipher      Ciphersuite
	SenderKey   Key
	ReceiverKey Key
	ChainVar    []byte
	KDFNum      int

	keyBuf [512]byte
}

func (c *Crypter) Encrypt(dst []byte, ephKey *Key, plaintext []byte, padLen int) ([]byte, error) {
	if len(c.ChainVar) == 0 {
		c.ChainVar = make([]byte, cvLen)
	}
	if ephKey == nil {
		k, err := c.Cipher.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		ephKey = &k
	}
	dstPrefixLen := len(dst)
	// Allocate a new slice that can fit the full encrypted box if the current dst doesn't fit
	if encLen := c.EncryptedLen(len(plaintext) + padLen); cap(dst)-len(dst) < encLen {
		newDst := make([]byte, len(dst), len(dst)+encLen)
		copy(newDst, dst)
		dst = newDst
	}

	dh1 := c.Cipher.DH(ephKey.Private, c.ReceiverKey.Public)
	dh2 := c.Cipher.DH(c.SenderKey.Private, c.ReceiverKey.Public)

	cv1 := c.deriveKey(dh1, c.ChainVar)
	c.ChainVar = c.deriveKey(dh2, cv1)

	cc1 := c.Cipher.NewCipher(cv1)
	cc2 := c.Cipher.NewCipher(c.ChainVar)

	dst = append(dst, ephKey.Public...)
	dst = cc1.Encrypt(dst, ephKey.Public, c.SenderKey.Public)
	return noiseBody(cc2, dst, padLen, plaintext, dst[dstPrefixLen:]), nil
}

func (c *Crypter) EncryptedLen(n int) int {
	return n + (2 * c.Cipher.DHLen()) + (2 * c.Cipher.MACLen()) + 4
}

func (c *Crypter) Decrypt(ciphertext []byte) ([]byte, error) {
	if len(c.ChainVar) == 0 {
		c.ChainVar = make([]byte, cvLen)
	}

	ephPubKey := ciphertext[:c.Cipher.DHLen()]
	dh1 := c.Cipher.DH(c.ReceiverKey.Private, ephPubKey)
	cv1 := c.deriveKey(dh1, c.ChainVar)
	cc1 := c.Cipher.NewCipher(cv1)

	header := ciphertext[:(2*c.Cipher.DHLen())+c.Cipher.MACLen()]
	ciphertext = ciphertext[len(header):]
	senderPubKey, err := cc1.Decrypt(ephPubKey, header[c.Cipher.DHLen():])
	if err != nil {
		return nil, err
	}

	dh2 := c.Cipher.DH(c.ReceiverKey.Private, senderPubKey)
	c.ChainVar = c.deriveKey(dh2, cv1)
	cc2 := c.Cipher.NewCipher(c.ChainVar)
	body, err := cc2.Decrypt(header, ciphertext)
	if err != nil {
		return nil, err
	}
	padLen := int(binary.BigEndian.Uint32(body[len(body)-4:]))

	return body[:len(body)-(padLen+4)], nil
}

func (c *Crypter) deriveKey(dh, cv []byte) []byte {
	// info || (byte)c || t[0:32] || extra_data
	data := append(append(c.keyBuf[:0:256], cv...), 0)
	data = data[:len(data)+32]
	data = c.Cipher.AppendName(data)
	data = strconv.AppendInt(data, int64(c.KDFNum), 10)

	output := c.keyBuf[256 : len(c.keyBuf)-sha512.Size : len(c.keyBuf)-sha512.Size]
	t := c.keyBuf[len(c.keyBuf)-sha512.Size:]

	k := deriveKey(dh, data, output, t, cvLen, cvLen+c.Cipher.CCLen())
	c.KDFNum++
	return k
}

func deriveKey(secret, data, output, t []byte, infoLen, outputLen int) []byte {
	h := hmac.New(sha512.New, secret)
	var c byte
	for len(output) < outputLen {
		data[infoLen] = c
		copy(data[infoLen+1:], t[:32])
		h.Write(data)
		t = h.Sum(t[:0])
		h.Reset()
		c++
		output = append(output, t...)
	}
	return output[:outputLen]
}

var Noise255 = noise255{}

type noise255 struct{}

func (noise255) AppendName(dst []byte) []byte {
	return append(dst, "Noise255\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"...)
}
func (noise255) DHLen() int  { return 32 }
func (noise255) CCLen() int  { return 40 }
func (noise255) MACLen() int { return 16 }

func (noise255) GenerateKey(random io.Reader) (Key, error) {
	var pubKey, privKey [32]byte
	if _, err := io.ReadFull(random, privKey[:]); err != nil {
		return Key{}, err
	}
	privKey[0] &= 248
	privKey[31] &= 127
	privKey[31] |= 64
	curve25519.ScalarBaseMult(&pubKey, &privKey)
	return Key{Private: privKey[:], Public: pubKey[:]}, nil
}

func (noise255) DH(privkey, pubkey []byte) []byte {
	var dst, in, base [32]byte
	copy(in[:], privkey)
	copy(base[:], pubkey)
	curve25519.ScalarMult(&dst, &in, &base)
	return dst[:]
}

func (noise255) NewCipher(cv []byte) CipherContext {
	return &noise255ctx{cv}
}

type noise255ctx struct {
	cc []byte
}

func (n *noise255ctx) key() (cipher.Stream, []byte) {
	cipherKey := n.cc[:32]
	iv := n.cc[32:40]

	c, err := chacha20.NewCipher(cipherKey, iv)
	if err != nil {
		panic(err)
	}

	keystream := make([]byte, 128)
	c.XORKeyStream(keystream, keystream)

	n.cc = keystream[64:104]
	return c, keystream
}

func (n *noise255ctx) mac(keystream, authtext, ciphertext []byte) [16]byte {
	var macKey [32]byte
	var tag [16]byte
	copy(macKey[:], keystream)
	poly1305.Sum(&tag, n.authData(authtext, ciphertext), &macKey)
	return tag
}

func (n *noise255ctx) Encrypt(dst, authtext, plaintext []byte) []byte {
	c, keystream := n.key()
	ciphertext := make([]byte, len(plaintext), len(plaintext)+16)
	c.XORKeyStream(ciphertext, plaintext)
	tag := n.mac(keystream, authtext, ciphertext)
	return append(dst, append(ciphertext, tag[:]...)...)
}

var ErrAuthFailed = errors.New("box: message authentication failed")

func (n *noise255ctx) Decrypt(authtext, ciphertext []byte) ([]byte, error) {
	digest := ciphertext[len(ciphertext)-16:]
	ciphertext = ciphertext[:len(ciphertext)-16]
	c, keystream := n.key()
	tag := n.mac(keystream, authtext, ciphertext)

	if subtle.ConstantTimeCompare(digest, tag[:]) != 1 {
		return nil, ErrAuthFailed
	}

	plaintext := make([]byte, len(ciphertext))
	c.XORKeyStream(plaintext, ciphertext)
	return plaintext, nil
}

func (noise255ctx) authData(authtext, ciphertext []byte) []byte {
	// PAD16(authtext) || PAD16(ciphertext) || (uint64)len(authtext) || (uint64)len(ciphertext)
	authData := make([]byte, pad16len(len(authtext))+pad16len(len(ciphertext))+8+8)
	copy(authData, authtext)
	offset := pad16len(len(authtext))
	copy(authData[offset:], ciphertext)
	offset += pad16len(len(ciphertext))
	binary.BigEndian.PutUint64(authData[offset:], uint64(len(authtext)))
	offset += 8
	binary.BigEndian.PutUint64(authData[offset:], uint64(len(ciphertext)))
	return authData
}

func pad16len(l int) int {
	return l + (16 - (l % 16))
}
