package box

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"io"
)

type Ciphersuite interface {
	AppendName(dst []byte) []byte
	DHLen() int
	CCLen() int
	MACLen() int
	KeyLen() (int, int)
	GenerateKey(io.Reader) (Key, error)

	DH(privkey, pubkey []byte) []byte
	NewCipher(cc []byte) CipherContext
}

type CipherContext interface {
	Reset(cc []byte)
	Encrypt(dst, plaintext, authtext []byte) []byte
	Decrypt(ciphertext, authtext []byte) ([]byte, error)
}

var ErrAuthFailed = errors.New("box: message authentication failed")

const CVLen = 48

type Key struct {
	Public  []byte
	Private []byte
}

type Crypter struct {
	Cipher   Ciphersuite
	Key      Key
	PeerKey  Key
	ChainVar []byte

	scratch [64]byte
	cc      CipherContext
}

func (c *Crypter) EncryptBody(dst, plaintext, authtext []byte, padLen int) []byte {
	var p []byte
	if plainLen := len(plaintext) + padLen + 4; len(c.scratch) >= plainLen {
		p = c.scratch[:plainLen]
	} else {
		p = make([]byte, plainLen)
	}
	copy(p, plaintext)
	if _, err := io.ReadFull(rand.Reader, p[len(plaintext):len(plaintext)+padLen]); err != nil {
		panic(err)
	}
	binary.BigEndian.PutUint32(p[len(plaintext)+padLen:], uint32(padLen))
	return c.cc.Encrypt(dst, p, authtext)
}

func (c *Crypter) EncryptBox(dst []byte, ephKey *Key, plaintext []byte, padLen int, kdfNum uint8) ([]byte, error) {
	if len(c.ChainVar) == 0 {
		c.ChainVar = make([]byte, CVLen)
	}
	if ephKey == nil {
		k, err := c.Cipher.GenerateKey(nil)
		if err != nil {
			return nil, err
		}
		ephKey = &k
	}
	dstPrefixLen := len(dst)
	// Allocate a new slice that can fit the full encrypted box if the current dst doesn't fit
	if encLen := c.BoxLen(len(plaintext) + padLen); cap(dst)-len(dst) < encLen {
		newDst := make([]byte, len(dst), len(dst)+encLen)
		copy(newDst, dst)
		dst = newDst
	}

	dh1 := c.Cipher.DH(ephKey.Private, c.PeerKey.Public)
	dh2 := c.Cipher.DH(c.Key.Private, c.PeerKey.Public)

	cv1, cc1 := c.deriveKey(dh1, c.ChainVar, kdfNum)
	cv2, cc2 := c.deriveKey(dh2, cv1, kdfNum+1)
	c.ChainVar = cv2

	dst = append(dst, ephKey.Public...)
	dst = c.cipher(cc1).Encrypt(dst, c.Key.Public, append(c.PeerKey.Public, ephKey.Public...))
	c.cc.Reset(cc2)
	return c.EncryptBody(dst, plaintext, append(c.PeerKey.Public, dst[dstPrefixLen:]...), padLen), nil
}

func (c *Crypter) BoxLen(n int) int {
	return n + (2 * c.Cipher.DHLen()) + (2 * c.Cipher.MACLen()) + 4
}

func (c *Crypter) BodyLen(n int) int {
	return n + c.Cipher.MACLen() + 4
}

func (c *Crypter) SetContext(cc []byte) {
	c.cipher(cc)
}

func (c *Crypter) cipher(cc []byte) CipherContext {
	if c.cc == nil {
		c.cc = c.Cipher.NewCipher(cc)
	} else {
		c.cc.Reset(cc)
	}
	return c.cc
}

func (c *Crypter) DecryptBox(ciphertext []byte, kdfNum uint8) ([]byte, error) {
	if len(c.ChainVar) == 0 {
		c.ChainVar = make([]byte, CVLen)
	}

	ephPubKey := ciphertext[:c.Cipher.DHLen()]
	dh1 := c.Cipher.DH(c.Key.Private, ephPubKey)
	cv1, cc1 := c.deriveKey(dh1, c.ChainVar, kdfNum)

	header := ciphertext[:(2*c.Cipher.DHLen())+c.Cipher.MACLen()]
	ciphertext = ciphertext[len(header):]
	senderPubKey, err := c.cipher(cc1).Decrypt(header[c.Cipher.DHLen():], append(c.Key.Public, ephPubKey...))
	if err != nil {
		return nil, err
	}
	if len(c.PeerKey.Public) > 0 {
		if len(c.PeerKey.Public) != len(senderPubKey) || subtle.ConstantTimeCompare(senderPubKey, c.PeerKey.Public) != 1 {
			return nil, errors.New("box: unexpected sender public key")
		}
	}

	dh2 := c.Cipher.DH(c.Key.Private, senderPubKey)
	cv2, cc2 := c.deriveKey(dh2, cv1, kdfNum+1)
	c.ChainVar = cv2
	body, err := c.cipher(cc2).Decrypt(ciphertext, append(c.Key.Public, header...))
	if err != nil {
		return nil, err
	}
	padLen := int(binary.BigEndian.Uint32(body[len(body)-4:]))
	if padLen < 0 || len(body) < padLen+4 {
		return nil, errors.New("box: invalid padding length")
	}
	return body[:len(body)-(padLen+4)], nil
}

func (c *Crypter) DecryptBody(ciphertext, authtext []byte) ([]byte, error) {
	if c.cc == nil {
		return nil, errors.New("box: uninitialized cipher context")
	}
	return c.cc.Decrypt(ciphertext, authtext)
}

func (c *Crypter) deriveKey(dh, cv []byte, kdfNum uint8) ([]byte, []byte) {
	extra := append(c.Cipher.AppendName(c.scratch[:0]), kdfNum)
	k := DeriveKey(dh, cv, extra, CVLen+c.Cipher.CCLen())
	return k[:CVLen], k[CVLen:]
}

func DeriveKey(secret, extra, info []byte, outputLen int) []byte {
	buf := make([]byte, outputLen+sha512.Size)
	output := buf[:0:outputLen]
	t := buf[outputLen:]
	h := hmac.New(sha512.New, secret)
	var c byte
	for len(output) < outputLen {
		h.Write(info)
		h.Write([]byte{c})
		h.Write(t[:32])
		h.Write(extra)
		t = h.Sum(t[:0])
		h.Reset()
		c++
		if outputLen-len(output) < len(t) {
			output = append(output, t[:outputLen-len(output)]...)
		} else {
			output = append(output, t...)
		}
	}
	return output
}
