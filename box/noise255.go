package box

import (
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"io"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/poly1305"
	"github.com/titanous/chacha20"
)

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
	if random == nil {
		random = rand.Reader
	}
	if _, err := io.ReadFull(random, privKey[:]); err != nil {
		return Key{}, err
	}
	privKey[0] &= 248
	privKey[31] &= 127
	privKey[31] |= 64
	curve25519.ScalarBaseMult(&pubKey, &privKey)
	return Key{Private: privKey[:], Public: pubKey[:]}, nil
}

func (noise255) KeyLen() (int, int) {
	return 32, 32
}

func (noise255) DH(privkey, pubkey []byte) []byte {
	var dst, in, base [32]byte
	copy(in[:], privkey)
	copy(base[:], pubkey)
	curve25519.ScalarMult(&dst, &in, &base)
	return dst[:]
}

func (noise255) NewCipher(cc []byte) CipherContext {
	return &noise255ctx{cc: cc}
}

type noise255ctx struct {
	cc        []byte
	keystream [168]byte
	cipher    chacha20.Cipher
}

func (n *noise255ctx) Reset(cc []byte) {
	n.cc = cc
}

func (n *noise255ctx) key() (cipher.Stream, []byte) {
	cipherKey := n.cc[:32]
	iv := n.cc[32:40]

	if err := n.cipher.Initialize(cipherKey, iv); err != nil {
		panic(err)
	}

	keystream := n.keystream[:64]
	for i := range keystream {
		n.keystream[i] = 0
	}
	n.cipher.XORKeyStream(keystream, keystream)

	return &n.cipher, keystream
}

func (n *noise255ctx) rekey() {
	cipherKey := n.cc[:32]
	iv := n.cc[32:40]
	for i := range iv {
		iv[i] ^= 0xff
	}
	if err := n.cipher.Initialize(cipherKey, iv); err != nil {
		panic(err)
	}

	ks := n.keystream[64:]
	for i := range ks {
		ks[i] = 0
	}
	n.cipher.XORKeyStream(ks, ks)
	n.cc = ks[64:]
}

func (n *noise255ctx) mac(keystream, ciphertext, authtext []byte) [16]byte {
	var macKey [32]byte
	var tag [16]byte
	copy(macKey[:], keystream)
	poly1305.Sum(&tag, n.authData(ciphertext, authtext), &macKey)
	return tag
}

func (n *noise255ctx) Encrypt(dst, plaintext, authtext []byte) []byte {
	c, keystream := n.key()
	ciphertext := make([]byte, len(plaintext), len(plaintext)+16)
	c.XORKeyStream(ciphertext, plaintext)
	n.rekey()
	tag := n.mac(keystream, ciphertext, authtext)
	return append(dst, append(ciphertext, tag[:]...)...)
}

func (n *noise255ctx) Decrypt(ciphertext, authtext []byte) ([]byte, error) {
	if len(ciphertext) < 16 {
		return nil, ErrAuthFailed
	}
	digest := ciphertext[len(ciphertext)-16:]
	ciphertext = ciphertext[:len(ciphertext)-16]
	c, keystream := n.key()
	tag := n.mac(keystream, ciphertext, authtext)

	if subtle.ConstantTimeCompare(digest, tag[:]) != 1 {
		return nil, ErrAuthFailed
	}

	plaintext := make([]byte, len(ciphertext))
	c.XORKeyStream(plaintext, ciphertext)
	n.rekey()
	return plaintext, nil
}

func (noise255ctx) authData(ciphertext, authtext []byte) []byte {
	// PAD16(authtext) || PAD16(ciphertext) || (uint64_little_endian)len(authtext) || (uint64_little_endian)len(ciphertext)
	authData := make([]byte, pad16len(len(authtext))+pad16len(len(ciphertext))+8+8)
	copy(authData, authtext)
	offset := pad16len(len(authtext))
	copy(authData[offset:], ciphertext)
	offset += pad16len(len(ciphertext))
	binary.LittleEndian.PutUint64(authData[offset:], uint64(len(authtext)))
	offset += 8
	binary.LittleEndian.PutUint64(authData[offset:], uint64(len(ciphertext)))
	return authData
}

func pad16len(l int) int {
	return l + ((16 - (l % 16)) % 16)
}
