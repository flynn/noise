package box

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"io"

	"golang.org/x/crypto/curve25519"
)

var Noise255AES256GCM = aes256gcm{}

type aes256gcm struct{}

func (aes256gcm) AppendName(dst []byte) []byte {
	return append(dst, "Noise255/AES256-GCM\x00\x00\x00\x00\x00"...)
}

func (aes256gcm) DHLen() int  { return 32 }
func (aes256gcm) CCLen() int  { return 44 }
func (aes256gcm) MACLen() int { return 16 }

func (aes256gcm) GenerateKey(random io.Reader) (Key, error) {
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

func (aes256gcm) KeyLen() (int, int) {
	return 32, 32
}

func (aes256gcm) DH(privkey, pubkey []byte) []byte {
	var dst, in, base [32]byte
	copy(in[:], privkey)
	copy(base[:], pubkey)
	curve25519.ScalarMult(&dst, &in, &base)
	return dst[:]
}

func (aes256gcm) NewCipher(cc []byte) CipherContext {
	return &aes256gcmctx{cc: cc}
}

type aes256gcmctx struct {
	cc     []byte
	cipher cipher.AEAD
}

func (ctx *aes256gcmctx) Reset(cc []byte) {
	ctx.cc = cc
}

func (ctx *aes256gcmctx) Encrypt(dst, plaintext, authtext []byte) []byte {
	block, err := aes.NewCipher(ctx.cc[:32])
	if err != nil {
		panic(err)
	}
	ctx.cipher, err = cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}

	nonce := make([]byte, 12)
	copy(nonce, ctx.cc[32:44])
	n := binary.BigEndian.Uint64(ctx.cc[36:44])
	binary.BigEndian.PutUint64(ctx.cc[36:44], n+1)

	return ctx.cipher.Seal(dst, nonce, plaintext, authtext)
}

func (ctx *aes256gcmctx) Decrypt(ciphertext, authtext []byte) ([]byte, error) {
	if len(ciphertext) < 16 {
		return nil, ErrAuthFailed
	}

	block, err := aes.NewCipher(ctx.cc[:32])
	if err != nil {
		panic(err)
	}
	ctx.cipher, err = cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}

	nonce := make([]byte, 12)
	copy(nonce, ctx.cc[32:44])
	n := binary.BigEndian.Uint64(ctx.cc[36:44])
	binary.BigEndian.PutUint64(ctx.cc[36:44], n+1)

	plaintext := make([]byte, 0, len(ciphertext)-ctx.cipher.Overhead())
	return ctx.cipher.Open(plaintext, nonce, ciphertext, authtext)
}
