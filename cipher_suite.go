package noise

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"hash"
	"io"

	"github.com/devi/blake2/blake2b"
	"github.com/devi/blake2/blake2s"
	"github.com/devi/chap"
	"golang.org/x/crypto/curve25519"
)

type DHKey struct {
	Private []byte
	Public  []byte
}

type DHFunc interface {
	GenerateKeypair(random io.Reader) DHKey
	DH(privkey, pubkey []byte) []byte
	DHLen() int
	DHName() string
}

type HashFunc interface {
	Hash() hash.Hash
	HashName() string
}

type CipherFunc interface {
	Cipher(k [32]byte) Cipher
	CipherName() string
}

type Cipher interface {
	Encrypt(out []byte, n uint64, ad, plaintext []byte) []byte
	Decrypt(out []byte, n uint64, ad, ciphertext []byte) ([]byte, error)
}

type CipherSuite interface {
	DHFunc
	CipherFunc
	HashFunc
	Name() []byte
}

func NewCipherSuite(dh DHFunc, c CipherFunc, h HashFunc) CipherSuite {
	return ciphersuite{
		DHFunc:     dh,
		CipherFunc: c,
		HashFunc:   h,
		name:       []byte(dh.DHName() + "_" + c.CipherName() + "_" + h.HashName()),
	}
}

type ciphersuite struct {
	DHFunc
	CipherFunc
	HashFunc
	name []byte
}

func (s ciphersuite) Name() []byte { return s.name }

var DH25519 DHFunc = dh25519{}

type dh25519 struct{}

func (dh25519) GenerateKeypair(rng io.Reader) DHKey {
	var pubkey, privkey [32]byte
	if rng == nil {
		rng = rand.Reader
	}
	if _, err := io.ReadFull(rng, privkey[:]); err != nil {
		panic(err)
	}
	curve25519.ScalarBaseMult(&pubkey, &privkey)
	return DHKey{Private: privkey[:], Public: pubkey[:]}
}

func (dh25519) DH(privkey, pubkey []byte) []byte {
	var dst, in, base [32]byte
	copy(in[:], privkey)
	copy(base[:], pubkey)
	curve25519.ScalarMult(&dst, &in, &base)
	return dst[:]
}

func (dh25519) DHLen() int     { return 32 }
func (dh25519) DHName() string { return "25519" }

type cipherFn struct {
	fn   func([32]byte) Cipher
	name string
}

func (c cipherFn) Cipher(k [32]byte) Cipher { return c.fn(k) }
func (c cipherFn) CipherName() string       { return c.name }

var CipherAESGCM CipherFunc = cipherFn{
	func(k [32]byte) Cipher {
		c, err := aes.NewCipher(k[:])
		if err != nil {
			panic(err)
		}
		gcm, err := cipher.NewGCM(c)
		if err != nil {
			panic(err)
		}
		return aeadCipher{
			gcm,
			func(n uint64) []byte {
				var nonce [12]byte
				binary.BigEndian.PutUint64(nonce[4:], n)
				return nonce[:]
			},
		}
	},
	"AESGCM",
}

var CipherChaChaPoly CipherFunc = cipherFn{
	func(k [32]byte) Cipher {
		return aeadCipher{
			chap.NewCipher(&k),
			func(n uint64) []byte {
				var nonce [12]byte
				binary.LittleEndian.PutUint64(nonce[4:], n)
				return nonce[:]
			},
		}
	},
	"ChaChaPoly",
}

type aeadCipher struct {
	cipher.AEAD
	nonce func(uint64) []byte
}

func (c aeadCipher) Encrypt(out []byte, n uint64, ad, plaintext []byte) []byte {
	return c.Seal(out, c.nonce(n), plaintext, ad)
}

func (c aeadCipher) Decrypt(out []byte, n uint64, ad, ciphertext []byte) ([]byte, error) {
	return c.Open(out, c.nonce(n), ciphertext, ad)
}

type hashFn struct {
	fn   func() hash.Hash
	name string
}

func (h hashFn) Hash() hash.Hash  { return h.fn() }
func (h hashFn) HashName() string { return h.name }

var HashSHA256 HashFunc = hashFn{sha256.New, "SHA256"}
var HashSHA512 HashFunc = hashFn{sha512.New, "SHA512"}
var HashBLAKE2b HashFunc = hashFn{blake2b.New, "BLAKE2b"}
var HashBLAKE2s HashFunc = hashFn{blake2s.New, "BLAKE2s"}
