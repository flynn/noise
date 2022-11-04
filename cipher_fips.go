// +build fips

package noise

/*
#cgo LDFLAGS: -L ./lib/ -lcrypto
#cgo LDFLAGS: -L ./lib/ -lssl
#include <openssl/evp.h>
#include <openssl/aes.h>
*/
import "C"

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"hash"
	"io"
	"unsafe"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
)

// CipherAESGCM is the AES256-GCM AEAD cipher.
var CipherAESGCMFIPS CipherFunc = cipherFn{cipherAESGCMFIPS, "AESGCM"}

func cipherAESGCMFIPS(k [32]byte) Cipher {
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
		k,
		"AESGCMFIPS",
	}
}

type (
	Ctx *C.EVP_CIPHER_CTX
)

func Get_Ctx() Ctx {
	return C.EVP_CIPHER_CTX_new()
}

func (c aeadCipher) Key() [32]byte { return c.key }

func (c aeadCipher) Name() string { return c.name }

func (c aeadCipher) Encrypt(out []byte, n uint64, ad, plaintext []byte) []byte {

	//fmt.Printf("PLAINTEXT:\n%s\n", string(plaintext))
	//fmt.Println("********* ENCRYPT *********")
	//fmt.Printf("ENCRYPTION: %s\n", c.name)

	if len(plaintext) > 0 && c.name == "AESGCMFIPS" {
		//fmt.Printf("CIPHER WITH STACK: %s\n", c.name)
		var tempLength int = 0
		var output []byte = make([]byte, 8096)
		var outputLength int = 0
		var inputArray []byte = []byte(plaintext)
		var inputLength int = len(inputArray)
		var key [32]byte = c.Key()

		//fmt.Println("********* ENCRYPT *********")

		pInput := (*C.uchar)(unsafe.Pointer(&inputArray[0]))
		// fmt.Printf("Original: %s\n", string(inputArray))
		// fmt.Printf("Original Length: %d\n", len(inputArray))

		pKey := (*C.uchar)(unsafe.Pointer(C.CString(string(key[:]))))
		defer C.free((unsafe.Pointer)(pKey))
		// fmt.Printf("UChar* key = %s", key)

		pIv := (*C.uchar)(unsafe.Pointer(C.CString(string(key[0:15]))))
		defer C.free((unsafe.Pointer)(pIv))
		//fmt.Printf("UChar* iv =  %\n", pIv)

		var ctx Ctx = Get_Ctx()
		//fmt.Printf("Context made\n")

		C.EVP_EncryptInit_ex(ctx, C.EVP_aes_128_gcm(), nil, pKey, pIv)
		//fmt.Printf("Encrypt Init\n")

		_ = C.EVP_EncryptUpdate(ctx, (*C.uchar)(&output[0]), (*C.int)(unsafe.Pointer(&outputLength)), pInput, (C.int)(inputLength))
		//fmt.Printf("Update Value: %d\n", value)

		_ = C.EVP_EncryptFinal_ex(ctx, (*C.uchar)(&output[outputLength]), (*C.int)(unsafe.Pointer(&tempLength)))
		//fmt.Printf("Final Value: %d\n", value)

		// fmt.Printf("TempLength: %d\nTotalLength: %d\n", tempLength, outputLength+tempLength)
		C.EVP_CIPHER_CTX_free(ctx)
		//fmt.Printf("Freed\n")

		output = output[0 : outputLength+tempLength]

		//fmt.Printf("FIPSTEXT:\n%s\n", string(output))

		ciphertext := c.Seal(out, c.nonce(n), output, ad)

		//fmt.Printf("CIPHERTEXT:\n%s\n", string(ciphertext))

		//fmt.Printf("ENCRYPTION: %s\n", c.name)

		return ciphertext
	} else {
		return c.Seal(out, c.nonce(n), plaintext, ad)
	}

	//return c.Seal(out, c.nonce(n), plaintext, ad)
}

func (c aeadCipher) Decrypt(out []byte, n uint64, ad, ciphertext []byte) ([]byte, error) {

	//fmt.Printf("CIPHERTEXT:\n%s\n", string(ciphertext))

	//fmt.Println("********* DECRYPT *********")
	//fmt.Printf("DECRYPTION: %s\n", c.name)

	ctext, err := c.Open(out, c.nonce(n), ciphertext, ad)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return ctext, err
	}

	//fmt.Printf("CTEXT:\n%s\n", string(ctext))

	if len(ctext) > 0 && c.name == "AESGCMFIPS" {

		var inputLength int = len(ctext)
		var tempLength int = 0
		var output []byte = make([]byte, 8096)
		var outputLength int = 0
		var key [32]byte = c.Key()

		// TODO: Need error detection
		// fmt.Println("********* DECRYPT *********")

		pInput := (*C.uchar)(unsafe.Pointer(&ctext[0]))

		pKey := (*C.uchar)(unsafe.Pointer(C.CString(string(key[:]))))
		defer C.free((unsafe.Pointer)(pKey))
		//fmt.Printf("UChar* key = %v", pKey)

		pIv := (*C.uchar)(unsafe.Pointer(C.CString(string(key[0:15]))))
		defer C.free((unsafe.Pointer)(pIv))
		//fmt.Printf("UChar* iv =  %v\n", pIv)

		var ctx Ctx = Get_Ctx()
		//fmt.Printf("Context made\n")

		C.EVP_DecryptInit_ex(ctx, C.EVP_aes_128_gcm(), nil, pKey, pIv)
		//fmt.Printf("Decrypt Init\n")

		_ = C.EVP_DecryptUpdate(ctx, (*C.uchar)(&output[0]), (*C.int)(unsafe.Pointer(&outputLength)), pInput, (C.int)(inputLength))
		// fmt.Printf("Input Length = %d\nOutput Length = %d\n", inputLength, outputLength)
		//fmt.Printf("Update Value: %d\n", value)

		_ = C.EVP_DecryptFinal_ex(ctx, (*C.uchar)(&output[outputLength]), (*C.int)(unsafe.Pointer(&tempLength)))
		//fmt.Printf("Final Value: %d\n", value)

		// fmt.Printf("TempLength: %d\nTotalLength: %d\n", tempLength, outputLength+tempLength)

		C.EVP_CIPHER_CTX_free(ctx)
		//fmt.Printf("Freed\n")

		output = output[0 : outputLength+tempLength]

		//fmt.Printf("PLAINTEXT:\n%s\n", string(output))

		return output, nil
	}

	return ctext, nil
}

type hashFn struct {
	fn   func() hash.Hash
	name string
}

func (h hashFn) Hash() hash.Hash  { return h.fn() }
func (h hashFn) HashName() string { return h.name }

// HashSHA256 is the SHA-256 hash function.
var HashSHA256 HashFunc = hashFn{sha256.New, "SHA256"}

// HashSHA512 is the SHA-512 hash function.
var HashSHA512 HashFunc = hashFn{sha512.New, "SHA512"}

func blake2bNew() hash.Hash {
	h, err := blake2b.New512(nil)
	if err != nil {
		panic(err)
	}
	return h
}

// HashBLAKE2b is the BLAKE2b hash function.
var HashBLAKE2b HashFunc = hashFn{blake2bNew, "BLAKE2b"}

func blake2sNew() hash.Hash {
	h, err := blake2s.New256(nil)
	if err != nil {
		panic(err)
	}
	return h
}

// HashBLAKE2s is the BLAKE2s hash function.
var HashBLAKE2s HashFunc = hashFn{blake2sNew, "BLAKE2s"}
