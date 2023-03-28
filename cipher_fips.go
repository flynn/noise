//go:build fips
// +build fips

package noise

/*
#cgo LDFLAGS: -L ./lib/ -lcrypto
#cgo LDFLAGS: -L ./lib/ -lssl
#cgo LDFLAGS: -L ./lib/ -lpec
#cgo CFLAGS: -I ./include/
#include "openssl/evp.h"
#include "openssl/aes.h"
#include "engine_ex.h"
*/
import "C"

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"unsafe"
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

func EncryptPEC(key string, input []byte) []byte {
	// BRIDGE GO VARS TO C VARS
	pKey := (*C.uchar)(unsafe.Pointer(C.CString(key)))
	keyLength := C.uint64_t(len(key))
	pInput := (*C.uchar)(unsafe.Pointer(&input[0]))
	inputLength := C.uint64_t(len(input))
	outputArray := make([]byte, 8096)
	outputLength := C.uint64_t(0)
	pOutput := (*C.uchar)(unsafe.Pointer(&outputArray[0]))
	pOutputLength := (*C.uint64_t)(unsafe.Pointer(&outputLength))

	C.EncryptText_GO(pKey, keyLength, pInput, inputLength, pOutput, pOutputLength)

	// TRIM ARRAY
	return outputArray[0:outputLength]
}

func DecryptPEC(key string, input []byte) []byte {
	// BRIDGE GO VARS TO C VARS
	pKey := (*C.uchar)(unsafe.Pointer(C.CString(key)))
	keyLength := C.uint64_t(len(key))
	pInput := (*C.uchar)(unsafe.Pointer(&input[0]))
	inputLength := C.uint64_t(len(input))
	outputArray := make([]byte, 8096)
	outputLength := C.uint64_t(0)
	pOutput := (*C.uchar)(unsafe.Pointer(&outputArray[0]))
	pOutputLength := (*C.uint64_t)(unsafe.Pointer(&outputLength))

	C.DecryptText_GO(pKey, keyLength, pInput, inputLength, pOutput, pOutputLength)

	// TRIM ARRAY
	return outputArray[0:outputLength]
}

func (c aeadCipher) Key() [32]byte { return c.key }

func (c aeadCipher) Name() string { return c.name }

func (c aeadCipher) Encrypt(out []byte, n uint64, ad, plaintext []byte) []byte {

	if len(plaintext) > 0 && c.name == "AESGCMFIPS" {
		var inputArray []byte = []byte(plaintext)
		var key string = string(c.Key())

		output := EncryptPEC(string(key), inputArray)
		ciphertext := c.Seal(out, c.nonce(n), output, ad)

		return ciphertext
	}

	return c.Seal(out, c.nonce(n), plaintext, ad)
}

func (c aeadCipher) Decrypt(out []byte, n uint64, ad, ciphertext []byte) ([]byte, error) {

	ctext, err := c.Open(out, c.nonce(n), ciphertext, ad)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return ctext, err
	}

	if len(ctext) > 0 && c.name == "AESGCMFIPS" {
		var key string = string(c.Key())

		output := C.DecryptPEC(key, cText)
		return output, nil
	}

	return ctext, nil
}
