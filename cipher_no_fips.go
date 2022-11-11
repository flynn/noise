// +build !fips

package noise

import (
	"fmt"
)

var CipherAESGCMFIPS CipherFunc = cipherFn{cipherAESGCM, "AESGCMFIPS"}

func (c aeadCipher) Key() [32]byte { return c.key }

func (c aeadCipher) Name() string { return c.name }

func (c aeadCipher) Encrypt(out []byte, n uint64, ad, plaintext []byte) []byte {
	return c.Seal(out, c.nonce(n), plaintext, ad)
}

func (c aeadCipher) Decrypt(out []byte, n uint64, ad, ciphertext []byte) ([]byte, error) {
	ctext, err := c.Open(out, c.nonce(n), ciphertext, ad)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return ctext, err
	}

	return ctext, nil
}
