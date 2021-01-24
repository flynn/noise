// hfs.go - Hybrid Forward Secrecy extension.
// Copyright (C) 2021  David Stainton.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package noise

import (
	"io"

	"github.com/cloudflare/circl/kem/kyber/kyber1024"
)

type HFSDecapsulationKey interface {
	DecapsulateTo(sharedSecret, ciphertext []byte)
}

type HFSKeyPair interface {
	Public() []byte
	Private() HFSDecapsulationKey
}

// HFSFunc implements a KEM-based Hybrid Forward Secrecy for Noise.
//
// See: https://github.com/noiseprotocol/noise_hfs_spec/blob/master/output/noise_hfs.pdf
type HFSFunc interface {
	// GenerateKEMKeypair generates a new KEM key pair.
	GenerateKEMKeypair(rng io.Reader) HFSKeyPair

	// GenerateKEMCiphertext generates both a ciphertext
	// and a KEM output given the remote party's public key.
	GenerateKEMCiphertext(pubkey []byte, rng io.Reader) (ciphertext, sharedSecret []byte)

	// KEM performs calculation between the private key in the key pair
	// and the ciphertext and returns a sharedSecret.
	KEM(keyPair HFSKeyPair, ciphertext []byte) (sharedSecret []byte)

	// PublicKeySize returns the size of the serialized public key.
	PublicKeySize() int

	// CiphertextSize returns the size of the KEM ciphertext.
	CiphertextSize() int

	// SharedKeySize returns the size of the KEM shared secret.
	SharedKeySize() int

	// HFSName is the name of the HFS function.
	HFSName() string
}

// HFSKyber is the Kyber crypto_kem_keypair HFS function.
var HFSKyber HFSFunc = hfsKyber{}

type hfsKyber struct{}

type keyKyberInitiator struct {
	privKey *kyber1024.PrivateKey
	pubKey  *kyber1024.PublicKey
}

func (k *keyKyberInitiator) Public() []byte {
	var ret [kyber1024.PublicKeySize]byte
	k.pubKey.Pack(ret[:])
	return ret[:]
}

func (k *keyKyberInitiator) Private() HFSDecapsulationKey {
	return k.privKey
}

func (hfsKyber) GenerateKEMKeypair(rng io.Reader) HFSKeyPair {
	pubKey, privKey, err := kyber1024.GenerateKeyPair(rng)
	if err != nil {
		panic("noise/hfs: kyber1024.GenerateKeyPair: " + err.Error())
	}
	return &keyKyberInitiator{
		privKey: privKey,
		pubKey:  pubKey,
	}
}

func (h hfsKyber) GenerateKEMCiphertext(pubkey []byte, rng io.Reader) (ciphertext, sharedSecret []byte) {
	if len(pubkey) != h.PublicKeySize() {
		panic("noise/hfs: PublicKey is not kyber1024.PublicKeySize")
	}
	alicePubKey := new(kyber1024.PublicKey)
	alicePubKey.Unpack(pubkey)
	ciphertext = make([]byte, kyber1024.CiphertextSize)
	sharedSecret = make([]byte, kyber1024.SharedKeySize)
	seed := make([]byte, kyber1024.EncapsulationSeedSize)
	_, err := rng.Read(seed)
	if err != nil {
		panic(err)
	}
	alicePubKey.EncapsulateTo(ciphertext, sharedSecret, seed)
	return ciphertext, sharedSecret
}

func (hfsKyber) KEM(keyPair HFSKeyPair, ciphertext []byte) (sharedSecret []byte) {
	sharedSecret = make([]byte, kyber1024.SharedKeySize)
	privKey := keyPair.Private()
	privKey.DecapsulateTo(sharedSecret, ciphertext)
	return sharedSecret
}

func (hfsKyber) PublicKeySize() int {
	return kyber1024.PublicKeySize
}

func (hfsKyber) CiphertextSize() int {
	return kyber1024.CiphertextSize
}

func (hfsKyber) SharedKeySize() int {
	return kyber1024.SharedKeySize
}

func (hfsKyber) HFSName() string {
	return "kyber1024"
}

var hfsNull HFSFunc = hfsNullImpl{}

type hfsNullImpl struct{}

func (hfsNullImpl) GenerateKEMKeypair(rng io.Reader) HFSKeyPair {
	panic("noise/hfs: GenerateKEMKeypair called for null HFS")
}

func (hfsNullImpl) GenerateKEMCiphertext(pubkey []byte, rng io.Reader) (ciphertext, sharedSecret []byte) {
	panic("noise/hfs: GenerateKEMCiphertext called for null HFS")
}

func (hfsNullImpl) KEM(keypair HFSKeyPair, ciphertext []byte) []byte {
	panic("noise/hfs: KEM called for null HFS")
}

func (hfsNullImpl) PublicKeySize() int {
	return 0
}

func (hfsNullImpl) CiphertextSize() int {
	return 0
}

func (hfsNullImpl) SharedKeySize() int {
	return 0
}

func (hfsNullImpl) HFSName() string {
	return "(null)"
}
