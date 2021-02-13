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
	ret, err := k.pubKey.MarshalBinary()
	if err != nil {
		panic("noise/hfs: kyber1024: failure to serialize public key: " + err.Error())
	}
	return ret
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
	alicePublicKeyVal, err := kyber1024.Scheme().UnmarshalBinaryPublicKey(pubkey)
	if err != nil {
		panic("noise/hfs: PublicKey failed to deserialize: " + err.Error())
	}
	alicePubKey := alicePublicKeyVal.(*kyber1024.PublicKey)
	ciphertext = make([]byte, kyber1024.CiphertextSize)
	sharedSecret = make([]byte, kyber1024.SharedKeySize)
	seed := make([]byte, kyber1024.EncapsulationSeedSize)
	_, err = rng.Read(seed)
	if err != nil {
		panic(err)
	}
	alicePubKey.EncapsulateTo(ciphertext, sharedSecret, seed)
	return ciphertext, sharedSecret
}

func (hfsKyber) KEM(keyPair HFSKeyPair, ciphertext []byte) (sharedSecret []byte) {
	if len(ciphertext) != kyber1024.CiphertextSize {
		panic("noise/hfs: ciphertext is not kyber1024.CiphertextSize")
	}
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
	return "Kyber1024"
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
