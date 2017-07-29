// hfs.go - Hybrid Forward Secrecy extension.
// Copyright (C) 2017  Yawning Angel.
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

	"git.schwanenlied.me/yawning/newhope.git"
)

type HFSKey interface {
	Public() []byte
}

// HFSFunc implements a hybrid forward secrecy function, for the Noise HFS
// extension (version 1draft-5).
//
// See: https://github.com/noiseprotocol/noise_spec/blob/master/extensions/ext_hybrid_forward_secrecy.md
type HFSFunc interface {
	// GenerateKeypairF generates a new key pair for the hybrid forward
	// secrecy algorithm relative to a remote public key rf. The rf value
	// will be empty for the first "f" token in the handshake, and non-empty
	// for the second "f" token.
	GenerateKeypairF(rng io.Reader, rf []byte) HFSKey

	// FF performs a hybrid forward secrecy calculation that mixes a local key
	// pair with a remote public key.
	FF(keypair HFSKey, pubkey []byte) []byte

	// FLen1 is a constant specifying the size in bytes of the output from
	// GenerateKeypairF(rf) when rf is empty.
	FLen1() int

	// Flen2 is a constant specifying the size in bytes of the output from
	// GenerateKeypairF(rf) when rf is not empty.
	FLen2() int

	// FLen is constant specifying the size in bytes of the output from FF().
	FLen() int

	// HFSName is the name of the HFS function.
	HFSName() string
}

// HFSNewHopeSimple is the NewHope-Simple HFS function.
var HFSNewHopeSimple HFSFunc = hfsNewHopeSimple{}

type hfsNewHopeSimple struct{}

type keyNewHopeSimpleAlice struct {
	privKey *newhope.PrivateKeySimpleAlice
	pubKey  *newhope.PublicKeySimpleAlice
}

func (k *keyNewHopeSimpleAlice) Public() []byte {
	return k.pubKey.Send[:]
}

type keyNewHopeSimpleBob struct {
	pubKey *newhope.PublicKeySimpleBob
	shared []byte
}

func (k *keyNewHopeSimpleBob) Public() []byte {
	return k.pubKey.Send[:]
}

func (hfsNewHopeSimple) GenerateKeypairF(rng io.Reader, rf []byte) HFSKey {
	if rf != nil {
		if len(rf) != newhope.SendASimpleSize {
			panic("noise/hfs: rf is not SendASimpleSize")
		}
		var alicePk newhope.PublicKeySimpleAlice
		copy(alicePk.Send[:], rf)

		pubKey, shared, err := newhope.KeyExchangeSimpleBob(rng, &alicePk)
		if err != nil {
			panic("noise/hfs: newhope.KeyExchangeSimpleBob(): " + err.Error())
		}

		return &keyNewHopeSimpleBob{
			pubKey: pubKey,
			shared: shared,
		}
	}

	// Generate the keypair as Alice.
	privKey, pubKey, err := newhope.GenerateKeyPairSimpleAlice(rng)
	if err != nil {
		panic("noise/hfs: newhope.GenerateKeypairSimpleAlice(): " + err.Error())
	}

	return &keyNewHopeSimpleAlice{
		privKey: privKey,
		pubKey:  pubKey,
	}
}

func (hfsNewHopeSimple) FF(keypair HFSKey, pubkey []byte) []byte {
	switch k := keypair.(type) {
	case *keyNewHopeSimpleAlice:
		if len(pubkey) != newhope.SendBSimpleSize {
			panic("noise/hfs: pubkey is not SendBSimpleSize")
		}
		var bobPk newhope.PublicKeySimpleBob
		copy(bobPk.Send[:], pubkey[:])

		s, err := newhope.KeyExchangeSimpleAlice(&bobPk, k.privKey)
		if err != nil {
			panic("noise/hfs: newhope.KeyExchangeSimpleAlice(): " + err.Error())
		}
		return s
	case *keyNewHopeSimpleBob:
		return k.shared
	default:
	}
	panic("noise/fs: FF(): unsupported keypair type")
}

func (hfsNewHopeSimple) FLen1() int {
	return newhope.SendASimpleSize
}

func (hfsNewHopeSimple) FLen2() int {
	return newhope.SendBSimpleSize
}

func (hfsNewHopeSimple) FLen() int {
	return newhope.SharedSecretSize
}

func (hfsNewHopeSimple) HFSName() string {
	return "NewHopeSimple"
}

var hfsNull HFSFunc = hfsNullImpl{}

type hfsNullImpl struct{}

func (hfsNullImpl) GenerateKeypairF(r io.Reader, rf []byte) HFSKey {
	panic("noise/hfs: GenerateKeypairF called for null HFS")
}

func (hfsNullImpl) FF(keypair HFSKey, pubkey []byte) []byte {
	panic("noise/hfs: FF called for null HFS")
}

func (hfsNullImpl) FLen1() int {
	return 0
}

func (hfsNullImpl) FLen2() int {
	return 0
}

func (hfsNullImpl) FLen() int {
	return 0
}

func (hfsNullImpl) HFSName() string {
	return "(null)"
}
