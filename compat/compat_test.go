package compat

import (
	"bytes"
	"crypto/rand"
	"testing"

	sbox "github.com/stouset/go.noise/box"
	scipher "github.com/stouset/go.noise/ciphersuite"
	"github.com/titanous/noise/box"
)

var plaintext = []byte("yellow submarine")

func TestStousetSendBox(t *testing.T) {
	senderKey := scipher.Noise255.NewKeypair()
	receiverKey, _ := box.Noise255.GenerateKey(rand.Reader)

	sc := sbox.NewContext(scipher.Noise255, senderKey, 0)
	sc.Init(scipher.PublicKey(receiverKey.Public))

	ciphertext := sc.Shut(plaintext, 0, 5)

	dc := &box.Crypter{
		Cipher:  box.Noise255,
		Key:     receiverKey,
		PeerKey: box.Key{Public: []byte(senderKey.Public)},
	}
	if expected := dc.BoxLen(len(plaintext) + 5); len(ciphertext) != expected {
		t.Errorf("expected box length to be %d, got %d", expected, len(ciphertext))
	}

	result, err := dc.DecryptBox(ciphertext, 0)
	if err != nil {
		t.Error("error decrypting:", err)
	}
	if !bytes.Equal(plaintext, result) {
		t.Errorf("expected %q, got %q", plaintext, result)
	}
}
