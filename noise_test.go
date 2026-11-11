package noise

import (
	"bytes"
	"encoding/hex"
	"math"
	"testing"

	"github.com/stretchr/testify/require"
)

type RandomInc byte

func (r *RandomInc) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = byte(*r)
		*r = (*r) + 1
	}
	return len(p), nil
}

func TestN(t *testing.T) {
	cs := NewCipherSuite(DH25519, CipherAESGCM, HashSHA256)
	rng := new(RandomInc)
	staticR, _ := cs.GenerateKeypair(rng)
	hs, _ := NewHandshakeState(Config{
		CipherSuite: cs,
		Random:      rng,
		Pattern:     HandshakeN,
		Initiator:   true,
		PeerStatic:  staticR.Public,
	})

	hello, _, _, _ := hs.WriteMessage(nil, nil)
	expected, _ := hex.DecodeString("358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd1662548331a3d1e93b490263abc7a4633867f4")
	require.Equal(t, expected, hello)
}

func TestX(t *testing.T) {
	cs := NewCipherSuite(DH25519, CipherChaChaPoly, HashSHA256)
	rng := new(RandomInc)
	staticI, _ := cs.GenerateKeypair(rng)
	staticR, _ := cs.GenerateKeypair(rng)
	hs, _ := NewHandshakeState(Config{
		CipherSuite:   cs,
		Random:        rng,
		Pattern:       HandshakeX,
		Initiator:     true,
		StaticKeypair: staticI,
		PeerStatic:    staticR.Public,
	})

	hello, _, _, _ := hs.WriteMessage(nil, nil)
	expected, _ := hex.DecodeString("79a631eede1bf9c98f12032cdeadd0e7a079398fc786b88cc846ec89af85a51ad203cd28d81cf65a2da637f557a05728b3ae4abdc3a42d1cda5f719d6cf41d7f2cf1b1c5af10e38a09a9bb7e3b1d589a99492cc50293eaa1f3f391b59bb6990d")
	require.Equal(t, expected, hello)
}

func TestNN(t *testing.T) {
	cs := NewCipherSuite(DH25519, CipherAESGCM, HashSHA512)
	rngI := new(RandomInc)
	rngR := new(RandomInc)
	*rngR = 1

	hsI, _ := NewHandshakeState(Config{
		CipherSuite: cs,
		Random:      rngI,
		Pattern:     HandshakeNN,
		Initiator:   true,
	})
	hsR, _ := NewHandshakeState(Config{
		CipherSuite: cs,
		Random:      rngR,
		Pattern:     HandshakeNN,
		Initiator:   false,
	})

	msg, _, _, _ := hsI.WriteMessage(nil, []byte("abc"))
	require.Len(t, msg, 35)
	res, _, _, err := hsR.ReadMessage(nil, msg)
	require.NoError(t, err)
	require.Equal(t, "abc", string(res))

	msg, _, _, _ = hsR.WriteMessage(nil, []byte("defg"))
	require.Len(t, msg, 52)
	res, _, _, err = hsI.ReadMessage(nil, msg)
	require.NoError(t, err)
	require.Equal(t, "defg", string(res))

	expected, _ := hex.DecodeString("07a37cbc142093c8b755dc1b10e86cb426374ad16aa853ed0bdfc0b2b86d1c7c5e4dc9545d41b3280f4586a5481829e1e24ec5a0")
	require.Equal(t, expected, msg)
}

func TestXX(t *testing.T) {
	cs := NewCipherSuite(DH25519, CipherAESGCM, HashSHA256)
	rngI := new(RandomInc)
	rngR := new(RandomInc)
	*rngR = 1

	staticI, _ := cs.GenerateKeypair(rngI)
	staticR, _ := cs.GenerateKeypair(rngR)

	hsI, _ := NewHandshakeState(Config{
		CipherSuite:   cs,
		Random:        rngI,
		Pattern:       HandshakeXX,
		Initiator:     true,
		StaticKeypair: staticI,
	})
	hsR, _ := NewHandshakeState(Config{
		CipherSuite:   cs,
		Random:        rngR,
		Pattern:       HandshakeXX,
		StaticKeypair: staticR,
	})

	msg, _, _, _ := hsI.WriteMessage(nil, []byte("abc"))
	require.Len(t, msg, 35)
	res, _, _, err := hsR.ReadMessage(nil, msg)
	require.NoError(t, err)
	require.Equal(t, "abc", string(res))

	msg, _, _, _ = hsR.WriteMessage(nil, []byte("defg"))
	require.Len(t, msg, 100)
	res, _, _, err = hsI.ReadMessage(nil, msg)
	require.NoError(t, err)
	require.Equal(t, "defg", string(res))

	msg, _, _, _ = hsI.WriteMessage(nil, nil)
	require.Len(t, msg, 64)
	res, _, _, err = hsR.ReadMessage(nil, msg)
	require.NoError(t, err)
	require.Len(t, res, 0)

	expected, _ := hex.DecodeString("8127f4b35cdbdf0935fcf1ec99016d1dcbc350055b8af360be196905dfb50a2c1c38a7ca9cb0cfe8f4576f36c47a4933eee32288f590ac4305d4b53187577be7")
	require.Equal(t, expected, msg)
}

func TestIK(t *testing.T) {
	cs := NewCipherSuite(DH25519, CipherAESGCM, HashSHA256)
	rngI := new(RandomInc)
	rngR := new(RandomInc)
	*rngR = 1

	staticI, _ := cs.GenerateKeypair(rngI)
	staticR, _ := cs.GenerateKeypair(rngR)

	hsI, _ := NewHandshakeState(Config{
		CipherSuite:   cs,
		Random:        rngI,
		Pattern:       HandshakeIK,
		Initiator:     true,
		Prologue:      []byte("ABC"),
		StaticKeypair: staticI,
		PeerStatic:    staticR.Public,
	})
	hsR, _ := NewHandshakeState(Config{
		CipherSuite:   cs,
		Random:        rngR,
		Pattern:       HandshakeIK,
		Prologue:      []byte("ABC"),
		StaticKeypair: staticR,
	})

	msg, _, _, _ := hsI.WriteMessage(nil, []byte("abc"))
	require.Len(t, msg, 99)
	res, _, _, err := hsR.ReadMessage(nil, msg)
	require.NoError(t, err)
	require.Equal(t, "abc", string(res))

	msg, _, _, _ = hsR.WriteMessage(nil, []byte("defg"))
	require.Len(t, msg, 52)
	res, _, _, err = hsI.ReadMessage(nil, msg)
	require.NoError(t, err)
	require.Equal(t, "defg", string(res))

	expected, _ := hex.DecodeString("5869aff450549732cbaaed5e5df9b30a6da31cb0e5742bad5ad4a1a768f1a67b7555a94199d0ce2972e0861b06c2152419a278de")
	require.Equal(t, expected, msg)
}

func TestXXRoundtrip(t *testing.T) {
	cs := NewCipherSuite(DH25519, CipherAESGCM, HashSHA256)
	rngI := new(RandomInc)
	rngR := new(RandomInc)
	*rngR = 1

	staticI, _ := cs.GenerateKeypair(rngI)
	staticR, _ := cs.GenerateKeypair(rngR)

	hsI, _ := NewHandshakeState(Config{
		CipherSuite:   cs,
		Random:        rngI,
		Pattern:       HandshakeXX,
		Initiator:     true,
		StaticKeypair: staticI,
	})
	hsR, _ := NewHandshakeState(Config{
		CipherSuite:   cs,
		Random:        rngR,
		Pattern:       HandshakeXX,
		StaticKeypair: staticR,
	})

	// -> e
	msg, _, _, _ := hsI.WriteMessage(nil, []byte("abcdef"))
	require.Len(t, msg, 38)
	res, _, _, err := hsR.ReadMessage(nil, msg)
	require.NoError(t, err)
	require.Equal(t, "abcdef", string(res))

	// <- e, dhee, s, dhse
	msg, _, _, _ = hsR.WriteMessage(nil, nil)
	require.Len(t, msg, 96)
	res, _, _, err = hsI.ReadMessage(nil, msg)
	require.NoError(t, err)
	require.Len(t, res, 0)

	// -> s, dhse
	payload := "0123456789012345678901234567890123456789012345678901234567890123456789"
	msg, csI0, csI1, _ := hsI.WriteMessage(nil, []byte(payload))
	require.Len(t, msg, 134)
	res, csR0, csR1, err := hsR.ReadMessage(nil, msg)
	require.NoError(t, err)
	require.Equal(t, payload, string(res))

	// transport message I -> R
	msg, err = csI0.Encrypt(nil, nil, []byte("wubba"))
	require.NoError(t, err)
	res, err = csR0.Decrypt(nil, nil, msg)
	require.NoError(t, err)
	require.Equal(t, "wubba", string(res))

	// transport message I -> R again
	msg, err = csI0.Encrypt(nil, nil, []byte("aleph"))
	require.NoError(t, err)
	res, err = csR0.Decrypt(nil, nil, msg)
	require.NoError(t, err)
	require.Equal(t, "aleph", string(res))

	// transport message R <- I
	msg, err = csR1.Encrypt(nil, nil, []byte("worri"))
	require.NoError(t, err)
	res, err = csI1.Decrypt(nil, nil, msg)
	require.NoError(t, err)
	require.Equal(t, "worri", string(res))
}

func Test_IXpsk2_Roundtrip(t *testing.T) {
	cs := NewCipherSuite(DH25519, CipherAESGCM, HashSHA256)
	rngI := new(RandomInc)
	rngR := new(RandomInc)
	*rngR = 1

	staticI, err := cs.GenerateKeypair(rngI)
	if err != nil {
		t.Fatal(err)
	}
	staticR, err := cs.GenerateKeypair(rngR)
	if err != nil {
		t.Fatal(err)
	}

	psk := []byte("00000000000000000000000000000000")

	hsI, _ := NewHandshakeState(Config{
		CipherSuite:           cs,
		Random:                rngI,
		Pattern:               HandshakeIX,
		PresharedKeyPlacement: 2,
		PresharedKey:          psk,
		Initiator:             true,
		StaticKeypair:         staticI,
	})
	hsR, _ := NewHandshakeState(Config{
		CipherSuite:           cs,
		Random:                rngR,
		Pattern:               HandshakeIX,
		PresharedKeyPlacement: 2,
		StaticKeypair:         staticR,
	})

	// -> e, s
	msg, _, _, _ := hsI.WriteMessage(nil, nil)
	require.Len(t, msg, 96)

	res, _, _, err := hsR.ReadMessage(nil, msg)
	require.NoError(t, err)
	require.Len(t, res, 0)

	if !bytes.Equal(hsR.PeerStatic(), staticI.Public) {
		t.Error("wrong public key from peer")
	}

	// Look up psk from peer static public key

	// responder should know psk now and set it from the
	// initiators preshared key
	if err = hsR.SetPresharedKey(psk); err != nil {
		t.Fatal(err)
	}
	// <- e, dhee, dhse, s, dhes, psk
	msg, csR0, csR1, _ := hsR.WriteMessage(nil, nil)
	require.Len(t, msg, 96)
	res, csI0, csI1, err := hsI.ReadMessage(nil, msg)
	require.NoError(t, err)
	require.Len(t, res, 0)

	// transport I -> R
	msg, err = csI0.Encrypt(nil, nil, []byte("foo"))
	require.NoError(t, err)
	res, err = csR0.Decrypt(nil, nil, msg)
	require.NoError(t, err)
	require.Equal(t, "foo", string(res))

	// transport R -> I
	msg, err = csR1.Encrypt(nil, nil, []byte("bar"))
	require.NoError(t, err)
	res, err = csI1.Decrypt(nil, nil, msg)
	require.NoError(t, err)
	require.Equal(t, "bar", string(res))
}

func Test_NNpsk0_Roundtrip(t *testing.T) {
	cs := NewCipherSuite(DH25519, CipherChaChaPoly, HashBLAKE2b)
	rngI := new(RandomInc)
	rngR := new(RandomInc)
	*rngR = 1

	hsI, _ := NewHandshakeState(Config{
		CipherSuite:  cs,
		Random:       rngI,
		Pattern:      HandshakeNN,
		Initiator:    true,
		PresharedKey: []byte("supersecretsupersecretsupersecre"),
	})
	hsR, _ := NewHandshakeState(Config{
		CipherSuite:  cs,
		Random:       rngR,
		Pattern:      HandshakeNN,
		PresharedKey: []byte("supersecretsupersecretsupersecre"),
	})

	// -> e
	msg, _, _, _ := hsI.WriteMessage(nil, nil)
	require.Len(t, msg, 48)
	res, _, _, err := hsR.ReadMessage(nil, msg)
	require.NoError(t, err)
	require.Len(t, res, 0)

	// <- e, dhee
	msg, csR0, csR1, _ := hsR.WriteMessage(nil, nil)
	require.Len(t, msg, 48)
	res, csI0, csI1, err := hsI.ReadMessage(nil, msg)
	require.NoError(t, err)
	require.Len(t, res, 0)

	// transport I -> R
	msg, err = csI0.Encrypt(nil, nil, []byte("foo"))
	require.NoError(t, err)
	res, err = csR0.Decrypt(nil, nil, msg)
	require.NoError(t, err)
	require.Equal(t, "foo", string(res))

	// transport R -> I
	msg, err = csR1.Encrypt(nil, nil, []byte("bar"))
	require.NoError(t, err)
	res, err = csI1.Decrypt(nil, nil, msg)
	require.NoError(t, err)
	require.Equal(t, "bar", string(res))
}

func Test_Npsk0(t *testing.T) {
	cs := NewCipherSuite(DH25519, CipherAESGCM, HashSHA256)
	rng := new(RandomInc)
	staticR, _ := cs.GenerateKeypair(rng)

	hsI, _ := NewHandshakeState(Config{
		CipherSuite:  cs,
		Random:       rng,
		Pattern:      HandshakeN,
		Initiator:    true,
		PresharedKey: []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20},
		PeerStatic:   staticR.Public,
	})

	msg, _, _, _ := hsI.WriteMessage(nil, nil)
	require.Len(t, msg, 48)

	expected, _ := hex.DecodeString("358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd1662542044ae563929068930dcf04674526cb9")
	require.Equal(t, expected, msg)
}

func Test_Xpsk0(t *testing.T) {
	cs := NewCipherSuite(DH25519, CipherChaChaPoly, HashSHA256)
	rng := new(RandomInc)
	staticI, _ := cs.GenerateKeypair(rng)
	staticR, _ := cs.GenerateKeypair(rng)

	hs, _ := NewHandshakeState(Config{
		CipherSuite:   cs,
		Random:        rng,
		Pattern:       HandshakeX,
		Initiator:     true,
		PresharedKey:  []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20},
		StaticKeypair: staticI,
		PeerStatic:    staticR.Public,
	})
	msg, _, _, _ := hs.WriteMessage(nil, nil)
	require.Len(t, msg, 96)

	expected, _ := hex.DecodeString("79a631eede1bf9c98f12032cdeadd0e7a079398fc786b88cc846ec89af85a51ad51eef529db0dd9127d4aa59a9183e118337d75a4e55e7e00f85c3d20ede536dd0112eec8c3b2a514018a90ab685b027dd24aa0c70b0c0f00524cc23785028b9")
	require.Equal(t, expected, msg)
}

func Test_NNpsk0(t *testing.T) {
	cs := NewCipherSuite(DH25519, CipherAESGCM, HashSHA512)
	rngI := new(RandomInc)
	rngR := new(RandomInc)
	*rngR = 1
	prologue := []byte{0x01, 0x02, 0x03}
	psk := []byte{0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23}

	hsI, _ := NewHandshakeState(Config{
		CipherSuite:  cs,
		Random:       rngI,
		Pattern:      HandshakeNN,
		Initiator:    true,
		Prologue:     prologue,
		PresharedKey: psk,
	})
	hsR, _ := NewHandshakeState(Config{
		CipherSuite:  cs,
		Random:       rngR,
		Pattern:      HandshakeNN,
		Prologue:     prologue,
		PresharedKey: psk,
	})

	msg, _, _, _ := hsI.WriteMessage(nil, []byte("abc"))
	require.Len(t, msg, 51)
	res, _, _, err := hsR.ReadMessage(nil, msg)
	require.NoError(t, err)
	require.Equal(t, "abc", string(res))

	msg, _, _, _ = hsR.WriteMessage(nil, []byte("defg"))
	require.Len(t, msg, 52)
	res, _, _, err = hsI.ReadMessage(nil, msg)
	require.NoError(t, err)
	require.Equal(t, "defg", string(res))

	expected, _ := hex.DecodeString("07a37cbc142093c8b755dc1b10e86cb426374ad16aa853ed0bdfc0b2b86d1c7c3e42e140cfffbcdf5d9d2a1c24ce4cdbdf1eaf37")
	require.Equal(t, expected, msg)
}

func Test_XXpsk0(t *testing.T) {
	cs := NewCipherSuite(DH25519, CipherAESGCM, HashSHA256)
	rngI := new(RandomInc)
	rngR := new(RandomInc)
	*rngR = 1

	staticI, _ := cs.GenerateKeypair(rngI)
	staticR, _ := cs.GenerateKeypair(rngR)
	prologue := []byte{0x01, 0x02, 0x03}
	psk := []byte{0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23}

	hsI, _ := NewHandshakeState(Config{
		CipherSuite:   cs,
		Random:        rngI,
		Pattern:       HandshakeXX,
		Initiator:     true,
		Prologue:      prologue,
		PresharedKey:  psk,
		StaticKeypair: staticI,
	})
	hsR, _ := NewHandshakeState(Config{
		CipherSuite:   cs,
		Random:        rngR,
		Pattern:       HandshakeXX,
		Prologue:      prologue,
		PresharedKey:  psk,
		StaticKeypair: staticR,
	})

	msg, _, _, _ := hsI.WriteMessage(nil, []byte("abc"))
	require.Len(t, msg, 51)
	res, _, _, err := hsR.ReadMessage(nil, msg)
	require.NoError(t, err)
	require.Equal(t, "abc", string(res))

	msg, _, _, _ = hsR.WriteMessage(nil, []byte("defg"))
	require.Len(t, msg, 100)
	res, _, _, err = hsI.ReadMessage(nil, msg)
	require.NoError(t, err)
	require.Equal(t, "defg", string(res))

	msg, _, _, _ = hsI.WriteMessage(nil, nil)
	require.Len(t, msg, 64)
	res, _, _, err = hsR.ReadMessage(nil, msg)
	require.NoError(t, err)
	require.Len(t, res, 0)

	expected, _ := hex.DecodeString("1b6d7cc3b13bd02217f9cdb98c50870db96281193dca4df570bf6230a603b686fd90d2914c7e797d9276ef8fb34b0c9d87faa048ce4bc7e7af21b6a450352275")
	require.Equal(t, expected, msg)
}

func TestHandshakeRollback(t *testing.T) {
	cs := NewCipherSuite(DH25519, CipherAESGCM, HashSHA512)
	rngI := new(RandomInc)
	rngR := new(RandomInc)
	*rngR = 1

	hsI, _ := NewHandshakeState(Config{
		CipherSuite: cs,
		Random:      rngI,
		Pattern:     HandshakeNN,
		Initiator:   true,
	})
	hsR, _ := NewHandshakeState(Config{
		CipherSuite: cs,
		Random:      rngR,
		Pattern:     HandshakeNN,
		Initiator:   false,
	})

	msg, _, _, _ := hsI.WriteMessage(nil, []byte("abc"))
	require.Len(t, msg, 35)
	res, _, _, err := hsR.ReadMessage(nil, msg)
	require.NoError(t, err)
	require.Equal(t, "abc", string(res))

	msg, _, _, _ = hsR.WriteMessage(nil, []byte("defg"))
	require.Len(t, msg, 52)
	prev := msg[1]
	msg[1] = msg[1] + 1
	_, _, _, err = hsI.ReadMessage(nil, msg)
	require.Error(t, err)
	msg[1] = prev
	res, _, _, err = hsI.ReadMessage(nil, msg)
	require.NoError(t, err)
	require.Equal(t, "defg", string(res))

	expected, _ := hex.DecodeString("07a37cbc142093c8b755dc1b10e86cb426374ad16aa853ed0bdfc0b2b86d1c7c5e4dc9545d41b3280f4586a5481829e1e24ec5a0")
	require.Equal(t, expected, msg)
}

func TestHandshakeRollback_rs(t *testing.T) {
	cs := NewCipherSuite(DH25519, CipherAESGCM, HashSHA512)
	rngI := new(RandomInc)
	rngR := new(RandomInc)

	staticI, _ := cs.GenerateKeypair(rngI)
	staticR, _ := cs.GenerateKeypair(rngR)

	*rngR = 1

	hsI, _ := NewHandshakeState(Config{
		CipherSuite:   cs,
		Random:        rngI,
		Pattern:       HandshakeIX,
		Initiator:     true,
		StaticKeypair: staticI,
	})
	hsR, _ := NewHandshakeState(Config{
		CipherSuite:   cs,
		Random:        rngR,
		Pattern:       HandshakeIX,
		Initiator:     false,
		StaticKeypair: staticR,
	})

	msg, _, _, _ := hsI.WriteMessage(nil, []byte("abc"))
	require.Len(t, msg, 67)
	res, _, _, err := hsR.ReadMessage(nil, msg)
	require.NoError(t, err)
	require.Equal(t, "abc", string(res))

	msg, _, _, _ = hsR.WriteMessage(nil, []byte("defg"))
	require.Len(t, msg, 100)
	prev := msg[1]
	msg[1] = msg[1] + 1
	_, _, _, err = hsI.ReadMessage(nil, msg)
	require.Error(t, err)
	msg[1] = prev
	res, _, _, err = hsI.ReadMessage(nil, msg)
	require.NoError(t, err)
	require.Equal(t, "defg", string(res))

	expected, _ := hex.DecodeString("07a37cbc142093c8b755dc1b10e86cb426374ad16aa853ed0bdfc0b2b86d1c7cf66fc41515606de81af64a5364fbc0b2cbd71e0837ea590b72b77ae2caaaa93bc19c167c28236a18e0737d395fe95083e41da26a30a8062faf92ed05bbdc36db2369f19b")
	require.Equal(t, expected, msg)
}

func TestSetNonce(t *testing.T) {
	cs := NewCipherSuite(DH25519, CipherAESGCM, HashSHA512)
	rngI := new(RandomInc)
	rngR := new(RandomInc)
	*rngR = 1

	hsI, _ := NewHandshakeState(Config{
		CipherSuite: cs,
		Random:      rngI,
		Pattern:     HandshakeNN,
		Initiator:   true,
	})
	hsR, _ := NewHandshakeState(Config{
		CipherSuite: cs,
		Random:      rngR,
		Pattern:     HandshakeNN,
		Initiator:   false,
	})

	msg, _, _, _ := hsI.WriteMessage(nil, nil)
	res, _, _, err := hsR.ReadMessage(nil, msg)
	require.NoError(t, err)
	require.Len(t, res, 0)

	msg, csR0, csR1, _ := hsR.WriteMessage(nil, nil)
	res, csI0, csI1, err := hsI.ReadMessage(nil, msg)
	require.NoError(t, err)
	require.Len(t, res, 0)

	require.Equal(t, uint64(0), csI0.Nonce())
	require.Equal(t, uint64(0), csI1.Nonce())
	require.Equal(t, uint64(0), csR0.Nonce())
	require.Equal(t, uint64(0), csR1.Nonce())

	const n = 1234
	clientMessage := []byte("msg1")
	csI0.SetNonce(n)
	msg, err = csI0.Encrypt(nil, nil, clientMessage)
	require.NoError(t, err)
	// decrypt with incorrect nonce
	_, err = csR0.Decrypt(nil, nil, msg)
	require.Error(t, err)
	// decrypt with correct nonce
	csR0.SetNonce(n)
	res, err = csR0.Decrypt(nil, nil, msg)
	require.NoError(t, err)
	require.Equal(t, string(res), string(clientMessage))

	require.Equal(t, uint64(n+1), csI0.Nonce())
	require.Equal(t, uint64(0), csI1.Nonce())
	require.Equal(t, uint64(n+1), csR0.Nonce())
	require.Equal(t, uint64(0), csR1.Nonce())

	serverMessage := []byte("msg2")
	csR1.SetNonce(MaxNonce + 1)
	_, err = csR1.Encrypt(nil, nil, serverMessage)
	require.ErrorIs(t, err, ErrMaxNonce)
}

func TestRekey(t *testing.T) {
	rng := new(RandomInc)

	clientStaticKeypair, _ := DH25519.GenerateKeypair(rng)
	clientConfig := Config{}
	clientConfig.CipherSuite = NewCipherSuite(DH25519, CipherChaChaPoly, HashBLAKE2b)
	clientConfig.Random = rng
	clientConfig.Pattern = HandshakeNN
	clientConfig.Initiator = true
	clientConfig.Prologue = []byte{0}
	clientConfig.StaticKeypair = clientStaticKeypair
	clientConfig.EphemeralKeypair, _ = DH25519.GenerateKeypair(rng)
	clientHs, _ := NewHandshakeState(clientConfig)

	serverStaticKeypair, _ := DH25519.GenerateKeypair(rng)
	serverConfig := Config{}
	serverConfig.CipherSuite = NewCipherSuite(DH25519, CipherChaChaPoly, HashBLAKE2b)
	serverConfig.Random = rng
	serverConfig.Pattern = HandshakeNN
	serverConfig.Initiator = false
	serverConfig.Prologue = []byte{0}
	serverConfig.StaticKeypair = serverStaticKeypair
	serverConfig.EphemeralKeypair, _ = DH25519.GenerateKeypair(rng)
	serverHs, _ := NewHandshakeState(serverConfig)

	clientHsMsg, _, _, _ := clientHs.WriteMessage(nil, nil)
	require.Len(t, clientHsMsg, 32)

	serverHsResult, _, _, err := serverHs.ReadMessage(nil, clientHsMsg)
	require.NoError(t, err)
	require.Len(t, serverHsResult, 0)

	serverHsMsg, csR0, csR1, _ := serverHs.WriteMessage(nil, nil)
	require.Len(t, serverHsMsg, 48)

	clientHsResult, csI0, csI1, err := clientHs.ReadMessage(nil, serverHsMsg)
	require.NoError(t, err)
	require.Len(t, clientHsResult, 0)

	clientMessage := []byte("hello")
	msg, err := csI0.Encrypt(nil, nil, clientMessage)
	require.NoError(t, err)
	res, err := csR0.Decrypt(nil, nil, msg)
	require.NoError(t, err)
	require.Equal(t, string(res), string(clientMessage))

	oldK := csI0.k
	csI0.Rekey()
	require.NotEqual(t, csI0.k, oldK)
	csR0.Rekey()

	clientMessage = []byte("hello again")
	msg, err = csI0.Encrypt(nil, nil, clientMessage)
	require.NoError(t, err)
	res, err = csR0.Decrypt(nil, nil, msg)
	require.NoError(t, err)
	require.Equal(t, string(res), string(clientMessage))

	serverMessage := []byte("bye")
	msg, err = csR1.Encrypt(nil, nil, serverMessage)
	require.NoError(t, err)
	res, err = csI1.Decrypt(nil, nil, msg)
	require.NoError(t, err)
	require.Equal(t, string(res), string(serverMessage))

	preNonce := csR1.Nonce()

	csR1.Rekey()
	csI1.Rekey()

	postNonce := csR1.Nonce()
	require.Equal(t, postNonce, preNonce)

	serverMessage = []byte("bye bye")
	msg, err = csR1.Encrypt(nil, nil, serverMessage)
	require.NoError(t, err)
	res, err = csI1.Decrypt(nil, nil, msg)
	require.NoError(t, err)
	require.Equal(t, string(res), string(serverMessage))

	// only rekey one side, test for failure
	csR1.Rekey()
	serverMessage = []byte("bye again")
	msg, err = csR1.Encrypt(nil, nil, serverMessage)
	require.NoError(t, err)
	res, err = csI1.Decrypt(nil, nil, msg)
	require.Error(t, err)
	require.NotEqual(t, string(res), string(serverMessage))

	// check nonce overflow handling
	csI1.n = math.MaxUint64
	msg, err = csI1.Encrypt(nil, nil, nil)
	require.ErrorIs(t, err, ErrMaxNonce)
	require.Nil(t, msg)
	msg, err = csI1.Decrypt(nil, nil, nil)
	require.ErrorIs(t, err, ErrMaxNonce)
	require.Nil(t, msg)
}
