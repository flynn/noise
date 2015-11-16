package noise

import (
	"encoding/hex"
	"testing"

	. "gopkg.in/check.v1"
)

func Test(t *testing.T) { TestingT(t) }

type NoiseSuite struct{}

var _ = Suite(&NoiseSuite{})

type RandomInc byte

func (r *RandomInc) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = byte(*r)
		*r = (*r) + 1
	}
	return len(p), nil
}

func (NoiseSuite) TestN(c *C) {
	cs := NewCipherSuite(DH25519, CipherAESGCM, HashSHA256)
	rng := new(RandomInc)
	staticR := cs.GenerateKeypair(rng)
	hs := NewHandshakeState(Config{CipherSuite: cs, Random: rng, Pattern: HandshakeN, Initiator: true, PeerStatic: staticR.Public})

	hello, _, _ := hs.WriteMessage(nil, nil)
	expected, _ := hex.DecodeString("358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd1662548331a3d1e93b490263abc7a4633867f4")
	c.Assert(hello, DeepEquals, expected)
}

func (NoiseSuite) TestX(c *C) {
	cs := NewCipherSuite(DH25519, CipherChaChaPoly, HashSHA256)
	rng := new(RandomInc)
	staticI := cs.GenerateKeypair(rng)
	staticR := cs.GenerateKeypair(rng)
	hs := NewHandshakeState(Config{CipherSuite: cs, Random: rng, Pattern: HandshakeX, Initiator: true, StaticKeypair: staticI, PeerStatic: staticR.Public})

	hello, _, _ := hs.WriteMessage(nil, nil)
	expected, _ := hex.DecodeString("79a631eede1bf9c98f12032cdeadd0e7a079398fc786b88cc846ec89af85a51ad203cd28d81cf65a2da637f557a05728b3ae4abdc3a42d1cda5f719d6cf41d7f2cf1b1c5af10e38a09a9bb7e3b1d589a99492cc50293eaa1f3f391b59bb6990d")
	c.Assert(hello, DeepEquals, expected)
}

func (NoiseSuite) TestNN(c *C) {
	cs := NewCipherSuite(DH25519, CipherAESGCM, HashSHA512)
	rngI := new(RandomInc)
	rngR := new(RandomInc)
	*rngR = 1

	hsI := NewHandshakeState(Config{CipherSuite: cs, Random: rngI, Pattern: HandshakeNN, Initiator: true})
	hsR := NewHandshakeState(Config{CipherSuite: cs, Random: rngR, Pattern: HandshakeNN, Initiator: false})

	msg, _, _ := hsI.WriteMessage(nil, []byte("abc"))
	c.Assert(msg, HasLen, 35)
	res, _, _, err := hsR.ReadMessage(nil, msg)
	c.Assert(err, IsNil)
	c.Assert(string(res), Equals, "abc")

	msg, _, _ = hsR.WriteMessage(nil, []byte("defg"))
	c.Assert(msg, HasLen, 52)
	res, _, _, err = hsI.ReadMessage(nil, msg)
	c.Assert(err, IsNil)
	c.Assert(string(res), Equals, "defg")

	expected, _ := hex.DecodeString("07a37cbc142093c8b755dc1b10e86cb426374ad16aa853ed0bdfc0b2b86d1c7c5e4dc9545d41b3280f4586a5481829e1e24ec5a0")
	c.Assert(msg, DeepEquals, expected)
}

func (NoiseSuite) TestXX(c *C) {
	cs := NewCipherSuite(DH25519, CipherAESGCM, HashSHA256)
	rngI := new(RandomInc)
	rngR := new(RandomInc)
	*rngR = 1

	staticI := cs.GenerateKeypair(rngI)
	staticR := cs.GenerateKeypair(rngR)

	hsI := NewHandshakeState(Config{CipherSuite: cs, Random: rngI, Pattern: HandshakeXX, Initiator: true, StaticKeypair: staticI})
	hsR := NewHandshakeState(Config{CipherSuite: cs, Random: rngR, Pattern: HandshakeXX, StaticKeypair: staticR})

	msg, _, _ := hsI.WriteMessage(nil, []byte("abc"))
	c.Assert(msg, HasLen, 35)
	res, _, _, err := hsR.ReadMessage(nil, msg)
	c.Assert(err, IsNil)
	c.Assert(string(res), Equals, "abc")

	msg, _, _ = hsR.WriteMessage(nil, []byte("defg"))
	c.Assert(msg, HasLen, 100)
	res, _, _, err = hsI.ReadMessage(nil, msg)
	c.Assert(err, IsNil)
	c.Assert(string(res), Equals, "defg")

	msg, _, _ = hsI.WriteMessage(nil, nil)
	c.Assert(msg, HasLen, 64)
	res, _, _, err = hsR.ReadMessage(nil, msg)
	c.Assert(err, IsNil)
	c.Assert(res, HasLen, 0)

	expected, _ := hex.DecodeString("8127f4b35cdbdf0935fcf1ec99016d1dcbc350055b8af360be196905dfb50a2c1c38a7ca9cb0cfe8f4576f36c47a4933eee32288f590ac4305d4b53187577be7")
	c.Assert(msg, DeepEquals, expected)
}

func (NoiseSuite) TestIK(c *C) {
	cs := NewCipherSuite(DH25519, CipherAESGCM, HashSHA256)
	rngI := new(RandomInc)
	rngR := new(RandomInc)
	*rngR = 1

	staticI := cs.GenerateKeypair(rngI)
	staticR := cs.GenerateKeypair(rngR)

	hsI := NewHandshakeState(Config{CipherSuite: cs, Random: rngI, Pattern: HandshakeIK, Initiator: true, Prologue: []byte("ABC"), StaticKeypair: staticI, PeerStatic: staticR.Public})
	hsR := NewHandshakeState(Config{CipherSuite: cs, Random: rngR, Pattern: HandshakeIK, Prologue: []byte("ABC"), StaticKeypair: staticR})

	msg, _, _ := hsI.WriteMessage(nil, []byte("abc"))
	c.Assert(msg, HasLen, 99)
	res, _, _, err := hsR.ReadMessage(nil, msg)
	c.Assert(err, IsNil)
	c.Assert(string(res), Equals, "abc")

	msg, _, _ = hsR.WriteMessage(nil, []byte("defg"))
	c.Assert(msg, HasLen, 52)
	res, _, _, err = hsI.ReadMessage(nil, msg)
	c.Assert(err, IsNil)
	c.Assert(string(res), Equals, "defg")

	expected, _ := hex.DecodeString("5869aff450549732cbaaed5e5df9b30a6da31cb0e5742bad5ad4a1a768f1a67b7555a94199d0ce2972e0861b06c2152419a278de")
	c.Assert(msg, DeepEquals, expected)
}

func (NoiseSuite) TestXE(c *C) {
	cs := NewCipherSuite(DH25519, CipherChaChaPoly, HashBLAKE2b)
	rngI := new(RandomInc)
	rngR := new(RandomInc)
	*rngR = 1

	staticI := cs.GenerateKeypair(rngI)
	staticR := cs.GenerateKeypair(rngR)
	ephR := cs.GenerateKeypair(rngR)

	hsI := NewHandshakeState(Config{CipherSuite: cs, Random: rngI, Pattern: HandshakeXE, Initiator: true, StaticKeypair: staticI, PeerStatic: staticR.Public, PeerEphemeral: ephR.Public})
	hsR := NewHandshakeState(Config{CipherSuite: cs, Random: rngR, Pattern: HandshakeXE, StaticKeypair: staticR, EphemeralKeypair: ephR})

	msg, _, _ := hsI.WriteMessage(nil, []byte("abc"))
	c.Assert(msg, HasLen, 51)
	res, _, _, err := hsR.ReadMessage(nil, msg)
	c.Assert(err, IsNil)
	c.Assert(string(res), Equals, "abc")

	msg, _, _ = hsR.WriteMessage(nil, []byte("defg"))
	c.Assert(msg, HasLen, 52)
	res, _, _, err = hsI.ReadMessage(nil, msg)
	c.Assert(err, IsNil)
	c.Assert(string(res), Equals, "defg")

	msg, _, _ = hsI.WriteMessage(nil, nil)
	c.Assert(msg, HasLen, 64)
	res, _, _, err = hsR.ReadMessage(nil, msg)
	c.Assert(err, IsNil)
	c.Assert(res, HasLen, 0)

	expected, _ := hex.DecodeString("08439f380b6f128a1465840d558f06abb1141cf5708a9dcf573d6e4fae01f90fd68dec89b26b249f2c4c61add5a1dbcf0a652ef015d7dbe0e80e9ea9af0aa7a2")
	c.Assert(msg, DeepEquals, expected)
}

func (NoiseSuite) TestXXRoundtrip(c *C) {
	cs := NewCipherSuite(DH25519, CipherAESGCM, HashSHA256)
	rngI := new(RandomInc)
	rngR := new(RandomInc)
	*rngR = 1

	staticI := cs.GenerateKeypair(rngI)
	staticR := cs.GenerateKeypair(rngR)

	hsI := NewHandshakeState(Config{CipherSuite: cs, Random: rngI, Pattern: HandshakeXX, Initiator: true, StaticKeypair: staticI})
	hsR := NewHandshakeState(Config{CipherSuite: cs, Random: rngR, Pattern: HandshakeXX, StaticKeypair: staticR})

	// -> e
	msg, _, _ := hsI.WriteMessage(nil, []byte("abcdef"))
	c.Assert(msg, HasLen, 38)
	res, _, _, err := hsR.ReadMessage(nil, msg)
	c.Assert(err, IsNil)
	c.Assert(string(res), Equals, "abcdef")

	// <- e, dhee, s, dhse
	msg, _, _ = hsR.WriteMessage(nil, nil)
	c.Assert(msg, HasLen, 96)
	res, _, _, err = hsI.ReadMessage(nil, msg)
	c.Assert(err, IsNil)
	c.Assert(res, HasLen, 0)

	// -> s, dhse
	payload := "0123456789012345678901234567890123456789012345678901234567890123456789"
	msg, csI0, csI1 := hsI.WriteMessage(nil, []byte(payload))
	c.Assert(msg, HasLen, 134)
	res, csR0, csR1, err := hsR.ReadMessage(nil, msg)
	c.Assert(err, IsNil)
	c.Assert(string(res), Equals, payload)

	// transport message I -> R
	msg = csI0.Encrypt(nil, nil, []byte("wubba"))
	res, err = csR0.Decrypt(nil, nil, msg)
	c.Assert(err, IsNil)
	c.Assert(string(res), Equals, "wubba")

	// transport message I -> R again
	msg = csI0.Encrypt(nil, nil, []byte("aleph"))
	res, err = csR0.Decrypt(nil, nil, msg)
	c.Assert(err, IsNil)
	c.Assert(string(res), Equals, "aleph")

	// transport message R <- I
	msg = csR1.Encrypt(nil, nil, []byte("worri"))
	res, err = csI1.Decrypt(nil, nil, msg)
	c.Assert(err, IsNil)
	c.Assert(string(res), Equals, "worri")
}

func (NoiseSuite) TestPSK_NN_Roundtrip(c *C) {
	cs := NewCipherSuite(DH25519, CipherChaChaPoly, HashBLAKE2b)
	rngI := new(RandomInc)
	rngR := new(RandomInc)
	*rngR = 1

	hsI := NewHandshakeState(Config{CipherSuite: cs, Random: rngI, Pattern: HandshakeNN, Initiator: true, PresharedKey: []byte("supersecret")})
	hsR := NewHandshakeState(Config{CipherSuite: cs, Random: rngR, Pattern: HandshakeNN, PresharedKey: []byte("supersecret")})

	// -> e
	msg, _, _ := hsI.WriteMessage(nil, nil)
	c.Assert(msg, HasLen, 48)
	res, _, _, err := hsR.ReadMessage(nil, msg)
	c.Assert(err, IsNil)
	c.Assert(res, HasLen, 0)

	// <- e, dhee
	msg, csR0, csR1 := hsR.WriteMessage(nil, nil)
	c.Assert(msg, HasLen, 48)
	res, csI0, csI1, err := hsI.ReadMessage(nil, msg)
	c.Assert(err, IsNil)
	c.Assert(res, HasLen, 0)

	// transport I -> R
	msg = csI0.Encrypt(nil, nil, []byte("foo"))
	res, err = csR0.Decrypt(nil, nil, msg)
	c.Assert(err, IsNil)
	c.Assert(string(res), Equals, "foo")

	// transport R -> I
	msg = csR1.Encrypt(nil, nil, []byte("bar"))
	res, err = csI1.Decrypt(nil, nil, msg)
	c.Assert(err, IsNil)
	c.Assert(string(res), Equals, "bar")
}

func (NoiseSuite) TestPSK_X(c *C) {
	cs := NewCipherSuite(DH25519, CipherChaChaPoly, HashSHA256)
	rng := new(RandomInc)
	staticI := cs.GenerateKeypair(rng)
	staticR := cs.GenerateKeypair(rng)

	hs := NewHandshakeState(Config{CipherSuite: cs, Random: rng, Pattern: HandshakeX, Initiator: true, PresharedKey: []byte{0x01, 0x02, 0x03}, StaticKeypair: staticI, PeerStatic: staticR.Public})
	msg, _, _ := hs.WriteMessage(nil, nil)
	c.Assert(msg, HasLen, 96)

	expected, _ := hex.DecodeString("79a631eede1bf9c98f12032cdeadd0e7a079398fc786b88cc846ec89af85a51a983a01a35059140decfb16a5748b5673a261e4bb69a11f0d698cf6d5117f99eadcacaa2082307089ab2c633970cdbe1da510833a29ba3211174d35780b58e99c")
	c.Assert(msg, DeepEquals, expected)
}

func (NoiseSuite) TestPSK_NN(c *C) {
	cs := NewCipherSuite(DH25519, CipherAESGCM, HashSHA512)
	rngI := new(RandomInc)
	rngR := new(RandomInc)
	*rngR = 1
	prologue := []byte{0x01, 0x02, 0x03}
	psk := []byte{0x04, 0x05, 0x06}

	hsI := NewHandshakeState(Config{CipherSuite: cs, Random: rngI, Pattern: HandshakeNN, Initiator: true, Prologue: prologue, PresharedKey: psk})
	hsR := NewHandshakeState(Config{CipherSuite: cs, Random: rngR, Pattern: HandshakeNN, Prologue: prologue, PresharedKey: psk})

	msg, _, _ := hsI.WriteMessage(nil, []byte("abc"))
	c.Assert(msg, HasLen, 51)
	res, _, _, err := hsR.ReadMessage(nil, msg)
	c.Assert(err, IsNil)
	c.Assert(string(res), Equals, "abc")

	msg, _, _ = hsR.WriteMessage(nil, []byte("defg"))
	c.Assert(msg, HasLen, 52)
	res, _, _, err = hsI.ReadMessage(nil, msg)
	c.Assert(err, IsNil)
	c.Assert(string(res), Equals, "defg")

	expected, _ := hex.DecodeString("07a37cbc142093c8b755dc1b10e86cb426374ad16aa853ed0bdfc0b2b86d1c7c4f28d0b09ff91e2ff6bb55bb99bc74436056c0d1")
	c.Assert(msg, DeepEquals, expected)
}

func (NoiseSuite) TestPSK_XX(c *C) {
	cs := NewCipherSuite(DH25519, CipherAESGCM, HashSHA256)
	rngI := new(RandomInc)
	rngR := new(RandomInc)
	*rngR = 1

	staticI := cs.GenerateKeypair(rngI)
	staticR := cs.GenerateKeypair(rngR)
	prologue := []byte{0x01, 0x02, 0x03}
	psk := []byte{0x04, 0x05, 0x06}

	hsI := NewHandshakeState(Config{CipherSuite: cs, Random: rngI, Pattern: HandshakeXX, Initiator: true, Prologue: prologue, PresharedKey: psk, StaticKeypair: staticI})
	hsR := NewHandshakeState(Config{CipherSuite: cs, Random: rngR, Pattern: HandshakeXX, Prologue: prologue, PresharedKey: psk, StaticKeypair: staticR})

	msg, _, _ := hsI.WriteMessage(nil, []byte("abc"))
	c.Assert(msg, HasLen, 51)
	res, _, _, err := hsR.ReadMessage(nil, msg)
	c.Assert(err, IsNil)
	c.Assert(string(res), Equals, "abc")

	msg, _, _ = hsR.WriteMessage(nil, []byte("defg"))
	c.Assert(msg, HasLen, 100)
	res, _, _, err = hsI.ReadMessage(nil, msg)
	c.Assert(err, IsNil)
	c.Assert(string(res), Equals, "defg")

	msg, _, _ = hsI.WriteMessage(nil, nil)
	c.Assert(msg, HasLen, 64)
	res, _, _, err = hsR.ReadMessage(nil, msg)
	c.Assert(err, IsNil)
	c.Assert(res, HasLen, 0)

	expected, _ := hex.DecodeString("eb8f3a6d5b68c7048cf61cbbff4a19959fed3ad315ef0d088f00681f3f38295d5d2aee59874e22cf9e86c2df3aaea03449435de887bab9bde1ee7ef392785fdf")
	c.Assert(msg, DeepEquals, expected)
}
