package noise

import (
	"errors"
	"io"
)

type CipherState struct {
	cs CipherSuite
	c  Cipher
	k  [32]byte
	n  uint64
}

func (s *CipherState) Encrypt(out, ad, plaintext []byte) []byte {
	out = s.c.Encrypt(out, s.n, ad, plaintext)
	s.n++
	return out
}

func (s *CipherState) Decrypt(out, ad, ciphertext []byte) ([]byte, error) {
	out, err := s.c.Decrypt(out, s.n, ad, ciphertext)
	s.n++
	return out, err
}

type SymmetricState struct {
	CipherState
	hasK   bool
	hasPSK bool
	ck     []byte
	h      []byte
}

func (s *SymmetricState) InitializeSymmetric(handshakeName []byte) {
	h := s.cs.Hash()
	if len(handshakeName) <= h.Size() {
		s.h = make([]byte, h.Size())
		copy(s.h, handshakeName)
	} else {
		h.Write(handshakeName)
		s.h = h.Sum(nil)
	}
	s.ck = make([]byte, len(s.h))
	copy(s.ck, s.h)
}

func (s *SymmetricState) MixKey(dhOutput []byte) {
	s.n = 0
	s.hasK = true
	var hk []byte
	s.ck, hk = HKDF(s.cs.Hash, s.ck[:0], s.k[:0], s.ck, dhOutput)
	copy(s.k[:], hk)
	s.c = s.cs.Cipher(s.k)
}

func (s *SymmetricState) MixHash(data []byte) {
	h := s.cs.Hash()
	h.Write(s.h)
	h.Write(data)
	s.h = h.Sum(s.h[:0])
}

func (s *SymmetricState) MixPresharedKey(presharedKey []byte) {
	var temp []byte
	s.ck, temp = HKDF(s.cs.Hash, s.ck[:0], nil, s.ck, presharedKey)
	s.MixHash(temp)
	s.hasPSK = true
}

func (s *SymmetricState) EncryptAndHash(out, plaintext []byte) []byte {
	if !s.hasK {
		s.MixHash(plaintext)
		return append(out, plaintext...)
	}
	ciphertext := s.Encrypt(out, s.h, plaintext)
	s.MixHash(ciphertext[len(out):])
	return ciphertext
}

func (s *SymmetricState) DecryptAndHash(out, data []byte) ([]byte, error) {
	if !s.hasK {
		s.MixHash(data)
		return append(out, data...), nil
	}
	plaintext, err := s.Decrypt(out, s.h, data)
	if err != nil {
		return nil, err
	}
	s.MixHash(data)
	return plaintext, nil
}

func (s *SymmetricState) Split() (*CipherState, *CipherState) {
	s1, s2 := &CipherState{cs: s.cs}, &CipherState{cs: s.cs}
	hk1, hk2 := HKDF(s.cs.Hash, s1.k[:0], s2.k[:0], s.ck, nil)
	copy(s1.k[:], hk1)
	copy(s2.k[:], hk2)
	s1.c = s.cs.Cipher(s1.k)
	s2.c = s.cs.Cipher(s2.k)
	return s1, s2
}

type MessagePattern int

type HandshakePattern struct {
	Name                 string
	InitiatorPreMessages []MessagePattern
	ResponderPreMessages []MessagePattern
	Messages             [][]MessagePattern
}

const (
	MessagePatternS MessagePattern = iota
	MessagePatternE
	MessagePatternDHEE
	MessagePatternDHES
	MessagePatternDHSE
	MessagePatternDHSS
)

const MaxMsgLen = 65535

type HandshakeState struct {
	SymmetricState
	s               DHKey  // local static keypair
	e               DHKey  // local ephemeral keypair
	rs              []byte // remote party's static public key
	re              []byte // remote party's ephemeral public key
	messagePatterns [][]MessagePattern
	shouldWrite     bool
	msgIdx          int
	rng             io.Reader
}

type Config struct {
	CipherSuite      CipherSuite
	Random           io.Reader
	Pattern          HandshakePattern
	Initiator        bool
	Prologue         []byte
	PresharedKey     []byte
	StaticKeypair    DHKey
	EphemeralKeypair DHKey
	PeerStatic       []byte
	PeerEphemeral    []byte
}

func NewHandshakeState(c Config) *HandshakeState {
	hs := &HandshakeState{
		s:               c.StaticKeypair,
		e:               c.EphemeralKeypair,
		rs:              c.PeerStatic,
		re:              c.PeerEphemeral,
		messagePatterns: c.Pattern.Messages,
		shouldWrite:     c.Initiator,
		rng:             c.Random,
	}
	hs.SymmetricState.cs = c.CipherSuite
	namePrefix := "Noise_"
	if len(c.PresharedKey) > 0 {
		namePrefix = "NoisePSK_"
	}
	hs.InitializeSymmetric([]byte(namePrefix + c.Pattern.Name + "_" + string(hs.cs.Name())))
	hs.MixHash(c.Prologue)
	if len(c.PresharedKey) > 0 {
		hs.MixPresharedKey(c.PresharedKey)
	}
	for _, m := range c.Pattern.InitiatorPreMessages {
		switch {
		case c.Initiator && m == MessagePatternS:
			hs.MixHash(hs.s.Public)
		case c.Initiator && m == MessagePatternE:
			hs.MixHash(hs.e.Public)
		case !c.Initiator && m == MessagePatternS:
			hs.MixHash(hs.rs)
		case !c.Initiator && m == MessagePatternE:
			hs.MixHash(hs.re)
		}
	}
	for _, m := range c.Pattern.ResponderPreMessages {
		switch {
		case !c.Initiator && m == MessagePatternS:
			hs.MixHash(hs.s.Public)
		case !c.Initiator && m == MessagePatternE:
			hs.MixHash(hs.e.Public)
		case c.Initiator && m == MessagePatternS:
			hs.MixHash(hs.rs)
		case c.Initiator && m == MessagePatternE:
			hs.MixHash(hs.re)
		}
	}
	return hs
}

func (s *HandshakeState) WriteMessage(out, payload []byte) ([]byte, *CipherState, *CipherState) {
	if !s.shouldWrite {
		panic("noise: unexpected call to WriteMessage should be ReadMessage")
	}
	if s.msgIdx > len(s.messagePatterns)-1 {
		panic("noise: no handshake messages left")
	}
	if len(payload) > MaxMsgLen {
		panic("noise: message is too long")
	}

	for _, msg := range s.messagePatterns[s.msgIdx] {
		switch msg {
		case MessagePatternE:
			s.e = s.cs.GenerateKeypair(s.rng)
			out = append(out, s.e.Public...)
			s.MixHash(s.e.Public)
			if s.hasPSK {
				s.MixKey(s.e.Public)
			}
		case MessagePatternS:
			if len(s.s.Public) == 0 {
				panic("noise: invalid state, s.Public is nil")
			}
			out = s.EncryptAndHash(out, s.s.Public)
		case MessagePatternDHEE:
			s.MixKey(s.cs.DH(s.e.Private, s.re))
		case MessagePatternDHES:
			s.MixKey(s.cs.DH(s.e.Private, s.rs))
		case MessagePatternDHSE:
			s.MixKey(s.cs.DH(s.s.Private, s.re))
		case MessagePatternDHSS:
			s.MixKey(s.cs.DH(s.s.Private, s.rs))
		}
	}
	s.shouldWrite = false
	s.msgIdx++
	out = s.EncryptAndHash(out, payload)

	if s.msgIdx >= len(s.messagePatterns) {
		cs1, cs2 := s.Split()
		return out, cs1, cs2
	}

	return out, nil, nil
}

var ErrShortMessage = errors.New("noise: message is too short")

func (s *HandshakeState) ReadMessage(out, message []byte) ([]byte, *CipherState, *CipherState, error) {
	if s.shouldWrite {
		panic("noise: unexpected call to ReadMessage should be WriteMessage")
	}
	if s.msgIdx > len(s.messagePatterns)-1 {
		panic("noise: no handshake messages left")
	}

	var err error
	for _, msg := range s.messagePatterns[s.msgIdx] {
		switch msg {
		case MessagePatternE, MessagePatternS:
			expected := s.cs.DHLen()
			if msg == MessagePatternS && s.hasK {
				expected += 16
			}
			if len(message) < expected {
				return nil, nil, nil, ErrShortMessage
			}
			switch msg {
			case MessagePatternE:
				if cap(s.re) < s.cs.DHLen() {
					s.re = make([]byte, s.cs.DHLen())
				}
				s.re = s.re[:s.cs.DHLen()]
				copy(s.re, message)
				s.MixHash(s.re)
				if s.hasPSK {
					s.MixKey(s.re)
				}
			case MessagePatternS:
				if len(s.rs) > 0 {
					panic("noise: invalid state, rs is not nil")
				}
				s.rs, err = s.DecryptAndHash(s.rs[:0], message[:expected])
			}
			if err != nil {
				return nil, nil, nil, err
			}
			message = message[expected:]
		case MessagePatternDHEE:
			s.MixKey(s.cs.DH(s.e.Private, s.re))
		case MessagePatternDHES:
			s.MixKey(s.cs.DH(s.s.Private, s.re))
		case MessagePatternDHSE:
			s.MixKey(s.cs.DH(s.e.Private, s.rs))
		case MessagePatternDHSS:
			s.MixKey(s.cs.DH(s.s.Private, s.rs))
		}
	}
	s.shouldWrite = true
	s.msgIdx++
	out, err = s.DecryptAndHash(out, message)
	if err != nil {
		return nil, nil, nil, err
	}

	if s.msgIdx >= len(s.messagePatterns) {
		cs1, cs2 := s.Split()
		return out, cs1, cs2, nil
	}

	return out, nil, nil, nil
}
