package noise

import (
	"bufio"

	"bytes"
	"encoding/hex"
	"encoding/json"
	"github.com/stretchr/testify/assert"
	. "gopkg.in/check.v1"
	"io"
	"os"
)

type FallbackVectors struct {
	Vectors []Vector `json:"vectors"`
}

type Vector struct {
	Name             string    `json:"name"`
	Pattern          string    `json:"pattern"`
	Dh               string    `json:"dh"`
	Cipher           string    `json:"cipher"`
	Hash             string    `json:"hash"`
	Fallback         bool      `json:"fallback"`
	InitPrologue     string    `json:"init_prologue"`
	InitStatic       string    `json:"init_static"`
	InitEphemeral    string    `json:"init_ephemeral"`
	InitRemoteStatic string    `json:"init_remote_static"`
	RespPrologue     string    `json:"resp_prologue"`
	RespStatic       string    `json:"resp_static"`
	RespEphemeral    string    `json:"resp_ephemeral"`
	Messages         []Message `json:"messages"`
	HandshakeHash    string    `json:"handshake_hash"`
	InitPsk          string    `json:"init_psk,omitempty"`
	RespPsk          string    `json:"resp_psk,omitempty"`
}

type Message struct {
	Payload    string `json:"payload"`
	Ciphertext string `json:"ciphertext"`
}

func (NoiseSuite) TestFallbackVectors(c *C) {
	f, err := os.Open("fallback_vectors.json")
	c.Assert(err, IsNil)
	r := bufio.NewReader(f)

	var tests *FallbackVectors

	err = json.NewDecoder(r).Decode(&tests)
	c.Assert(err, IsNil)

	var hsI, hsR *HandshakeState
	var staticR, staticI DHKey
	var initStaticR []byte
	var configI, configR Config
	var name string
	var pskI, pskR []byte
	var handshakeHash []byte

	for _, t := range tests.Vectors {

		if t.Dh != "25519" { //448 is not supported yet
			continue
		}
		if len(t.InitStatic) > 0 {
			staticI = DH25519.GenerateKeypair(hexStrReader(t.InitStatic))
		}

		if len(t.InitRemoteStatic) > 0 {
			initStaticR = mustStrHex(t.InitRemoteStatic)
		}

		if len(t.RespStatic) > 0 {
			staticR = DH25519.GenerateKeypair(hexStrReader(t.RespStatic))
		}

		name = t.Name

		c.Log(name)
		configI, configR = Config{Initiator: true}, Config{}
		hsI, hsR = nil, nil
		configI.Pattern = patterns[t.Pattern]
		configR.Pattern = configI.Pattern

		configI.CipherSuite = NewCipherSuite(DH25519, ciphers[t.Cipher], hashes[t.Hash])
		configR.CipherSuite = configI.CipherSuite

		configI.Prologue = mustStrHex(t.InitPrologue)
		configR.Prologue = mustStrHex(t.RespPrologue)
		pskR = mustStrHex(t.RespPsk)
		pskI = mustStrHex(t.InitPsk)
		configI.PresharedKey = pskI
		configR.PresharedKey = pskR

		if len(t.InitEphemeral) > 0 {
			configI.Random = hexStrReader(t.InitEphemeral)
		}
		if len(t.RespEphemeral) > 0 {
			configR.Random = hexStrReader(t.RespEphemeral)
		}

		configI.StaticKeypair = staticI
		configI.PeerStatic = initStaticR
		configR.StaticKeypair = staticR

		hsI, hsR = NewHandshakeState(configI), NewHandshakeState(configR)

		handshakeHash = mustStrHex(t.HandshakeHash)

		processMessages(c, t.Messages, hsI, hsR, handshakeHash)
	}

}
func processMessages(c *C, ms []Message, stateI *HandshakeState, stateR *HandshakeState, handshakeHash []byte) {
	w, r := stateI, stateR

	// Starts as IK
	ciphertext, _, _ := w.WriteMessage(nil, mustStrHex(ms[0].Payload)) //-> e, es, s, s from IK
	assert.Equal(c, ms[0].Ciphertext, hex.EncodeToString(ciphertext))

	_, _, _, err := r.ReadMessage(nil, ciphertext) //tries to read message sent for a different static key

	assert.Error(c, err)

	r.Fallback() //responder falls back and becomes initiator

	w, r = r, w

	ciphertext, _, _ = w.WriteMessage(nil, mustStrHex(ms[1].Payload)) //-> e, ee, s, se from XXFallback
	assert.Equal(c, ms[1].Ciphertext, hex.EncodeToString(ciphertext))

	//attempt #1
	_, _, _, err = r.ReadMessage(nil, ciphertext) // reads XXfallback and fails because it's IK

	assert.Error(c, err)

	r.Fallback() //initiator falls back and becomes responder
	//attempt #2
	_, _, _, err = r.ReadMessage(nil, ciphertext)
	assert.NoError(c, err)

	w, r = r, w

	ciphertext, cs1, ts1 := w.WriteMessage(nil, mustStrHex(ms[2].Payload)) //   <- s, es  from XXFallback
	assert.Equal(c, ms[2].Ciphertext, hex.EncodeToString(ciphertext))
	assert.NotNil(c, cs1)
	assert.NotNil(c, ts1)

	payload, cs2, ts2, err := r.ReadMessage(nil, ciphertext)
	assert.NoError(c, err)
	assert.NotNil(c, payload)
	assert.NotNil(c, cs2)
	assert.NotNil(c, ts2)

	if len(handshakeHash) > 0 {
		assert.Equal(c, handshakeHash, r.ChannelBinding())
		assert.Equal(c, handshakeHash, w.ChannelBinding())
	}

	assert.Equal(c, cs1.k, cs2.k)
	assert.Equal(c, ts1.k, ts2.k)

	//transport messages
	for i := 3; i < len(ms); i++ {
		ciphertext = cs1.Encrypt(nil, nil, mustStrHex(ms[i].Payload))
		assert.Equal(c, ciphertext, mustStrHex(ms[i].Ciphertext))
		payload, err := cs2.Decrypt(nil, nil, ciphertext)
		assert.NoError(c, err)
		assert.Equal(c, payload, mustStrHex(ms[i].Payload))
		cs1, cs2, ts1, ts2 = ts1, ts2, cs1, cs2
	}
}

func mustStrHex(s string) []byte {
	res, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return res
}

func hexStrReader(s string) io.Reader {
	return bytes.NewBuffer(mustStrHex(s))
}
