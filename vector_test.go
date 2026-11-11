package noise

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func mustHex(s []byte) []byte {
	res, err := hex.DecodeString(string(s))
	if err != nil {
		panic(err)
	}
	return res
}

func hexReader(s []byte) io.Reader {
	return bytes.NewBuffer(mustHex(s))
}

var patterns = make(map[string]HandshakePattern)
var ciphers = map[string]CipherFunc{
	"AESGCM":     CipherAESGCM,
	"ChaChaPoly": CipherChaChaPoly,
}
var hashes = map[string]HashFunc{
	"SHA256":  HashSHA256,
	"SHA512":  HashSHA512,
	"BLAKE2b": HashBLAKE2b,
	"BLAKE2s": HashBLAKE2s,
}

var patternKeys = make(map[string]patternKeyInfo)

type patternKeyInfo struct {
	is, rs, isr, rsi, e bool
}

func init() {
	for _, h := range []HandshakePattern{
		HandshakeNN,
		HandshakeKN,
		HandshakeNK,
		HandshakeKK,
		HandshakeNX,
		HandshakeKX,
		HandshakeXN,
		HandshakeIN,
		HandshakeXK,
		HandshakeIK,
		HandshakeXX,
		HandshakeIX,
		HandshakeN,
		HandshakeK,
		HandshakeX,
	} {
		patterns[h.Name] = h
		var k patternKeyInfo
		if len(h.Name) == 1 {
			switch h.Name {
			case "N":
				k.rs = true
				k.rsi = true
			case "K":
				k.is = true
				k.isr = true
				k.rs = true
				k.rsi = true
			case "X":
				k.is = true
				k.rs = true
				k.rsi = true
			}
		} else {
			switch h.Name[0] {
			case 'X', 'I':
				k.is = true
			case 'K':
				k.is = true
				k.isr = true
			}
			switch h.Name[1] {
			case 'K':
				k.rs = true
				k.rsi = true
			case 'X', 'R':
				k.rs = true
			}
		}
		patternKeys[h.Name] = k
	}
}

func TestVectors(t *testing.T) {
	f, err := os.Open("vectors.txt")
	require.NoError(t, err)
	r := bufio.NewReader(f)

	var hsI, hsR *HandshakeState
	var staticR, staticI, ephR DHKey
	var configI, configR Config
	var keyInfo patternKeyInfo
	var name string
	var payload, psk []byte
	var csW0, csW1, csR0, csR1 *CipherState

	for {
		line, _, err := r.ReadLine()
		if err == io.EOF {
			break
		}
		require.NoError(t, err)

		if len(bytes.TrimSpace(line)) == 0 || line[0] == '#' {
			continue
		}

		splitLine := bytes.SplitN(line, []byte("="), 2)
		require.Len(t, splitLine, 2)

		switch string(splitLine[0]) {
		case "init_static":
			staticI, _ = DH25519.GenerateKeypair(hexReader(splitLine[1]))
		case "resp_static":
			staticR, _ = DH25519.GenerateKeypair(hexReader(splitLine[1]))
		case "resp_ephemeral":
			ephR, _ = DH25519.GenerateKeypair(hexReader(splitLine[1]))
		case "handshake":
			name = string(splitLine[1])
			t.Log(name)
			configI, configR = Config{Initiator: true}, Config{}
			hsI, hsR = nil, nil
			components := strings.SplitN(name, "_", 5)
			handshakeComponents := strings.Split(components[1], "psk")
			if len(handshakeComponents) == 2 {
				configI.PresharedKeyPlacement, _ = strconv.Atoi(handshakeComponents[1])
			}
			keyInfo = patternKeys[handshakeComponents[0]]
			configI.Pattern = patterns[handshakeComponents[0]]
			configI.CipherSuite = NewCipherSuite(DH25519, ciphers[components[3]], hashes[components[4]])
			configR.Pattern = configI.Pattern
			configR.CipherSuite = configI.CipherSuite
			configR.PresharedKeyPlacement = configI.PresharedKeyPlacement
		case "gen_init_ephemeral":
			configI.Random = hexReader(splitLine[1])
		case "gen_resp_ephemeral":
			configR.Random = hexReader(splitLine[1])
		case "prologue":
			configI.Prologue = mustHex(splitLine[1])
			configR.Prologue = configI.Prologue
		case "preshared_key":
			psk = mustHex(splitLine[1])
		}

		if !bytes.HasPrefix(splitLine[0], []byte("msg_")) {
			continue
		}
		if bytes.HasSuffix(splitLine[0], []byte("_payload")) {
			payload = mustHex(splitLine[1])
			continue
		}

		if hsI == nil {
			if keyInfo.is {
				configI.StaticKeypair = staticI
			}
			if keyInfo.rs {
				configR.StaticKeypair = staticR
			}
			if keyInfo.isr {
				configR.PeerStatic = staticI.Public
			}
			if keyInfo.rsi {
				configI.PeerStatic = staticR.Public
			}
			if keyInfo.e {
				configR.EphemeralKeypair = ephR
				configI.PeerEphemeral = ephR.Public
			}
			if strings.Contains(name, "psk") {
				configI.PresharedKey = psk
				configR.PresharedKey = psk
			}
			hsI, _ = NewHandshakeState(configI)
			hsR, _ = NewHandshakeState(configR)
		}

		i, _ := strconv.Atoi(string(splitLine[0][4:5]))

		if i > len(configI.Pattern.Messages)-1 {
			enc, dec := csW0, csR0
			if (i-len(configI.Pattern.Messages))%2 != 0 {
				enc, dec = csW1, csR1
			}
			encrypted, err := enc.Encrypt(nil, nil, payload)
			require.NoError(t, err)
			require.Equal(t, string(splitLine[1]), fmt.Sprintf("%x", encrypted))
			decrypted, err := dec.Decrypt(nil, nil, encrypted)
			require.NoError(t, err)
			require.Equal(t, string(decrypted), string(payload))
			payload = nil
			continue
		}

		writer, reader := hsI, hsR
		if i%2 != 0 {
			writer, reader = hsR, hsI
		}

		var msg, res []byte
		msg, csW0, csW1, _ = writer.WriteMessage(nil, payload)
		require.Equal(t, string(splitLine[1]), fmt.Sprintf("%x", msg))
		res, csR0, csR1, err = reader.ReadMessage(nil, msg)
		require.NoError(t, err)
		require.Equal(t, string(payload), string(res))
		payload = nil
	}
}
