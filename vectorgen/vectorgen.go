package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"os"

	. "github.com/flynn/noise"
)

func main() {
	for _, cipher := range []CipherFunc{CipherAESGCM, CipherChaChaPoly} {
		for _, hash := range []HashFunc{HashSHA256, HashSHA512, HashBLAKE2b, HashBLAKE2s} {
			for _, handshake := range []HandshakePattern{
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
				for _, prologue := range []bool{false, true} {
					for _, payloads := range []bool{false, true} {
						for pskPlacement := -1; pskPlacement <= len(handshake.Messages); pskPlacement++ {
							writeHandshake(
								os.Stdout,
								NewCipherSuite(DH25519, cipher, hash),
								handshake, pskPlacement,
								pskPlacement >= 0, prologue, payloads,
							)
							fmt.Fprintln(os.Stdout)
						}
					}
				}
			}
		}
	}
}

func hexReader(s string) io.Reader {
	res, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return bytes.NewBuffer(res)
}

const (
	key0 = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	key1 = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
	key2 = "2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40"
	key3 = "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
	key4 = "4142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f60"
)

func writeHandshake(out io.Writer, cs CipherSuite, h HandshakePattern, pskPlacement int, hasPSK, hasPrologue, payloads bool) {
	var prologue, psk []byte
	if hasPrologue {
		prologue = []byte("notsecret")
	}
	if hasPSK {
		psk = []byte("!verysecretverysecretverysecret!")
	}

	staticI, _ := cs.GenerateKeypair(hexReader(key0))
	staticR, _ := cs.GenerateKeypair(hexReader(key1))
	ephR, _ := cs.GenerateKeypair(hexReader(key2))

	configI := Config{
		CipherSuite:           cs,
		Random:                hexReader(key3),
		Pattern:               h,
		Initiator:             true,
		Prologue:              prologue,
		PresharedKey:          psk,
		PresharedKeyPlacement: pskPlacement,
	}
	configR := configI
	configR.Random = hexReader(key4)
	configR.Initiator = false

	var pskName string
	if hasPSK {
		pskName = fmt.Sprintf("psk%d", pskPlacement)
	}

	fmt.Fprintf(out, "handshake=Noise_%s%s_%s\n", h.Name, pskName, cs.Name())

	if len(h.Name) == 1 {
		switch h.Name {
		case "N":
			configR.StaticKeypair = staticR
			configI.PeerStatic = staticR.Public
			fmt.Fprintf(out, "resp_static=%x\n", staticR.Private)
		case "K":
			configI.StaticKeypair = staticI
			configR.PeerStatic = staticI.Public
			configR.StaticKeypair = staticR
			configI.PeerStatic = staticR.Public
			fmt.Fprintf(out, "init_static=%x\n", staticI.Private)
			fmt.Fprintf(out, "resp_static=%x\n", staticR.Private)
		case "X":
			configI.StaticKeypair = staticI
			configR.StaticKeypair = staticR
			configI.PeerStatic = staticR.Public
			fmt.Fprintf(out, "init_static=%x\n", staticI.Private)
			fmt.Fprintf(out, "resp_static=%x\n", staticR.Private)
		}
	} else {
		switch h.Name[0] {
		case 'K', 'X', 'I':
			configI.StaticKeypair = staticI
			if h.Name[0] == 'K' {
				configR.PeerStatic = staticI.Public
			}
			fmt.Fprintf(out, "init_static=%x\n", staticI.Private)
		}
		switch h.Name[1] {
		case 'K', 'E', 'X', 'R':
			configR.StaticKeypair = staticR
			fmt.Fprintf(out, "resp_static=%x\n", staticR.Private)
			switch h.Name[1] {
			case 'K':
				configI.PeerStatic = staticR.Public
			case 'E':
				configR.EphemeralKeypair = ephR
				configI.PeerEphemeral = ephR.Public
				configI.PeerStatic = staticR.Public
				fmt.Fprintf(out, "resp_ephemeral=%x\n", ephR.Private)
			}
		}
	}

	fmt.Fprintf(out, "gen_init_ephemeral=%s\n", key3)
	fmt.Fprintf(out, "gen_resp_ephemeral=%s\n", key4)
	if len(prologue) > 0 {
		fmt.Fprintf(out, "prologue=%x\n", prologue)
	}
	if len(psk) > 0 {
		fmt.Fprintf(out, "preshared_key=%x\n", psk)
	}

	hsI, _ := NewHandshakeState(configI)
	hsR, _ := NewHandshakeState(configR)

	var cs0, cs1 *CipherState
	for i := range h.Messages {
		writer, reader := hsI, hsR
		if i%2 != 0 {
			writer, reader = hsR, hsI
		}

		var payload string
		if payloads {
			payload = fmt.Sprintf("test_msg_%d", i)
		}
		var msg []byte
		msg, cs0, cs1, _ = writer.WriteMessage(nil, []byte(payload))
		_, _, _, err := reader.ReadMessage(nil, msg)
		if err != nil {
			panic(err)
		}
		fmt.Fprintf(out, "msg_%d_payload=%x\n", i, payload)
		fmt.Fprintf(out, "msg_%d_ciphertext=%x\n", i, msg)
	}

	payload0 := []byte("yellowsubmarine")
	payload1 := []byte("submarineyellow")
	fmt.Fprintf(out, "msg_%d_payload=%x\n", len(h.Messages), payload0)
	ciphertext0, _ := cs0.Encrypt(nil, nil, payload0)
	fmt.Fprintf(out, "msg_%d_ciphertext=%x\n", len(h.Messages), ciphertext0)
	fmt.Fprintf(out, "msg_%d_payload=%x\n", len(h.Messages)+1, payload1)
	ciphertext1, _ := cs1.Encrypt(nil, nil, payload1)
	fmt.Fprintf(out, "msg_%d_ciphertext=%x\n", len(h.Messages)+1, ciphertext1)
}
