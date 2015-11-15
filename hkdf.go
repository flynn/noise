package noise

import (
	"crypto/hmac"
	"hash"
)

func HKDF(h func() hash.Hash, out1, out2, chainingKey, inputKeyMaterial []byte) ([]byte, []byte) {
	if len(out1) > 0 {
		panic("len(out1) > 0")
	}
	if len(out2) > 0 {
		panic("len(out2) > 0")
	}

	tempMAC := hmac.New(h, chainingKey)
	tempMAC.Write(inputKeyMaterial)
	tempKey := tempMAC.Sum(out2)

	out1MAC := hmac.New(h, tempKey)
	out1MAC.Write([]byte{0x01})
	out1 = out1MAC.Sum(out1)

	out2MAC := hmac.New(h, tempKey)
	out2MAC.Write(out1)
	out2MAC.Write([]byte{0x02})
	out2 = out2MAC.Sum(tempKey[:0])

	return out1, out2
}
