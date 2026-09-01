package proto

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
)

// padding envelope wraps the plaintext wire-x packet BEFORE encryption:
// [0x2A][padLen:2][pad][framed]. inside the aead zone the tag is
// unambiguous (0x2A is never a wire-x type) and authenticated, so there is
// no on-wire first-byte collision and zero packet loss from misparsing.
// encrypted sizes collapse into fixed classes, blurring the per-tick size
// fingerprint; bulk world data above the largest class stays unpadded —
// hiding those is hopeless and the waste would be punitive.

var ErrPadMalformed = errors.New("hydra-pad: malformed padding envelope")

const padTag = 0x2A

var PadClasses = [...]int{128, 256, 512, 1024}

// Pad wraps the plaintext packet so its length lands on a class boundary.
// payloads above the largest class go out as-is.
func Pad(framed []byte) []byte {
	for _, class := range PadClasses {
		if class < len(framed)+3 {
			continue
		}
		waste := class - 3 - len(framed)
		out := make([]byte, 0, class)
		out = append(out, padTag)
		out = binary.BigEndian.AppendUint16(out, uint16(waste))
		pad := make([]byte, waste)
		rand.Read(pad)
		out = append(out, pad...)
		return append(out, framed...)
	}
	return framed
}

// UnPad strips the envelope; raw packets (tag byte is never a wire-x type)
// pass through untouched
func UnPad(data []byte) ([]byte, error) {
	if len(data) < 4 || data[0] != padTag {
		return data, nil
	}
	padLen := int(binary.BigEndian.Uint16(data[1:3]))
	if 3+padLen > len(data) {
		return nil, ErrPadMalformed
	}
	return data[3+padLen:], nil
}
