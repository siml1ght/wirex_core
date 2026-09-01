package proto

import (
	"bytes"
	"testing"
)

func TestPadClassBoundaries(t *testing.T) {
	for _, n := range []int{1, 50, 100, 124, 125, 130, 253, 300, 509, 1021} {
		framed := bytes.Repeat([]byte{0xEE}, n)
		padded := Pad(framed)
		if len(padded) > 1024 {
			t.Fatalf("n=%d: padded to %d", n, len(padded))
		}
		got, err := UnPad(padded)
		if err != nil {
			t.Fatalf("n=%d: unpad: %v", n, err)
		}
		if !bytes.Equal(got, framed) {
			t.Fatalf("n=%d: roundtrip corrupted (got %d bytes)", n, len(got))
		}
		if padded[0] == padTag {
			class := len(padded)
			inClass := false
			for _, c := range PadClasses {
				if class == c {
					inClass = true
				}
			}
			if !inClass {
				t.Fatalf("n=%d: size %d is not a class boundary", n, class)
			}
		}
	}
}

func TestPadOversizedPassThrough(t *testing.T) {
	big := bytes.Repeat([]byte{0x42}, 2000)
	if padded := Pad(big); !bytes.Equal(padded, big) {
		t.Fatal("oversized payload must pass through unpadded")
	}
}

func TestPadRawPacketUntouched(t *testing.T) {
	// wire-x DATA packet (type 0x02) of size 100: waste 25 = 19% of the class, pads
	data := append([]byte{PacketDATA}, bytes.Repeat([]byte{0x11}, 99)...)
	padded := Pad(data)
	if len(padded) != 128 {
		t.Fatalf("expected class 128, got %d", len(padded))
	}
	got, err := UnPad(padded)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatal("roundtrip failed")
	}

	// wire-x packet of size 70 lands on the 128 class
	small := append([]byte{PacketDATA}, bytes.Repeat([]byte{0x11}, 69)...)
	if padded := Pad(small); len(padded) != 128 {
		t.Fatalf("expected class 128, got %d", len(padded))
	}
	if got, err := UnPad(Pad(small)); err != nil || !bytes.Equal(got, small) {
		t.Fatal("roundtrip failed")
	}
}

func TestPadRandomness(t *testing.T) {
	framed := bytes.Repeat([]byte{0x77}, 100)
	if bytes.Equal(Pad(framed), Pad(framed)) {
		t.Fatal("two pads of the same payload are identical — no entropy in pad bytes")
	}
}

func TestUnPadUntagged(t *testing.T) {
	raw := []byte{0x01, 0x02, 0x03}
	got, err := UnPad(raw)
	if err != nil || !bytes.Equal(got, raw) {
		t.Fatal("untagged data must pass through")
	}
	bad := []byte{0x2A, 0xFF, 0xFF, 0x01}
	if _, err := UnPad(bad); err == nil {
		t.Fatal("malformed envelope must be rejected")
	}
}
