package proto

import (
	"bytes"
	"errors"
)

var ErrMaskMismatch = errors.New("hydra: mask prefix mismatch")

func Frame(prefix, encrypted []byte) []byte {
	out := make([]byte, 0, len(prefix)+len(encrypted))
	out = append(out, prefix...)
	out = append(out, encrypted...)
	return out
}

func Unframe(prefix, wire []byte) ([]byte, error) {
	if !bytes.HasPrefix(wire, prefix) {
		return nil, ErrMaskMismatch
	}
	return wire[len(prefix):], nil
}
