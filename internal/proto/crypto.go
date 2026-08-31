package proto

import (
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	NonceSize = 12
	TagSize   = 16
	Overhead  = NonceSize + TagSize
)

var ErrPacketTooShort = errors.New("hydra: packet shorter than the crypto header")

type Codec struct {
	aead cipher.AEAD
}

func NewCodec(key []byte) (*Codec, error) {
	if len(key) != chacha20poly1305.KeySize {
		return nil, fmt.Errorf("hydra: key must be %d bytes, got %d", chacha20poly1305.KeySize, len(key))
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	return &Codec{aead: aead}, nil
}

// random nonce per packet: the wire-x header lives inside the AEAD zone,
// so nothing about session/flow/seq leaks to the wire
func (c *Codec) Encrypt(plaintext []byte) ([]byte, error) {
	nonce := make([]byte, NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	out := make([]byte, 0, NonceSize+len(plaintext)+TagSize)
	out = append(out, nonce...)
	out = c.aead.Seal(out, nonce, plaintext, nil)
	return out, nil
}

func (c *Codec) Decrypt(data []byte) ([]byte, error) {
	if len(data) < Overhead {
		return nil, ErrPacketTooShort
	}
	return c.aead.Open(nil, data[:NonceSize], data[NonceSize:], nil)
}
