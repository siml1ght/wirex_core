package proto

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net"
)

// stun channel disguise: real RFC 8489 Binding Requests/Responses. tunnel
// payload rides in a comprehension-optional attribute (0xC0FF); probes get a
// genuine XOR-MAPPED-ADDRESS response, so the port looks like a working
// STUN endpoint to scanners.

const (
	StunMagic      = 0x2112A442
	stunHeaderSize = 20

	stunMethodBinding = 0x001
	stunClassRequest  = 0x000
	stunClassResp     = 0x0100

	stunAttrXORMapped = 0x0020
	stunAttrSoftware  = 0x8022
	stunAttrHydraData = 0xC0FF
)

var (
	ErrStunMalformed  = errors.New("hydra-stun: malformed message")
	ErrStunNotBinding = errors.New("hydra-stun: not a binding request")
)

func isStunClass(wire []byte, class uint16) bool {
	if len(wire) < stunHeaderSize {
		return false
	}
	m := uint16(wire[0])<<8 | uint16(wire[1])
	return m&0x0110 == class && binary.BigEndian.Uint32(wire[4:8]) == StunMagic
}

func IsStunRequest(wire []byte) bool {
	return isStunClass(wire, stunClassRequest)
}

type StunMask struct {
	Software string
}

// BuildRequest wraps the encrypted wire-x packet as a Binding Request
func (s *StunMask) BuildRequest(payload []byte) ([]byte, error) {
	var tx [12]byte
	rand.Read(tx[:])
	attrs := make([]byte, 0, 4+len(payload)+len(s.Software)+8)
	attrs = appendTLV(attrs, stunAttrHydraData, payload)
	if s.Software != "" {
		attrs = appendTLV(attrs, stunAttrSoftware, []byte(s.Software))
	}
	out := make([]byte, 0, stunHeaderSize+len(attrs))
	method := stunMethodBinding | stunClassRequest
	out = append(out, byte(method>>8), byte(method&0xFF))
	out = binary.BigEndian.AppendUint16(out, uint16(len(attrs)))
	out = append(out, 0x21, 0x12, 0xA4, 0x42)
	out = append(out, tx[:]...)
	out = append(out, attrs...)
	return out, nil
}

// ParseRequest splits tunnel payload from probe status
func (s *StunMask) ParseRequest(wire []byte) (payload []byte, txID [12]byte, err error) {
	if !IsStunRequest(wire) {
		return nil, txID, ErrStunNotBinding
	}
	mlen := int(binary.BigEndian.Uint16(wire[2:4]))
	copy(txID[:], wire[8:20])
	pos := stunHeaderSize
	end := stunHeaderSize + mlen
	if end > len(wire) {
		end = len(wire)
	}
	for pos+4 <= end {
		at := binary.BigEndian.Uint16(wire[pos:])
		al := int(binary.BigEndian.Uint16(wire[pos+2:]))
		if pos+4+al > end {
			break
		}
		if at == stunAttrHydraData {
			payload = append([]byte(nil), wire[pos+4:pos+4+al]...)
		}
		pos += 4 + al
		if al%4 != 0 {
			pos += 4 - al%4
		}
	}
	return payload, txID, nil
}

// BuildBindingResponse produces an honest response for probes: XOR-MAPPED-ADDRESS
func (s *StunMask) BuildBindingResponse(txID [12]byte, src *net.UDPAddr) []byte {
	magic := []byte{0x21, 0x12, 0xA4, 0x42}
	xip := make([]byte, 4)
	for i := 0; i < 4; i++ {
		xip[i] = src.IP.To4()[i] ^ magic[i]
	}
	xport := uint16(src.Port) ^ uint16(StunMagic&0xFFFF)

	xa := make([]byte, 0, 8)
	xa = append(xa, 0x00, 0x01) // IPv4
	xa = binary.BigEndian.AppendUint16(xa, xport)
	xa = append(xa, xip...)

	attrs := make([]byte, 0, len(xa)+len(s.Software)+8)
	attrs = appendTLV(attrs, stunAttrXORMapped, xa)
	if s.Software != "" {
		attrs = appendTLV(attrs, stunAttrSoftware, []byte(s.Software))
	}
	out := make([]byte, 0, stunHeaderSize+len(attrs))
	method := stunMethodBinding | stunClassResp
	out = append(out, byte(method>>8), byte(method&0xFF))
	out = binary.BigEndian.AppendUint16(out, uint16(len(attrs)))
	out = append(out, 0x21, 0x12, 0xA4, 0x42)
	out = append(out, txID[:]...)
	out = append(out, attrs...)
	return out
}

// BuildDataResponse returns a Binding Response carrying the encrypted reply
func (s *StunMask) BuildDataResponse(txID [12]byte, payload []byte) []byte {
	attrs := make([]byte, 0, len(payload)+4)
	attrs = appendTLV(attrs, stunAttrHydraData, payload)
	out := make([]byte, 0, stunHeaderSize+len(attrs))
	method := stunMethodBinding | stunClassResp
	out = append(out, byte(method>>8), byte(method&0xFF))
	out = binary.BigEndian.AppendUint16(out, uint16(len(attrs)))
	out = append(out, 0x21, 0x12, 0xA4, 0x42)
	out = append(out, txID[:]...)
	out = append(out, attrs...)
	return out
}

// ParseResponse extracts tunnel payload from a Binding Response (nil if none)
func (s *StunMask) ParseResponse(wire []byte) (payload []byte, txID [12]byte, err error) {
	if !isStunClass(wire, stunClassResp) {
		return nil, txID, ErrStunMalformed
	}
	mlen := int(binary.BigEndian.Uint16(wire[2:4]))
	copy(txID[:], wire[8:20])
	pos := stunHeaderSize
	end := stunHeaderSize + mlen
	if end > len(wire) {
		end = len(wire)
	}
	for pos+4 <= end {
		at := binary.BigEndian.Uint16(wire[pos:])
		al := int(binary.BigEndian.Uint16(wire[pos+2:]))
		if pos+4+al > end {
			break
		}
		if at == stunAttrHydraData {
			payload = append([]byte(nil), wire[pos+4:pos+4+al]...)
		}
		pos += 4 + al
		if al%4 != 0 {
			pos += 4 - al%4
		}
	}
	return payload, txID, nil
}

func appendTLV(dst []byte, attrType uint16, val []byte) []byte {
	dst = binary.BigEndian.AppendUint16(dst, attrType)
	dst = binary.BigEndian.AppendUint16(dst, uint16(len(val)))
	dst = append(dst, val...)
	for len(val)%4 != 0 {
		dst = append(dst, 0)
		break
	}
	return dst
}
