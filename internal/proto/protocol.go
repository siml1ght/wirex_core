package proto

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
)

const (
	PacketOPEN  byte = 0x01
	PacketDATA  byte = 0x02
	PacketCLOSE byte = 0x03
	// keepalive + rtt probe: sent on every channel, answered in place,
	// never touches the reorder window or nat
	PacketPING byte = 0x04
	PacketPONG byte = 0x05

	AddrTypeIPv4   byte = 0x01
	AddrTypeDomain byte = 0x03

	// packets under this size ride several channels at once; bigger ones go round-robin
	DuplicationThreshold = 200

	WireXHeaderSize = 13
	IPv4Size        = 4

	maxDomainLength = 255
)

var (
	ErrMalformedPacket = errors.New("hydra: malformed wire-x packet")
	ErrUnknownAddrType = errors.New("hydra: unknown AddrType")
	ErrIPv6Unsupported = errors.New("hydra: wire-x v2 does not support IPv6")
)

type Header struct {
	Type      byte
	SessionID uint32
	FlowID    uint32
	Seq       uint32
}

func MarshalOPEN(sessionID, flowID, seq uint32, addrType byte, rawAddr []byte, port uint16, payload []byte) ([]byte, error) {
	body, err := appendAddress(nil, addrType, rawAddr)
	if err != nil {
		return nil, err
	}
	body = appendPort(body, port)
	out := make([]byte, 0, WireXHeaderSize+len(body)+len(payload))
	out = append(out, PacketOPEN)
	out = appendHeader(out, sessionID, flowID, seq)
	out = append(out, body...)
	out = append(out, payload...)
	return out, nil
}

func MarshalDATA(sessionID, flowID, seq uint32, payload []byte) []byte {
	out := make([]byte, 0, WireXHeaderSize+len(payload))
	out = append(out, PacketDATA)
	out = appendHeader(out, sessionID, flowID, seq)
	out = append(out, payload...)
	return out
}

func MarshalCLOSE(sessionID, flowID, seq uint32) []byte {
	out := make([]byte, 0, WireXHeaderSize)
	out = append(out, PacketCLOSE)
	out = appendHeader(out, sessionID, flowID, seq)
	return out
}

// ping/pong carry an 8-byte millisecond timestamp as body; pong echoes seq+ts
func MarshalPing(sessionID, seq uint32, tsMillis uint64) []byte {
	out := make([]byte, 0, WireXHeaderSize+8)
	out = append(out, PacketPING)
	out = appendHeader(out, sessionID, 0, seq)
	out = binary.BigEndian.AppendUint64(out, tsMillis)
	return out
}

func MarshalPong(sessionID, seq uint32, tsMillis []byte) []byte {
	out := make([]byte, 0, WireXHeaderSize+8)
	out = append(out, PacketPONG)
	out = appendHeader(out, sessionID, 0, seq)
	out = append(out, tsMillis[:8]...)
	return out
}

func ParseHeader(b []byte) (Header, []byte, error) {
	if len(b) < WireXHeaderSize {
		return Header{}, nil, ErrMalformedPacket
	}
	h := Header{
		Type:      b[0],
		SessionID: uint32(b[1])<<24 | uint32(b[2])<<16 | uint32(b[3])<<8 | uint32(b[4]),
		FlowID:    uint32(b[5])<<24 | uint32(b[6])<<16 | uint32(b[7])<<8 | uint32(b[8]),
		Seq:       uint32(b[9])<<24 | uint32(b[10])<<16 | uint32(b[11])<<8 | uint32(b[12]),
	}
	return h, b[WireXHeaderSize:], nil
}

func ParseOpenBody(body []byte) (addrType byte, rawAddr []byte, port uint16, payload []byte, err error) {
	if len(body) < 1 {
		return 0, nil, 0, nil, ErrMalformedPacket
	}
	addrType = body[0]
	switch addrType {
	case AddrTypeIPv4:
		if len(body) < 1+IPv4Size+2 {
			return 0, nil, 0, nil, ErrMalformedPacket
		}
		rawAddr = body[1 : 1+IPv4Size]
		port = uint16(body[1+IPv4Size])<<8 | uint16(body[1+IPv4Size+1])
		payload = body[1+IPv4Size+2:]
	case AddrTypeDomain:
		if len(body) < 2 {
			return 0, nil, 0, nil, ErrMalformedPacket
		}
		nameLen := int(body[1])
		if len(body) < 2+nameLen+2 {
			return 0, nil, 0, nil, ErrMalformedPacket
		}
		rawAddr = body[2 : 2+nameLen]
		port = uint16(body[2+nameLen])<<8 | uint16(body[2+nameLen+1])
		payload = body[2+nameLen+2:]
	default:
		return 0, nil, 0, nil, fmt.Errorf("%w: 0x%02X", ErrUnknownAddrType, addrType)
	}
	return addrType, rawAddr, port, payload, nil
}

func EncodeAddress(host string) (byte, []byte, error) {
	if host == "" {
		return 0, nil, errors.New("hydra: empty target address")
	}
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			return AddrTypeIPv4, append([]byte(nil), v4...), nil
		}
		return 0, nil, ErrIPv6Unsupported
	}
	if len(host) > maxDomainLength {
		return 0, nil, errors.New("hydra: target name too long")
	}
	return AddrTypeDomain, []byte(host), nil
}

func appendAddress(dst []byte, addrType byte, rawAddr []byte) ([]byte, error) {
	switch addrType {
	case AddrTypeIPv4:
		if len(rawAddr) != IPv4Size {
			return nil, fmt.Errorf("hydra: bad IPv4 address: %d bytes", len(rawAddr))
		}
		dst = append(dst, addrType)
		return append(dst, rawAddr...), nil
	case AddrTypeDomain:
		if len(rawAddr) == 0 || len(rawAddr) > maxDomainLength {
			return nil, fmt.Errorf("hydra: bad domain name: %d bytes", len(rawAddr))
		}
		dst = append(dst, addrType, byte(len(rawAddr)))
		return append(dst, rawAddr...), nil
	default:
		return nil, fmt.Errorf("%w: 0x%02X", ErrUnknownAddrType, addrType)
	}
}

func appendHeader(dst []byte, sessionID, flowID, seq uint32) []byte {
	dst = appendUint32(dst, sessionID)
	dst = appendUint32(dst, flowID)
	return appendUint32(dst, seq)
}

func appendPort(dst []byte, port uint16) []byte {
	return append(dst, byte(port>>8), byte(port))
}

func appendUint32(dst []byte, v uint32) []byte {
	return append(dst, byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}
