package proto

import (
	"crypto/rand"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strings"
)

// dns channel disguise: payload rides in a base32 QNAME of a TXT query for
// the camouflage domain. everything on the wire is a real RFC 1035 message,
// sized under the classic 512-byte UDP limit.

const (
	DefaultDNSDomain = "cdn-updates.net"

	dnsHeaderSize = 12
	dnsTypeTXT    = 16
	dnsClassIN    = 1
	maxDNSMessage = 512

	dnsFlagQR = 0x8000
	dnsFlagRD = 0x0100
	dnsFlagRA = 0x0080
	dnsRCODE1 = 0x0001
)

var b32 = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)

var (
	ErrDNSQueryTooLong = errors.New("hydra-dns: payload does not fit the qname budget")
	ErrDNSMalformed    = errors.New("hydra-dns: malformed message")
	ErrDNSNoData       = errors.New("hydra-dns: no hydra data in message")
)

type DNSQuery struct {
	Payload  []byte // decoded tunnel payload (nil for probes)
	ID       uint16
	Question []byte // raw question section (echoed by responses)
	Ours     bool   // qname suffix matches the camouflage domain
	Valid    bool   // structurally valid RFC 1035 query (probe candidate)
}

type DNSMask struct{ Domain string }

func (m *DNSMask) domainLabels() []string {
	return strings.Split(strings.TrimSuffix(strings.ToLower(m.Domain), "."), ".")
}

func b32Len(payloadLen int) int { return (payloadLen*8 + 4) / 5 }

// wire length of the full qname: chars + one length byte per label +
// random anti-repetition label (hex, 6 chars) + terminator
func (m *DNSMask) qnameWireLen(encLen int) int {
	labels := (encLen + 62) / 63
	domainLabels := len(m.domainLabels())
	return encLen + labels + 7 + domainLabels + len(m.Domain) + 1
}

// MaxPayload: largest payload whose query stays inside the classic 512-byte
// UDP datagram; binary-searched because label boundaries make it piecewise
func (m *DNSMask) MaxPayload() int {
	lo, hi := 0, 512
	for lo < hi {
		mid := (lo + hi + 1) / 2
		if dnsHeaderSize+m.qnameWireLen(b32Len(mid))+4 <= maxDNSMessage {
			lo = mid
		} else {
			hi = mid - 1
		}
	}
	return lo
}

func dnsRandom(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}

// BuildQuery wraps the encrypted wire-x packet into a TXT lookup for a
// pseudo-random subdomain (random hex label defeats name repetition)
func (m *DNSMask) BuildQuery(payload []byte) ([]byte, error) {
	enc := b32.EncodeToString(payload)
	if dnsHeaderSize+m.qnameWireLen(len(enc))+4 > maxDNSMessage {
		return nil, ErrDNSQueryTooLong
	}
	out := make([]byte, 0, dnsHeaderSize+len(enc)+len(m.Domain)+24)
	var id [2]byte
	rand.Read(id[:])
	out = append(out, id[0], id[1], 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0)
	writeLabel := func(s string) {
		out = append(out, byte(len(s)))
		out = append(out, s...)
	}
	for off := 0; off < len(enc); off += 63 {
		end := off + 63
		if end > len(enc) {
			end = len(enc)
		}
		writeLabel(enc[off:end])
	}
	writeLabel(hex.EncodeToString(dnsRandom(3)))
	for _, dl := range m.domainLabels() {
		writeLabel(dl)
	}
	out = append(out, 0)
	out = binary.BigEndian.AppendUint16(out, dnsTypeTXT)
	out = binary.BigEndian.AppendUint16(out, dnsClassIN)
	return out, nil
}

// ParseQuery classifies an incoming datagram. Valid-but-foreign queries are
// probes: the server forwards them to a real recursive resolver.
func (m *DNSMask) ParseQuery(wire []byte) (*DNSQuery, error) {
	if len(wire) < dnsHeaderSize+5 {
		return nil, ErrDNSMalformed
	}
	q := &DNSQuery{Valid: true}
	q.ID = binary.BigEndian.Uint16(wire[0:2])

	pos := dnsHeaderSize
	var labels []string
	for {
		if pos >= len(wire) {
			return nil, ErrDNSMalformed
		}
		l := int(wire[pos])
		if l == 0 {
			pos++
			break
		}
		if l > 63 || pos+1+l >= len(wire) {
			return nil, ErrDNSMalformed
		}
		labels = append(labels, strings.ToLower(string(wire[pos+1:pos+1+l])))
		pos += 1 + l
	}
	if pos+4 > len(wire) {
		return nil, ErrDNSMalformed
	}
	qtype := binary.BigEndian.Uint16(wire[pos:])
	pos += 2
	qclass := binary.BigEndian.Uint16(wire[pos:])
	pos += 2
	if qtype != dnsTypeTXT || qclass != dnsClassIN {
		q.Question = append([]byte(nil), wire[dnsHeaderSize:pos]...)
		return q, nil
	}
	q.Question = append([]byte(nil), wire[dnsHeaderSize:pos]...)

	domain := m.domainLabels()
	if len(labels) <= len(domain) {
		return q, nil // valid foreign query
	}
	tail := labels[len(labels)-len(domain):]
	for i := range domain {
		if tail[i] != domain[i] {
			return q, nil // foreign
		}
	}
	body := strings.Join(labels[:len(labels)-len(domain)-1], "")
	payload, err := b32.DecodeString(strings.ToLower(body))
	if err != nil {
		return q, nil // looks like us but garbage payload — treat as foreign
	}
	q.Payload = payload
	q.Ours = true
	return q, nil
}

// BuildResponse echoes the question and answers with TXT: real payload for
// tunnel replies, random decoy data otherwise (1 query = 1 answer, always)
func (m *DNSMask) BuildResponse(id uint16, question []byte, payload []byte) []byte {
	data := payload
	if data == nil {
		data = dnsRandom(24)
	}
	enc := b32.EncodeToString(data)
	rdata := make([]byte, 0, len(enc)+len(enc)/255+1)
	for off := 0; ; off += 255 {
		end := off + 255
		if end > len(enc) {
			end = len(enc)
		}
		rdata = append(rdata, byte(end-off))
		rdata = append(rdata, enc[off:end]...)
		if end >= len(enc) {
			break
		}
	}

	answer := make([]byte, 0, len(rdata)+16)
	answer = append(answer, 0xC0, 0x0C)
	answer = binary.BigEndian.AppendUint16(answer, dnsTypeTXT)
	answer = binary.BigEndian.AppendUint16(answer, dnsClassIN)
	answer = binary.BigEndian.AppendUint32(answer, 60)
	answer = binary.BigEndian.AppendUint16(answer, uint16(len(rdata)))
	answer = append(answer, rdata...)

	flags := uint16(dnsFlagQR | dnsFlagRD | dnsFlagRA)
	out := make([]byte, 0, dnsHeaderSize+len(question)+len(answer))
	out = append(out, byte(id>>8), byte(id))
	out = binary.BigEndian.AppendUint16(out, flags)
	out = binary.BigEndian.AppendUint16(out, 1) // qdcount
	out = binary.BigEndian.AppendUint16(out, 1) // ancount
	out = binary.BigEndian.AppendUint16(out, 0)
	out = binary.BigEndian.AppendUint16(out, 0)
	out = append(out, question...)
	out = append(out, answer...)
	return out
}

// BuildFormErr answers unparseable garbage the way a real resolver would
func (m *DNSMask) BuildFormErr(id uint16) []byte {
	out := make([]byte, dnsHeaderSize)
	out[0], out[1] = byte(id>>8), byte(id)
	out[2], out[3] = byte(dnsFlagQR>>8), byte(dnsFlagQR&0xFF|dnsRCODE1)
	return out
}

// ParseResponse extracts the tunnel payload from a TXT answer; decoys decode
// to random bytes and are discarded by the caller
func (m *DNSMask) ParseResponse(wire []byte) ([]byte, error) {
	if len(wire) < dnsHeaderSize {
		return nil, ErrDNSMalformed
	}
	if binary.BigEndian.Uint16(wire[2:])&dnsFlagQR == 0 {
		return nil, ErrDNSMalformed
	}
	an := binary.BigEndian.Uint16(wire[6:8])
	if an < 1 {
		return nil, ErrDNSNoData
	}
	pos := dnsHeaderSize
	for {
		if pos >= len(wire) {
			return nil, ErrDNSMalformed
		}
		l := int(wire[pos])
		pos++
		if l == 0 {
			break
		}
		if l > 63 || pos+l > len(wire) {
			return nil, ErrDNSMalformed
		}
		pos += l
	}
	pos += 4 // qtype + qclass
	if pos+12 > len(wire) {
		return nil, ErrDNSMalformed
	}
	if wire[pos] != 0xC0 || wire[pos+1] != 0x0C {
		return nil, ErrDNSMalformed
	}
	pos += 2
	if binary.BigEndian.Uint16(wire[pos:]) != dnsTypeTXT {
		return nil, ErrDNSNoData
	}
	pos += 8 // type + class + ttl
	rdlen := int(binary.BigEndian.Uint16(wire[pos:]))
	pos += 2
	if pos+rdlen > len(wire) || rdlen < 1 {
		return nil, ErrDNSMalformed
	}
	var enc strings.Builder
	for p := pos; p < pos+rdlen; {
		sl := int(wire[p])
		p++
		if p+sl > pos+rdlen {
			return nil, ErrDNSMalformed
		}
		enc.WriteString(string(wire[p : p+sl]))
		p += sl
	}
	return b32.DecodeString(strings.ToLower(enc.String()))
}
