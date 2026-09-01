package proto

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
)

func TestDNSQueryResponseRoundTrip(t *testing.T) {
	m := &DNSMask{Domain: DefaultDNSDomain}
	payload := bytes.Repeat([]byte{0xA5}, 200)

	q, err := m.BuildQuery(payload)
	if err != nil {
		t.Fatal(err)
	}
	if len(q) > maxDNSMessage {
		t.Fatalf("query too large: %d", len(q))
	}
	parsed, err := m.ParseQuery(q)
	if err != nil {
		t.Fatal(err)
	}
	if !parsed.Ours || !parsed.Valid {
		t.Fatalf("ours=%v valid=%v", parsed.Ours, parsed.Valid)
	}
	if !bytes.Equal(parsed.Payload, payload) {
		t.Fatalf("payload corrupted: %d bytes", len(parsed.Payload))
	}

	resp := m.BuildResponse(parsed.ID, parsed.Question, []byte("reply-data"))
	back, err := m.ParseResponse(resp)
	if err != nil {
		t.Fatal(err)
	}
	if string(back) != "reply-data" {
		t.Fatalf("response payload: %q", back)
	}
}

func TestDNSProbeForeign(t *testing.T) {
	m := &DNSMask{Domain: DefaultDNSDomain}

	// a real-world style query for example.com A record — must classify as foreign
	q := []byte{0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	for _, part := range []string{"www", "example", "com"} {
		q = append(q, byte(len(part)))
		q = append(q, part...)
	}
	q = append(q, 0, 0, 1, 0, 1)

	parsed, err := m.ParseQuery(q)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Ours || parsed.Payload != nil {
		t.Fatal("foreign query misclassified as ours")
	}
	if !parsed.Valid {
		t.Fatal("foreign query must stay a valid probe candidate")
	}
	resp := m.BuildResponse(parsed.ID, parsed.Question, nil)
	if len(resp) < dnsHeaderSize {
		t.Fatal("decoy response too small")
	}
	if binary.BigEndian.Uint16(resp[0:2]) != 0x1234 {
		t.Fatal("response id mismatch")
	}
}

func TestDNSMaxPayload(t *testing.T) {
	m := &DNSMask{Domain: DefaultDNSDomain}
	big := bytes.Repeat([]byte{0x11}, m.MaxPayload())
	if _, err := m.BuildQuery(big); err != nil {
		t.Fatalf("max payload rejected: %v", err)
	}
	if _, err := m.BuildQuery(append(big, 0x22)); err == nil {
		t.Fatal("over-budget payload accepted")
	}
}

func TestSTUNRequestResponseRoundTrip(t *testing.T) {
	s := &StunMask{Software: "hydra"}
	payload := bytes.Repeat([]byte{0x5A}, 150)

	req, err := s.BuildRequest(payload)
	if err != nil {
		t.Fatal(err)
	}
	if !IsStunRequest(req) {
		t.Fatal("not classified as binding request")
	}
	got, tx, err := s.ParseRequest(req)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload corrupted: %d bytes", len(got))
	}

	resp := s.BuildDataResponse(tx, []byte("stun-reply"))
	back, _, err := s.ParseResponse(resp)
	if err != nil {
		t.Fatal(err)
	}
	if string(back) != "stun-reply" {
		t.Fatalf("response payload: %q", back)
	}
}

func TestSTUNProbeGetsHonestResponse(t *testing.T) {
	s := &StunMask{Software: "hydra"}
	req, err := s.BuildRequest(nil)
	if err != nil {
		t.Fatal(err)
	}
	_, tx, err := s.ParseRequest(req)
	if err != nil {
		t.Fatal(err)
	}
	src := &net.UDPAddr{IP: net.IPv4(203, 0, 113, 7).To4(), Port: 51337}
	resp := s.BuildBindingResponse(tx, src)

	if !bytes.Contains(resp, []byte("hydra")) {
		t.Fatal("software attribute missing")
	}
	// decode XOR-MAPPED-ADDRESS and check it matches the source
	m := binary.BigEndian.Uint16(resp[0:2])
	if m&0x0110 != 0x0100 {
		t.Fatal("not a response")
	}
	attrs := resp[stunHeaderSize:]
	found := false
	for pos := 0; pos+4 <= len(attrs); {
		at := binary.BigEndian.Uint16(attrs[pos:])
		al := int(binary.BigEndian.Uint16(attrs[pos+2:]))
		if at == stunAttrXORMapped && al == 8 {
			port := binary.BigEndian.Uint16(attrs[pos+6:pos+8]) ^ uint16(StunMagic&0xFFFF)
			ip := net.IPv4(
				attrs[pos+8]^0x21,
				attrs[pos+9]^0x12,
				attrs[pos+10]^0xA4,
				attrs[pos+11]^0x42)
			if !ip.Equal(src.IP) || int(port) != src.Port {
				t.Fatalf("xor-mapped mismatch: %s:%d", ip, port)
			}
			found = true
		}
		pos += 4 + al
	}
	if !found {
		t.Fatal("XOR-MAPPED-ADDRESS attribute missing")
	}
}

func TestSTUNPaddingAlignment(t *testing.T) {
	s := &StunMask{}
	for size := 1; size <= 20; size++ {
		req, err := s.BuildRequest(bytes.Repeat([]byte{7}, size))
		if err != nil {
			t.Fatal(err)
		}
		got, _, err := s.ParseRequest(req)
		if err != nil {
			t.Fatalf("size %d: %v", size, err)
		}
		if !bytes.Equal(got, bytes.Repeat([]byte{7}, size)) {
			t.Fatalf("size %d: payload corrupted", size)
		}
	}
}

func TestDNSDomainCaseInsensitive(t *testing.T) {
	m := &DNSMask{Domain: "CDN-UPDATES.NET"}
	q, err := m.BuildQuery([]byte("ok"))
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := m.ParseQuery(q)
	if err != nil {
		t.Fatal(err)
	}
	if !parsed.Ours {
		t.Fatal("own query rejected due to domain case")
	}
}
