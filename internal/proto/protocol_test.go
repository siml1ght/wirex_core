package proto

import (
	"bytes"
	"net"
	"testing"
)

func TestOpenIPv4RoundTrip(t *testing.T) {
	plain, err := MarshalOPEN(0xAABBCCDD, 7, 42, AddrTypeIPv4, net.IPv4(192, 168, 1, 10).To4(), 27015, []byte("payload-data"))
	if err != nil {
		t.Fatal(err)
	}
	hdr, body, err := ParseHeader(plain)
	if err != nil {
		t.Fatal(err)
	}
	if hdr.Type != PacketOPEN || hdr.SessionID != 0xAABBCCDD || hdr.FlowID != 7 || hdr.Seq != 42 {
		t.Fatalf("заголовок: %+v", hdr)
	}
	addrType, raw, port, payload, err := ParseOpenBody(body)
	if err != nil {
		t.Fatal(err)
	}
	if addrType != AddrTypeIPv4 || len(raw) != IPv4Size || !bytes.Equal(raw, net.IPv4(192, 168, 1, 10).To4()) {
		t.Fatalf("адрес: type=%d raw=%v", addrType, raw)
	}
	if port != 27015 {
		t.Fatalf("порт: %d", port)
	}
	if string(payload) != "payload-data" {
		t.Fatalf("payload: %q", payload)
	}
}

func TestOpenDomainRoundTrip(t *testing.T) {
	addrType, raw, err := EncodeAddress("game.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if addrType != AddrTypeDomain {
		t.Fatalf("addrType: %d", addrType)
	}
	plain, err := MarshalOPEN(1, 2, 3, addrType, raw, 1234, nil)
	if err != nil {
		t.Fatal(err)
	}
	hdr, body, err := ParseHeader(plain)
	if err != nil {
		t.Fatal(err)
	}
	gotType, gotAddr, gotPort, payload, err := ParseOpenBody(body)
	if err != nil {
		t.Fatal(err)
	}
	if hdr.Type != PacketOPEN || gotType != AddrTypeDomain {
		t.Fatalf("типы: %d/%d", hdr.Type, gotType)
	}
	if string(gotAddr) != "game.example.com" || gotPort != 1234 || len(payload) != 0 {
		t.Fatalf("адрес: %q:%d payload=%q", gotAddr, gotPort, payload)
	}
}

func TestDataAndCloseRoundTrip(t *testing.T) {
	plain := MarshalDATA(10, 20, 30, []byte("game-bytes"))
	hdr, body, err := ParseHeader(plain)
	if err != nil {
		t.Fatal(err)
	}
	if hdr.Type != PacketDATA || hdr.SessionID != 10 || hdr.FlowID != 20 || hdr.Seq != 30 {
		t.Fatalf("заголовок: %+v", hdr)
	}
	if string(body) != "game-bytes" {
		t.Fatalf("body: %q", body)
	}
	closePlain := MarshalCLOSE(10, 20, 31)
	hdr, body, err = ParseHeader(closePlain)
	if err != nil {
		t.Fatal(err)
	}
	if hdr.Type != PacketCLOSE || len(body) != 0 {
		t.Fatalf("CLOSE: %+v body=%v", hdr, body)
	}
}

func TestParseRejectsShortAndUnknown(t *testing.T) {
	if _, _, err := ParseHeader(make([]byte, 12)); err == nil {
		t.Fatal("короткий пакет должен отбрасываться")
	}
	if _, _, _, _, err := ParseOpenBody([]byte{0x99, 4, 1, 2, 3, 4, 0, 80}); err == nil {
		t.Fatal("неизвестный AddrType должен давать ошибку")
	}
	_, _, err := EncodeAddress("2001:db8::1")
	if err == nil {
		t.Fatal("IPv6 должен отклоняться")
	}
}
