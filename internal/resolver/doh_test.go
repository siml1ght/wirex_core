package resolver

import "testing"

func TestBuildQueryShape(t *testing.T) {
	q := buildQuery("example.com")
	if len(q) < 12+13+4 {
		t.Fatalf("query too short: %d", len(q))
	}
	if q[2]&0x01 != 0x01 {
		t.Fatal("rd flag not set")
	}
	if got := q[12]; got != 7 {
		t.Fatalf("first label length %d, want 7", got)
	}
	if string(q[13:20]) != "example" {
		t.Fatalf("label mismatch: %q", q[13:20])
	}
}

func TestSplitLabels(t *testing.T) {
	got := splitLabels("a.b.example.com")
	want := []string{"a", "b", "example", "com"}
	if len(got) != len(want) {
		t.Fatalf("labels: %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("labels: %v", got)
		}
	}
}

func TestParseAReply(t *testing.T) {
	// hand-built reply: header, question (example.com a in), one a rr
	msg := []byte{
		0x6d, 0x73, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0,
		7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0,
		0, 1, 0, 1,
		0xC0, 0x0C, // ptr to name
		0, 1, 0, 1, // a, in
		0, 0, 0, 60, // ttl
		0, 4, 93, 184, 216, 34, // rdlen + 93.184.216.34
	}
	ip, err := parseA(msg)
	if err != nil {
		t.Fatal(err)
	}
	if ip.String() != "93.184.216.34" {
		t.Fatalf("got %s", ip)
	}
}

func TestResolveHostIPPassthrough(t *testing.T) {
	ip, err := ResolveHost("93.184.216.34")
	if err != nil {
		t.Fatal(err)
	}
	if ip.String() != "93.184.216.34" {
		t.Fatalf("got %s", ip)
	}
	if _, err := ResolveHost("::1"); err == nil {
		t.Fatal("ipv6 must be rejected")
	}
}
