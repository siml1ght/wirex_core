package resolver

// minimal doh client (rfc 8484): binary dns over https, stdlib only.
// used to bootstrap the server address from a domain without leaking the
// lookup to the local resolver (and without a fixed ip in the config).

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

var dohEndpoints = []string{
	"https://1.1.1.1/dns-query",
	"https://8.8.8.8/dns-query",
}

func buildQuery(host string) []byte {
	qname := make([]byte, 0, len(host)+2)
	for _, label := range splitLabels(host) {
		qname = append(qname, byte(len(label)))
		qname = append(qname, label...)
	}
	qname = append(qname, 0)
	out := make([]byte, 0, 12+len(qname)+4)
	out = append(out, 0x6d, 0x73, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0) // rd=1
	out = append(out, qname...)
	out = binary.BigEndian.AppendUint16(out, 1) // a
	out = binary.BigEndian.AppendUint16(out, 1) // in
	return out
}

func splitLabels(host string) []string {
	var labels []string
	start := 0
	for i := 0; i <= len(host); i++ {
		if i == len(host) || host[i] == '.' {
			if i > start {
				labels = append(labels, host[start:i])
			}
			start = i + 1
		}
	}
	return labels
}

// ResolveHost returns an IPv4 for host: DoH first, system resolver fallback
func ResolveHost(host string) (net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			return v4, nil
		}
		return nil, fmt.Errorf("resolver: %s is not an ipv4 address", host)
	}
	var lastErr error
	for _, ep := range dohEndpoints {
		ip, err := dohResolve(ep, host)
		if err == nil {
			return ip, nil
		}
		lastErr = err
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		if lastErr != nil {
			return nil, fmt.Errorf("resolver: %s: doh failed (%v), system failed (%w)", host, lastErr, err)
		}
		return nil, fmt.Errorf("resolver: %s: %w", host, err)
	}
	for _, ip := range ips {
		if v4 := ip.To4(); v4 != nil {
			return v4, nil
		}
	}
	return nil, fmt.Errorf("resolver: no ipv4 for %s", host)
}

func dohResolve(endpoint, host string) (net.IP, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(buildQuery(host)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("doh: http %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return nil, err
	}
	return parseA(body)
}

func parseA(msg []byte) (net.IP, error) {
	if len(msg) < 12 {
		return nil, fmt.Errorf("resolver: short dns reply")
	}
	an := int(binary.BigEndian.Uint16(msg[6:8]))
	pos := 12
	skipName := func() error {
		for {
			if pos >= len(msg) {
				return fmt.Errorf("resolver: truncated name")
			}
			l := int(msg[pos])
			pos++
			if l == 0 {
				return nil
			}
			if l&0xC0 == 0xC0 {
				pos++
				return nil
			}
			pos += l
		}
	}
	if err := skipName(); err != nil {
		return nil, err
	}
	pos += 4 // qtype qclass
	for i := 0; i < an; i++ {
		if err := skipName(); err != nil {
			return nil, err
		}
		if pos+10 > len(msg) {
			return nil, fmt.Errorf("resolver: truncated rr")
		}
		rdlen := int(binary.BigEndian.Uint16(msg[pos+8 : pos+10]))
		pos += 10
		if pos+rdlen > len(msg) {
			return nil, fmt.Errorf("resolver: truncated rdata")
		}
		if rdlen == 4 {
			return net.IP(append([]byte(nil), msg[pos:pos+4]...)), nil
		}
		pos += rdlen
	}
	return nil, fmt.Errorf("resolver: no a record")
}
