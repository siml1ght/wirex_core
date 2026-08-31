package e2e

import (
	"bytes"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/siml1ght/wirex_core/internal/client"
	"github.com/siml1ght/wirex_core/internal/proto"
	"github.com/siml1ght/wirex_core/internal/server"
)

const testSession uint32 = 0xC0FFEE01

func testKey() []byte {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	return key
}

type fakeGame struct {
	conn *net.UDPConn
	mu   sync.Mutex
	got  [][]byte
	echo bool
}

func startFakeGame(t *testing.T, echo bool) *fakeGame {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	g := &fakeGame{conn: conn, echo: echo}
	t.Cleanup(func() { conn.Close() })
	go func() {
		buf := make([]byte, 65535)
		for {
			n, src, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			packet := append([]byte(nil), buf[:n]...)
			g.mu.Lock()
			g.got = append(g.got, packet)
			g.mu.Unlock()
			if g.echo {
				if _, err := conn.WriteToUDP(packet, src); err != nil {
					return
				}
			}
		}
	}()
	return g
}

func (g *fakeGame) addr() *net.UDPAddr {
	return g.conn.LocalAddr().(*net.UDPAddr)
}

func (g *fakeGame) count() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.got)
}

type replyFrame struct {
	addr [4]byte
	port uint16
	data []byte
}

type stack struct {
	cl       *client.Client
	requests io.Writer
	replies  chan replyFrame
}

func startStack(t *testing.T, portOffset, hopBase int, natOpts server.NATOptions, withCore bool) *stack {
	t.Helper()

	channels, err := proto.ShiftedChannels(portOffset)
	if err != nil {
		t.Fatal(err)
	}
	srv, err := server.NewWithOptions(testKey(), server.Options{
		NAT: natOpts,
		Hopping: server.HoppingOptions{
			Secret: "e2e-hop-secret",
			Base:   hopBase,
			Range:  10,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Listen(channels) }()
	t.Cleanup(srv.Close)
	time.Sleep(200 * time.Millisecond)

	s := &stack{replies: make(chan replyFrame, 64)}
	cfg := client.Config{
		ServerHost: "127.0.0.1",
		SessionID:  testSession,
		Key:        testKey(),
		Channels:   channels,
		Hopping: client.HoppingOptions{
			Secret: "e2e-hop-secret",
			Base:   hopBase,
			Range:  10,
		},
		Drain: 10 * time.Millisecond,
	}
	if withCore {
		inR, inW := io.Pipe()
		outR, outW := io.Pipe()
		cfg.Core = inR
		cfg.Replies = outW
		s.requests = inW
		t.Cleanup(func() {
			inW.Close()
			outR.Close()
		})
		go func() {
			for {
				_, _, port, payload, err := proto.ReadFrame(outR)
				if err != nil {
					close(s.replies)
					return
				}
				s.replies <- replyFrame{port: port, data: payload}
			}
		}()
	}
	cl, err := client.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cl.Close() })
	s.cl = cl
	return s
}

func (s *stack) sendCore(t *testing.T, ip [4]byte, port uint16, payload []byte) {
	t.Helper()
	if err := proto.WriteFrame(s.requests, proto.CoreFrameFromGame, ip, port, payload); err != nil {
		t.Fatal(err)
	}
}

func (s *stack) waitReply(t *testing.T, timeout time.Duration) replyFrame {
	t.Helper()
	select {
	case f, ok := <-s.replies:
		if !ok {
			t.Fatal("канал ответов закрыт до получения ответа")
		}
		return f
	case <-time.After(timeout):
		t.Fatal("ответ не получен вовремя")
		return replyFrame{}
	}
}

func TestFullRoundTripThroughNAT(t *testing.T) {
	game := startFakeGame(t, true)
	s := startStack(t, 40000, 44000, server.NATOptions{}, true)

	ga := game.addr()
	var ip4 [4]byte
	copy(ip4[:], ga.IP.To4())

	payload := []byte("game-request-packet")
	s.sendCore(t, ip4, uint16(ga.Port), payload)
	reply := s.waitReply(t, 3*time.Second)
	if !bytes.Equal(reply.data, payload) {
		t.Fatalf("ответ искажён: %q", reply.data)
	}
	if reply.port != uint16(ga.Port) {
		t.Fatalf("порт цели в ответе: %d, ожидался %d", reply.port, ga.Port)
	}
}

func TestThreeChannelsActive(t *testing.T) {
	game := startFakeGame(t, false)
	s := startStack(t, 40100, 44100, server.NATOptions{}, false)

	if s.cl.ChannelCount() != 3 {
		t.Fatalf("ожидалось 3 канала (dns, stun, hopping), есть %d", s.cl.ChannelCount())
	}
	if err := s.cl.SendGamePacket(game.addr().IP.String(), uint16(game.addr().Port), []byte("probe")); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return game.count() >= 1 }, "пакет не дошёл до игрового сервера")
}

func TestOpenThenDataCounts(t *testing.T) {
	game := startFakeGame(t, false)
	s := startStack(t, 40200, 44200, server.NATOptions{}, false)

	if err := s.cl.SendGamePacket(game.addr().IP.String(), uint16(game.addr().Port), []byte("first-open")); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return game.count() >= 1 }, "OPEN не дошёл до игрового сервера")

	if err := s.cl.SendGamePacket(game.addr().IP.String(), uint16(game.addr().Port), []byte("second-data")); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return game.count() >= 2 }, "DATA не дошёл до игрового сервера")
}

func TestIdleSweepClosesFlow(t *testing.T) {
	game := startFakeGame(t, false)
	s := startStack(t, 40300, 44300, server.NATOptions{IdleTimeout: 300 * time.Millisecond, SweepInterval: 100 * time.Millisecond}, false)

	if err := s.cl.SendGamePacket(game.addr().IP.String(), uint16(game.addr().Port), []byte("trigger-open")); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return game.count() >= 1 }, "OPEN не дошёл до игрового сервера")

	if s.cl.FlowCount() != 1 {
		t.Fatalf("ожидался 1 flow у клиента, есть %d", s.cl.FlowCount())
	}
	time.Sleep(900 * time.Millisecond)
	if s.cl.FlowCount() != 0 {
		t.Fatalf("CLOSE от сервера не удалил flow у клиента: %d", s.cl.FlowCount())
	}
}

func TestDuplicateSuppressionAcrossThreeChannels(t *testing.T) {
	game := startFakeGame(t, false)
	s := startStack(t, 40400, 44400, server.NATOptions{}, false)

	small := bytes.Repeat([]byte("d"), 40)
	if err := s.cl.SendGamePacket(game.addr().IP.String(), uint16(game.addr().Port), small); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(1 * time.Second)
	for time.Now().Before(deadline) {
		if game.count() > 1 {
			t.Fatalf("дубликат прошёл NAT через три канала: %d копий", game.count())
		}
		time.Sleep(20 * time.Millisecond)
	}
	if game.count() != 1 {
		t.Fatalf("ожидалась 1 копия, есть %d", game.count())
	}
}

func TestHopPortInvalidWithoutSecret(t *testing.T) {
	game := startFakeGame(t, false)
	channels, err := proto.ShiftedChannels(40500)
	if err != nil {
		t.Fatal(err)
	}
	srv, err := server.NewWithOptions(testKey(), server.Options{
		Hopping: server.HoppingOptions{Secret: "correct-secret", Base: 44500, Range: 10},
	})
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Listen(channels) }()
	t.Cleanup(srv.Close)
	time.Sleep(200 * time.Millisecond)

	codec, err := proto.NewCodec(testKey())
	if err != nil {
		t.Fatal(err)
	}
	plain, err := proto.MarshalOPEN(testSession, 1, 1, proto.AddrTypeIPv4, game.addr().IP.To4(), uint16(game.addr().Port), []byte("hop-inject"))
	if err != nil {
		t.Fatal(err)
	}
	enc, err := codec.Encrypt(plain)
	if err != nil {
		t.Fatal(err)
	}
	wrong := proto.HoppingPortForStep("wrong-secret", 44500, 10, proto.HoppingStepOf(time.Now()))
	// with a 10-port pool a random wrong port may collide with the valid ±1 window;
	// pick a step whose port is guaranteed outside it
	nowStep := proto.HoppingStepOf(time.Now())
	valid := map[int]bool{}
	for _, d := range []int64{-1, 0, 1} {
		valid[proto.HoppingPortForStep("correct-secret", 44500, 10, nowStep+d)] = true
	}
	for step := int64(1); valid[wrong]; step++ {
		wrong = proto.HoppingPortForStep("wrong-secret", 44500, 10, nowStep+step*7)
	}
	conn, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: wrong})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write(enc); err != nil {
		t.Fatal(err)
	}
	conn.Close()
	time.Sleep(400 * time.Millisecond)
	if game.count() != 0 {
		t.Fatalf("пакет на невалидный TOTP-порт прошёл на игровой сервер")
	}
}

func waitFor(t *testing.T, cond func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal(msg)
}
