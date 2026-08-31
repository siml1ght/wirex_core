package server

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/siml1ght/wirex_core/internal/applog"
	"github.com/siml1ght/wirex_core/internal/proto"
)

type HoppingOptions struct {
	Secret string
	Base   int
	Range  int
}

type Options struct {
	NAT     NATOptions
	Hopping HoppingOptions
}

type Server struct {
	codec *proto.Codec
	nat   *NAT
	hop   HoppingOptions

	listenersMu sync.RWMutex
	listeners   map[string]*listener

	stopOnce sync.Once
	stop     chan struct{}
	wg       sync.WaitGroup
}

type listener struct {
	ch   proto.Channel
	conn net.PacketConn
	hop  bool
}

func New(key []byte) (*Server, error) {
	return NewWithOptions(key, Options{})
}

func NewWithOptions(key []byte, opts Options) (*Server, error) {
	codec, err := proto.NewCodec(key)
	if err != nil {
		return nil, err
	}
	s := &Server{
		codec:     codec,
		listeners: make(map[string]*listener),
		stop:      make(chan struct{}),
		hop:       opts.Hopping,
	}
	s.nat = newNAT(s, opts.NAT)
	return s, nil
}

func (s *Server) NAT() *NAT {
	return s.nat
}

// each hop port gets its own listener; on Linux this scales fine up to the full range
func (s *Server) Listen(channels []proto.Channel) error {
	if len(channels) == 0 {
		return fmt.Errorf("hydra: no channels configured")
	}
	bound := make([]*listener, 0, len(channels)+s.hop.Range)
	defer func() {
		for _, l := range bound {
			l.conn.Close()
		}
	}()
	for _, ch := range channels {
		conn, err := net.ListenPacket("udp", fmt.Sprintf(":%d", ch.Port))
		if err != nil {
			return fmt.Errorf("hydra: channel %q port %d: %w", ch.Name, ch.Port, err)
		}
		l := &listener{ch: ch, conn: conn}
		bound = append(bound, l)
		s.listenersMu.Lock()
		s.listeners[ch.Name] = l
		s.listenersMu.Unlock()
		applog.Printf("[hydra-server] channel %q listening on UDP :%d (wire-x v2 + NAT)", ch.Name, ch.Port)
	}
	if s.hop.Range > 0 {
		for i := 0; i < s.hop.Range; i++ {
			port := s.hop.Base + i
			conn, err := net.ListenPacket("udp", fmt.Sprintf(":%d", port))
			if err != nil {
				return fmt.Errorf("hydra: hopping port %d: %w", port, err)
			}
			l := &listener{
				ch:   proto.Channel{Name: fmt.Sprintf("hop%d", i), Port: port},
				conn: conn,
				hop:  true,
			}
			bound = append(bound, l)
			s.listenersMu.Lock()
			s.listeners[l.ch.Name] = l
			s.listenersMu.Unlock()
		}
		applog.Printf("[hydra-server] hopping pool: %d ports %d..%d, totp window ±1 step (%s)",
			s.hop.Range, s.hop.Base, s.hop.Base+s.hop.Range-1, proto.HoppingStep)
	}
	s.nat.start()
	for _, l := range bound {
		s.wg.Add(1)
		go func(l *listener) {
			defer s.wg.Done()
			s.serve(l)
		}(l)
	}
	s.wg.Wait()
	return nil
}

func (s *Server) Close() {
	s.stopOnce.Do(func() {
		close(s.stop)
		s.nat.Shutdown()
		s.listenersMu.RLock()
		conns := make([]net.PacketConn, 0, len(s.listeners))
		for _, l := range s.listeners {
			conns = append(conns, l.conn)
		}
		s.listenersMu.RUnlock()
		for _, conn := range conns {
			conn.Close()
		}
	})
}

func (s *Server) serve(l *listener) {
	buf := make([]byte, 65535)
	for {
		n, src, err := l.conn.ReadFrom(buf)
		if err != nil {
			return
		}
		// hop ports only accept packets whose port matches the current totp step (±1)
		if l.hop && !proto.ValidateHoppingPort(s.hop.Secret, s.hop.Base, s.hop.Range, l.ch.Port, time.Now()) {
			continue
		}
		framed, err := proto.Unframe(l.ch.Prefix, buf[:n])
		if err != nil {
			continue
		}
		plain, err := s.codec.Decrypt(framed)
		if err != nil {
			continue
		}
		hdr, body, err := proto.ParseHeader(plain)
		if err != nil {
			continue
		}
		if hdr.Type != proto.PacketOPEN && hdr.Type != proto.PacketDATA && hdr.Type != proto.PacketCLOSE {
			continue
		}
		sess := s.nat.session(hdr.SessionID)
		sess.noteChannel(l.ch.Name, src)
		// dedup + reorder happen here; a later copy of the same seq dies inside the window
		sess.txReorder.Push(hdr.Seq, txMsg{typ: hdr.Type, flowID: hdr.FlowID, body: body}, func(seq uint32, m txMsg) {
			s.nat.handle(sess, m.typ, m.flowID, m.body)
		})
	}
}

// small replies are replicated via every channel the client has been seen on,
// big ones only via the last active one — mirrors the client-side policy
func (s *Server) sendToClient(sess *Session, typ byte, flowID uint32, payload []byte) {
	var plain []byte
	if typ == proto.PacketCLOSE {
		plain = proto.MarshalCLOSE(sess.SessionID, flowID, sess.rxSeq.Add(1))
	} else {
		plain = proto.MarshalDATA(sess.SessionID, flowID, sess.rxSeq.Add(1), payload)
	}
	enc, err := s.codec.Encrypt(plain)
	if err != nil {
		return
	}
	replicate := len(enc) < proto.DuplicationThreshold
	sess.mu.RLock()
	last := sess.lastChannel
	addrs := make(map[string]*net.UDPAddr, len(sess.clientAddrs))
	for k, v := range sess.clientAddrs {
		addrs[k] = v
	}
	sess.mu.RUnlock()
	for name, addr := range addrs {
		if !replicate && name != last {
			continue
		}
		s.listenersMu.RLock()
		l := s.listeners[name]
		s.listenersMu.RUnlock()
		if l == nil {
			continue
		}
		_, _ = l.conn.WriteTo(proto.Frame(l.ch.Prefix, enc), addr)
	}
}
