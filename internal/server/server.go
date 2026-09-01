package server

import (
	"fmt"
	"net"
	"os"
	"strings"
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
	// camouflage domain for the dns channel; must match the client
	DNSDomain string
	// dns probes are forwarded to this resolver (default: system, then 1.1.1.1)
	UpstreamDNS string
}

type Server struct {
	codec *proto.Codec
	nat   *NAT
	hop   HoppingOptions
	dns   *proto.DNSMask
	stun  *proto.StunMask

	// client binding-request txids (probes and data alike): server->client
	// data leaves as binding responses quoting one of these, FIFO
	txMu     sync.Mutex
	txQueue  [][12]byte
	txWaiter chan struct{}

	upstream     net.PacketConn
	upstreamAddr *net.UDPAddr
	upstreamDNS  string
	upstreamOnce sync.Once
	upstreamMu   sync.Mutex
	upstreamIn   map[uint16]chan []byte
	txid         uint16
	txidMu       sync.Mutex

	listenersMu sync.RWMutex
	listeners   map[string]*listener

	stopOnce sync.Once
	stop     chan struct{}
	wg       sync.WaitGroup
}

type listener struct {
	ch   proto.Channel
	conn net.PacketConn
	dns  *proto.DNSMask
	stun *proto.StunMask
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
	domain := opts.DNSDomain
	if domain == "" {
		domain = proto.DefaultDNSDomain
	}
	upstream := opts.UpstreamDNS
	if upstream == "" {
		upstream = systemResolver()
	}
	s := &Server{
		codec:       codec,
		listeners:   make(map[string]*listener),
		stop:        make(chan struct{}),
		hop:         opts.Hopping,
		dns:         &proto.DNSMask{Domain: domain},
		stun:        &proto.StunMask{Software: "hydra"},
		upstreamIn:  make(map[uint16]chan []byte),
		upstreamDNS: upstream,
	}
	s.nat = newNAT(s, opts.NAT)
	return s, nil
}

// rememberTx queues a client txid for server->client stun replies (FIFO, capped)
func (s *Server) rememberTx(tx [12]byte) {
	s.txMu.Lock()
	if len(s.txQueue) >= 64 {
		s.txQueue = s.txQueue[1:]
	}
	s.txQueue = append(s.txQueue, tx)
	s.txMu.Unlock()
}

func (s *Server) popTx() ([12]byte, bool) {
	s.txMu.Lock()
	defer s.txMu.Unlock()
	if len(s.txQueue) == 0 {
		return [12]byte{}, false
	}
	tx := s.txQueue[0]
	s.txQueue = s.txQueue[1:]
	return tx, true
}

// systemResolver picks the first nameserver from /etc/resolv.conf so dns
// probes look like they were answered by the host's own resolver
func systemResolver() string {
	data, err := os.ReadFile("/etc/resolv.conf")
	if err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "nameserver ") {
				ns := strings.TrimSpace(strings.TrimPrefix(line, "nameserver "))
				if ns != "" {
					return net.JoinHostPort(ns, "53")
				}
			}
		}
	}
	return "1.1.1.1:53"
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
		switch ch.Kind {
		case proto.KindDNS:
			l.dns = s.dns
		case proto.KindSTUN:
			l.stun = s.stun
		}
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
				ch:   proto.Channel{Name: fmt.Sprintf("hop%d", i), Port: port, Kind: proto.KindHop},
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
		if s.upstream != nil {
			s.upstream.Close()
		}
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
		var framed, reply []byte
		switch {
		case l.dns != nil:
			framed, reply = s.handleDNS(l, buf[:n])
		case l.stun != nil:
			framed, reply = s.handleSTUN(l, buf[:n], src)
		default: // hop channel carries bare encrypted wire-x
			framed = buf[:n]
		}
		if len(reply) > 0 && src != nil {
			l.conn.WriteTo(reply, src)
		}
		if len(framed) == 0 {
			continue
		}
		if framed, err = proto.UnPad(framed); err != nil {
			continue
		}
		s.acceptTunnelPacket(l, framed, src)
	}
}

// dns channel: tunnel data rides in a txt query; foreign queries are probes
// and get forwarded to a real resolver; own queries get an instant decoy
// answer (1 query = 1 response). tunnel replies never use this channel.
func (s *Server) handleDNS(l *listener, wire []byte) (framed, reply []byte) {
	q, err := l.dns.ParseQuery(wire)
	if err != nil {
		return nil, l.dns.BuildFormErr(txidOf(wire))
	}
	if !q.Ours {
		if q.Valid {
			if resp, ok := s.forwardUpstream(wire); ok {
				return nil, resp
			}
		}
		return nil, l.dns.BuildFormErr(q.ID)
	}
	return q.Payload, l.dns.BuildResponse(q.ID, q.Question, nil)
}

// stun channel: foreign binding requests get an honest xor-mapped-address
// response; own requests carry tunnel data, their txid goes into the reply
// queue so server-to-client data leaves as binding responses too
func (s *Server) handleSTUN(l *listener, wire []byte, src net.Addr) (framed, reply []byte) {
	payload, tx, err := l.stun.ParseRequest(wire)
	if err != nil {
		return nil, nil
	}
	srcAddr, _ := src.(*net.UDPAddr)
	if len(payload) == 0 {
		if srcAddr != nil {
			return nil, l.stun.BuildBindingResponse(tx, srcAddr)
		}
		return nil, nil
	}
	s.rememberTx(tx)
	return payload, nil
}

// upstream forwarding for dns probes: shared socket, fan-out by transaction id
func (s *Server) forwardUpstream(query []byte) ([]byte, bool) {
	if len(query) < 2 {
		return nil, false
	}
	s.upstreamOnce.Do(func() {
		conn, err := net.ListenPacket("udp", "0.0.0.0:0")
		if err != nil {
			applog.Printf("[hydra-server] upstream resolver socket: %v", err)
			return
		}
		addr, err := net.ResolveUDPAddr("udp", s.upstreamDNS)
		if err != nil {
			conn.Close()
			applog.Printf("[hydra-server] upstream resolver %q: %v", s.upstreamDNS, err)
			return
		}
		s.upstream = conn
		s.upstreamAddr = addr
		go s.upstreamReadLoop()
	})
	if s.upstream == nil {
		return nil, false
	}

	origID := []byte{query[0], query[1]}
	s.txidMu.Lock()
	s.txid++
	txid := s.txid
	ch := make(chan []byte, 1)
	s.upstreamIn[txid] = ch
	s.txidMu.Unlock()
	defer func() {
		s.txidMu.Lock()
		delete(s.upstreamIn, txid)
		s.txidMu.Unlock()
		close(ch)
	}()

	query = append([]byte(nil), query...)
	query[0], query[1] = byte(txid>>8), byte(txid)
	if _, err := s.upstream.WriteTo(query, s.upstreamAddr); err != nil {
		return nil, false
	}
	select {
	case resp := <-ch:
		if len(resp) >= 2 {
			// answer must match the probe's own transaction id
			resp[0], resp[1] = origID[0], origID[1]
		}
		return resp, true
	case <-time.After(2 * time.Second):
		return nil, false
	}
}

func (s *Server) upstreamReadLoop() {
	buf := make([]byte, 4096)
	for {
		n, _, err := s.upstream.ReadFrom(buf)
		if err != nil {
			return
		}
		if n < 2 {
			continue
		}
		txid := uint16(buf[0])<<8 | uint16(buf[1])
		s.txidMu.Lock()
		ch, ok := s.upstreamIn[txid]
		s.txidMu.Unlock()
		if ok {
			ch <- append([]byte(nil), buf[:n]...)
		}
	}
}

func txidOf(wire []byte) uint16 {
	if len(wire) < 2 {
		return 0
	}
	return uint16(wire[0])<<8 | uint16(wire[1])
}

func (s *Server) acceptTunnelPacket(l *listener, framed []byte, src net.Addr) {
	plain, err := s.codec.Decrypt(framed)
	if err != nil {
		return
	}
	hdr, body, err := proto.ParseHeader(plain)
	if err != nil {
		return
	}
	if hdr.Type == proto.PacketPING {
		// rtt probe: pong in place, same channel and port it came from
		if len(body) == 8 {
			pong := proto.MarshalPong(hdr.SessionID, hdr.Seq, body)
			if enc, err := s.codec.Encrypt(pong); err == nil {
				l.conn.WriteTo(proto.Pad(enc), src)
			}
		}
		return
	}
	if hdr.Type != proto.PacketOPEN && hdr.Type != proto.PacketDATA && hdr.Type != proto.PacketCLOSE {
		return
	}
	sess := s.nat.session(hdr.SessionID)
	sess.noteChannel(l, src)
	// dedup + reorder happen here; a later copy of the same seq dies inside the window
	sess.txReorder.Push(hdr.Seq, txMsg{typ: hdr.Type, flowID: hdr.FlowID, body: body}, func(seq uint32, m txMsg) {
		s.nat.handle(sess, m.typ, m.flowID, m.body)
	})
}

// replies must leave as valid protocol messages: hop = bare encrypted wire-x,
// stun = binding response carrying the payload (txid from the reply queue),
// dns = decoys only — tunnel replies never ride the dns channel.
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
	last := sess.lastCh
	addrs := make(map[string]*net.UDPAddr, len(sess.clientAddrs))
	for k, v := range sess.clientAddrs {
		addrs[k] = v
	}
	sess.mu.RUnlock()

	if last != nil {
		// last active channel first: it has the freshest path metrics
		s.sendOn(last, sess, enc, replicate)
	}
	for name := range addrs {
		s.listenersMu.RLock()
		l := s.listeners[name]
		s.listenersMu.RUnlock()
		if l == nil || l == last || l.dns != nil {
			continue
		}
		if !s.sendOn(l, sess, enc, replicate) {
			return
		}
	}
}

// sendOn dispatches one encrypted wire-x packet over a channel in its
// camouflage form; returns false when the caller should stop replicating
func (s *Server) sendOn(l *listener, sess *Session, enc []byte, replicate bool) bool {
	addr, ok := sess.clientAddrs[l.ch.Name]
	if !ok || l.dns != nil {
		return true
	}
	var wire []byte
	switch {
	case l.stun != nil:
		tx, ok := s.popTx()
		if !ok {
			return true
		}
		wire = l.stun.BuildDataResponse(tx, proto.Pad(enc))
	case l.hop:
		if !replicate {
			return false // big packet: one channel is enough, stop here
		}
		wire = proto.Pad(enc)
	default:
		return true
	}
	l.conn.WriteTo(wire, addr)
	return true
}
