package server

import (
	"fmt"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/siml1ght/wirex_core/internal/applog"
	"github.com/siml1ght/wirex_core/internal/proto"
	"github.com/siml1ght/wirex_core/internal/reorder"
)

const (
	defaultIdleTimeout = 120 * time.Second
	defaultSweepEvery  = 15 * time.Second
)

type NATOptions struct {
	IdleTimeout   time.Duration
	SweepInterval time.Duration
}

type NATFlow struct {
	FlowID       uint32
	TargetAddr   *net.UDPAddr
	UDPConn      *net.UDPConn
	LastActivity time.Time
}

type txMsg struct {
	typ    byte
	flowID uint32
	body   []byte
}

type Session struct {
	SessionID uint32
	rxSeq     atomic.Uint32
	txReorder *reorder.Buffer[txMsg]
	mu        sync.RWMutex
	flows     map[uint32]*NATFlow
	// per-channel last seen client address; dupes are answered via every channel we've heard from
	clientAddrs map[string]*net.UDPAddr
	lastChannel string
}

func newSession(id uint32) *Session {
	return &Session{
		SessionID:   id,
		txReorder:   reorder.New[txMsg](),
		flows:       make(map[uint32]*NATFlow),
		clientAddrs: make(map[string]*net.UDPAddr),
	}
}

func (s *Session) noteChannel(name string, addr net.Addr) {
	ua, ok := addr.(*net.UDPAddr)
	if !ok {
		return
	}
	s.mu.Lock()
	s.clientAddrs[name] = ua
	s.lastChannel = name
	s.mu.Unlock()
}

type NAT struct {
	mu          sync.Mutex
	sessions    map[uint32]*Session
	server      *Server
	idleTimeout time.Duration
	sweepEvery  time.Duration
	stopOnce    sync.Once
	stop        chan struct{}
}

func newNAT(srv *Server, opts NATOptions) *NAT {
	idle := opts.IdleTimeout
	if idle <= 0 {
		idle = defaultIdleTimeout
	}
	sweep := opts.SweepInterval
	if sweep <= 0 {
		sweep = defaultSweepEvery
	}
	return &NAT{
		sessions:    make(map[uint32]*Session),
		server:      srv,
		idleTimeout: idle,
		sweepEvery:  sweep,
		stop:        make(chan struct{}),
	}
}

func (n *NAT) start() {
	go n.sweepLoop()
}

func (n *NAT) Shutdown() {
	n.stopOnce.Do(func() {
		close(n.stop)
	})
}

func (n *NAT) SessionCount() int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return len(n.sessions)
}

func (n *NAT) FlowCount() int {
	n.mu.Lock()
	defer n.mu.Unlock()
	total := 0
	for _, s := range n.sessions {
		s.mu.RLock()
		total += len(s.flows)
		s.mu.RUnlock()
	}
	return total
}

func (n *NAT) session(id uint32) *Session {
	n.mu.Lock()
	defer n.mu.Unlock()
	s, ok := n.sessions[id]
	if !ok {
		s = newSession(id)
		n.sessions[id] = s
	}
	return s
}

func (n *NAT) sweepLoop() {
	ticker := time.NewTicker(n.sweepEvery)
	defer ticker.Stop()
	for {
		select {
		case <-n.stop:
			return
		case <-ticker.C:
			n.sweepIdle()
		}
	}
}

// idle flows get their socket closed, a CLOSE frame and a map delete — otherwise fd leak
func (n *NAT) sweepIdle() {
	n.mu.Lock()
	sessions := make([]*Session, 0, len(n.sessions))
	for _, s := range n.sessions {
		sessions = append(sessions, s)
	}
	n.mu.Unlock()
	deadline := time.Now().Add(-n.idleTimeout)
	for _, sess := range sessions {
		var expired []uint32
		sess.mu.Lock()
		for id, f := range sess.flows {
			if f.LastActivity.Before(deadline) {
				expired = append(expired, id)
			}
		}
		sess.mu.Unlock()
		for _, id := range expired {
			n.dropFlow(sess, id)
			n.server.sendToClient(sess, proto.PacketCLOSE, id, nil)
		}
	}
}

// runs after the reorder window — NAT side effects stay in-order
func (n *NAT) handle(sess *Session, typ byte, flowID uint32, body []byte) {
	switch typ {
	case proto.PacketOPEN:
		n.handleOpen(sess, flowID, body)
	case proto.PacketDATA:
		n.handleData(sess, flowID, body)
	case proto.PacketCLOSE:
		n.dropFlow(sess, flowID)
	}
}

// OPEN repeats carry the first payload too, so an existing flow just forwards
func (n *NAT) handleOpen(sess *Session, flowID uint32, body []byte) {
	addrType, rawAddr, port, payload, err := proto.ParseOpenBody(body)
	if err != nil {
		return
	}
	target, err := resolveTarget(addrType, rawAddr, port)
	if err != nil {
		return
	}
	sess.mu.Lock()
	flow, ok := sess.flows[flowID]
	if !ok {
		conn, derr := net.DialUDP("udp", nil, target)
		if derr != nil {
			sess.mu.Unlock()
			applog.Printf("[hydra-nat] dial %s for flow %d: %v", target, flowID, derr)
			return
		}
		flow = &NATFlow{FlowID: flowID, TargetAddr: target, UDPConn: conn, LastActivity: time.Now()}
		sess.flows[flowID] = flow
		sess.mu.Unlock()
		go n.pumpResponses(sess, flow)
	} else {
		sess.mu.Unlock()
	}
	n.touch(sess, flow)
	if _, err := flow.UDPConn.Write(payload); err != nil {
		applog.Printf("[hydra-nat] flow %d (%s) write: %v", flowID, target, err)
	}
}

// DATA for a flow that doesn't exist yet is dropped on purpose — the OPEN reorder pass will fix it
func (n *NAT) handleData(sess *Session, flowID uint32, body []byte) {
	sess.mu.RLock()
	flow, ok := sess.flows[flowID]
	sess.mu.RUnlock()
	if !ok {
		return
	}
	n.touch(sess, flow)
	if _, err := flow.UDPConn.Write(body); err != nil {
		applog.Printf("[hydra-nat] flow %d (%s) write: %v", flowID, flow.TargetAddr, err)
	}
}

func (n *NAT) pumpResponses(sess *Session, flow *NATFlow) {
	buf := make([]byte, 65535)
	for {
		numRead, err := flow.UDPConn.Read(buf)
		if err != nil {
			return
		}
		sess.mu.RLock()
		alive := sess.flows[flow.FlowID] == flow
		sess.mu.RUnlock()
		if !alive {
			return
		}
		n.server.sendToClient(sess, proto.PacketDATA, flow.FlowID, buf[:numRead])
	}
}

func (n *NAT) dropFlow(sess *Session, flowID uint32) {
	sess.mu.Lock()
	flow, ok := sess.flows[flowID]
	if ok {
		delete(sess.flows, flowID)
	}
	sess.mu.Unlock()
	if ok {
		flow.UDPConn.Close()
	}
}

func (n *NAT) touch(sess *Session, flow *NATFlow) {
	sess.mu.Lock()
	flow.LastActivity = time.Now()
	sess.mu.Unlock()
}

func resolveTarget(addrType byte, rawAddr []byte, port uint16) (*net.UDPAddr, error) {
	switch addrType {
	case proto.AddrTypeIPv4:
		if len(rawAddr) != proto.IPv4Size {
			return nil, fmt.Errorf("hydra: bad IPv4 address: %d bytes", len(rawAddr))
		}
		return &net.UDPAddr{IP: net.IP(append([]byte(nil), rawAddr...)), Port: int(port)}, nil
	case proto.AddrTypeDomain:
		if len(rawAddr) == 0 {
			return nil, fmt.Errorf("hydra: empty domain")
		}
		return net.ResolveUDPAddr("udp", net.JoinHostPort(string(rawAddr), strconv.Itoa(int(port))))
	default:
		return nil, fmt.Errorf("hydra: unknown AddrType 0x%02X", addrType)
	}
}
