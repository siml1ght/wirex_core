package client

import (
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/siml1ght/wirex_core/internal/proto"
	"github.com/siml1ght/wirex_core/internal/reorder"
)

type HoppingOptions struct {
	Secret string
	Base   int
	Range  int
}

type Config struct {
	ServerHost string
	SessionID  uint32
	Key        []byte
	Channels   []proto.Channel
	Hopping    HoppingOptions
	Core       io.Reader
	Replies    io.Writer
	Drain      time.Duration
	DNSDomain  string
}

type Flow struct {
	ID        uint32
	targetKey string
	replyIP   net.IP
	replyPort uint16
}

type replyMsg struct {
	typ    byte
	flowID uint32
	body   []byte
}

type outChannel struct {
	name    string
	kind    proto.ChannelKind
	conn    *net.UDPConn
	dst     *net.UDPAddr
	srcPort int
	dynamic bool
	base    int
	size    int
	secret  string
	dns     *proto.DNSMask
	stun    *proto.StunMask
}

type Client struct {
	cfg        Config
	codec      *proto.Codec
	serverIP   net.IP
	channels   []outChannel
	txSeq      atomic.Uint32
	flowSeq    atomic.Uint32
	rr         atomic.Uint32
	closed     atomic.Bool
	closeOnce  sync.Once
	wg         sync.WaitGroup
	wgCore     sync.WaitGroup
	coreDone   chan struct{}
	repliesMu  sync.Mutex
	flowsMu    sync.RWMutex
	flowsByKey map[string]*Flow
	flowsByID  map[uint32]*Flow
	rxReorder  *reorder.Buffer[replyMsg]
}

func New(cfg Config) (*Client, error) {
	if len(cfg.Channels) == 0 {
		return nil, fmt.Errorf("hydra: no channels configured")
	}
	codec, err := proto.NewCodec(cfg.Key)
	if err != nil {
		return nil, err
	}
	raddr0, err := net.ResolveUDPAddr("udp", net.JoinHostPort(cfg.ServerHost, strconv.Itoa(cfg.Channels[0].Port)))
	if err != nil {
		return nil, fmt.Errorf("hydra: server address: %w", err)
	}
	c := &Client{
		cfg:        cfg,
		codec:      codec,
		serverIP:   raddr0.IP,
		channels:   make([]outChannel, 0, len(cfg.Channels)+1),
		flowsByKey: make(map[string]*Flow),
		flowsByID:  make(map[uint32]*Flow),
		rxReorder:  reorder.New[replyMsg](),
	}
	if err := c.buildChannels(); err != nil {
		c.closeAllSockets()
		return nil, err
	}
	c.wg.Add(len(c.channels))
	for i := range c.channels {
		go c.readChannel(&c.channels[i])
	}
	if cfg.Core != nil {
		c.startCore()
	}
	return c, nil
}

// the hop channel shares one socket and picks its port per send — that's the whole point
func (c *Client) buildChannels() error {
	dnsMask := &proto.DNSMask{Domain: c.cfg.DNSDomain}
	if dnsMask.Domain == "" {
		dnsMask.Domain = proto.DefaultDNSDomain
	}
	stunMask := &proto.StunMask{Software: "hydra"}
	for _, ch := range c.cfg.Channels {
		raddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(c.cfg.ServerHost, strconv.Itoa(ch.Port)))
		if err != nil {
			return fmt.Errorf("hydra: channel %q address: %w", ch.Name, err)
		}
		conn, err := net.ListenUDP("udp", nil)
		if err != nil {
			return fmt.Errorf("hydra: channel %q socket: %w", ch.Name, err)
		}
		oc := outChannel{
			name:    ch.Name,
			kind:    ch.Kind,
			conn:    conn,
			dst:     raddr,
			srcPort: ch.Port,
		}
		switch ch.Kind {
		case proto.KindDNS:
			oc.dns = dnsMask
		case proto.KindSTUN:
			oc.stun = stunMask
		}
		c.channels = append(c.channels, oc)
	}
	if c.cfg.Hopping.Range > 0 {
		conn, err := net.ListenUDP("udp", nil)
		if err != nil {
			return fmt.Errorf("hydra: hopping socket: %w", err)
		}
		c.channels = append(c.channels, outChannel{
			name:    "hop",
			kind:    proto.KindHop,
			conn:    conn,
			dst:     &net.UDPAddr{IP: c.serverIP},
			dynamic: true,
			base:    c.cfg.Hopping.Base,
			size:    c.cfg.Hopping.Range,
			secret:  c.cfg.Hopping.Secret,
		})
	}
	return nil
}

func (c *Client) FlowCount() int {
	c.flowsMu.RLock()
	defer c.flowsMu.RUnlock()
	return len(c.flowsByID)
}

func (c *Client) ChannelCount() int {
	return len(c.channels)
}

// first packet to a target goes out as OPEN, everything after is bare DATA — keeps the header at 13 bytes
func (c *Client) SendGamePacket(targetAddr string, targetPort uint16, payload []byte) error {
	flow, created := c.ensureFlow(targetAddr, targetPort)
	seq := c.txSeq.Add(1)
	var plain []byte
	if created {
		addrType, rawAddr, err := proto.EncodeAddress(targetAddr)
		if err != nil {
			return err
		}
		plain, err = proto.MarshalOPEN(c.cfg.SessionID, flow.ID, seq, addrType, rawAddr, targetPort, payload)
		if err != nil {
			return err
		}
	} else {
		plain = proto.MarshalDATA(c.cfg.SessionID, flow.ID, seq, payload)
	}
	return c.sendEncrypted(plain)
}

func (c *Client) Wait() {
	if c.coreDone != nil {
		<-c.coreDone
	}
	c.wg.Wait()
}

func (c *Client) Close() error {
	if !c.closed.CompareAndSwap(false, true) {
		return nil
	}
	c.closeAllSockets()
	return nil
}

func (c *Client) closeAllSockets() {
	c.closeOnce.Do(func() {
		for i := range c.channels {
			c.channels[i].conn.Close()
		}
	})
}

func (c *Client) ensureFlow(targetAddr string, targetPort uint16) (*Flow, bool) {
	key := net.JoinHostPort(targetAddr, strconv.Itoa(int(targetPort)))
	c.flowsMu.Lock()
	defer c.flowsMu.Unlock()
	f, ok := c.flowsByKey[key]
	if ok {
		return f, false
	}
	f = &Flow{ID: c.flowSeq.Add(1), targetKey: key, replyPort: targetPort}
	if ip4 := net.ParseIP(targetAddr).To4(); ip4 != nil {
		f.replyIP = append(net.IP(nil), ip4...)
	} else if resolved, err := net.ResolveIPAddr("ip4", targetAddr); err == nil {
		f.replyIP = resolved.IP.To4()
	}
	if f.replyIP == nil {
		f.replyIP = net.IPv4zero.To4()
	}
	c.flowsByKey[key] = f
	c.flowsByID[f.ID] = f
	return f, true
}

func (c *Client) removeFlow(flowID uint32) {
	c.flowsMu.Lock()
	defer c.flowsMu.Unlock()
	f, ok := c.flowsByID[flowID]
	if !ok {
		return
	}
	delete(c.flowsByID, flowID)
	delete(c.flowsByKey, f.targetKey)
}

// small packet (<200b) — replicate across all channels at once, zero loss on the fastest path;
// the server keeps the first copy and drops the dupes. big packets go round-robin to stay cheap.
func (c *Client) sendEncrypted(plain []byte) error {
	enc, err := c.codec.Encrypt(plain)
	if err != nil {
		return err
	}
	if len(enc) < proto.DuplicationThreshold {
		var wg sync.WaitGroup
		errs := make([]error, len(c.channels))
		for i := range c.channels {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				errs[i] = c.channels[i].write(enc)
			}(i)
		}
		wg.Wait()
		for _, err := range errs {
			if err != nil {
				return err
			}
		}
		return nil
	}
	idx := int(c.rr.Add(1)-1) % len(c.channels)
	return c.channels[idx].write(enc)
}

func (oc *outChannel) write(enc []byte) error {
	dst := oc.dst
	if oc.dynamic {
		dst = &net.UDPAddr{IP: oc.dst.IP, Port: proto.GetHoppingPort(oc.secret, oc.base, oc.size)}
	}
	wire, err := oc.camouflage(enc)
	if err != nil {
		return err
	}
	_, err = oc.conn.WriteToUDP(wire, dst)
	return err
}

// camouflaged datagram: valid dns/stun messages instead of bare prefixes
func (oc *outChannel) camouflage(enc []byte) ([]byte, error) {
	switch {
	case oc.dns != nil:
		return oc.dns.BuildQuery(enc)
	case oc.stun != nil:
		return oc.stun.BuildRequest(enc)
	default:
		return enc, nil
	}
}

// replies are only trusted from the server itself, and hop-channel replies must land inside the hop range
func (c *Client) acceptFrom(oc *outChannel, src *net.UDPAddr) bool {
	if !src.IP.Equal(c.serverIP) {
		return false
	}
	if oc.dynamic {
		return src.Port >= oc.base && src.Port < oc.base+oc.size
	}
	return src.Port == oc.srcPort
}

func (c *Client) readChannel(oc *outChannel) {
	defer c.wg.Done()
	buf := make([]byte, 65535)
	for {
		n, src, err := oc.conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		if !c.acceptFrom(oc, src) {
			continue
		}
		var framed []byte
		switch {
		case oc.dns != nil:
			if framed, err = oc.dns.ParseResponse(buf[:n]); err != nil || len(framed) == 0 {
				continue
			}
		case oc.stun != nil:
			if framed, _, err = oc.stun.ParseResponse(buf[:n]); err != nil || len(framed) == 0 {
				continue
			}
		default:
			framed = buf[:n]
		}
		plain, err := c.codec.Decrypt(framed)
		if err != nil {
			continue
		}
		hdr, body, err := proto.ParseHeader(plain)
		if err != nil {
			continue
		}
		if hdr.SessionID != c.cfg.SessionID {
			continue
		}
		if hdr.Type != proto.PacketDATA && hdr.Type != proto.PacketCLOSE {
			continue
		}
		c.rxReorder.Push(hdr.Seq, replyMsg{typ: hdr.Type, flowID: hdr.FlowID, body: body}, c.deliverReply)
	}
}

func (c *Client) deliverReply(seq uint32, msg replyMsg) {
	if msg.typ == proto.PacketCLOSE {
		c.removeFlow(msg.flowID)
		return
	}
	c.flowsMu.RLock()
	f := c.flowsByID[msg.flowID]
	c.flowsMu.RUnlock()
	if f == nil {
		return
	}
	c.writeReply(f, msg.body)
}
