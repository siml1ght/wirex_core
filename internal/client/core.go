package client

import (
	"bufio"
	"io"
	"net"
	"time"

	"github.com/siml1ght/wirex_core/internal/applog"
	"github.com/siml1ght/wirex_core/internal/proto"
)

func (c *Client) startCore() {
	c.wgCore.Add(1)
	c.coreDone = make(chan struct{})
	go func() {
		defer c.wgCore.Done()
		c.readCore()
		// stdin closed: give in-flight replies a beat to drain, then tear down
		c.drainAndStop()
		close(c.coreDone)
	}()
}

// logs go to stderr only — stdout is reserved for binary reply frames
func (c *Client) readCore() {
	reader := bufio.NewReaderSize(c.cfg.Core, 1<<16)
	for {
		frameType, addr, port, payload, err := proto.ReadFrame(reader)
		if err != nil {
			if err != io.EOF {
				applog.Printf("[hydra-client] neko core stream ended: %v", err)
			}
			return
		}
		switch frameType {
		case proto.CoreFrameFromGame:
			target := net.IP(addr[:]).String()
			payloadCopy := append([]byte(nil), payload...)
			if err := c.SendGamePacket(target, port, payloadCopy); err != nil {
				applog.Printf("[hydra-client] core frame: %v", err)
			}
		case proto.CoreFrameClose:
			applog.Printf("[hydra-client] got CoreFrameClose")
			return
		default:
			applog.Printf("[hydra-client] unexpected core frame type 0x%02X", frameType)
		}
	}
}

func (c *Client) drainAndStop() {
	drain := c.cfg.Drain
	if drain <= 0 {
		drain = 500 * time.Millisecond
	}
	time.Sleep(drain)
	c.closeAllSockets()
}

// repliesMu serializes frame writes: stdout is a shared pipe, not a writer we own
func (c *Client) writeReply(flow *Flow, payload []byte) {
	if c.cfg.Replies == nil {
		return
	}
	var addr [4]byte
	if ip4 := flow.replyIP.To4(); ip4 != nil {
		copy(addr[:], ip4)
	}
	c.repliesMu.Lock()
	defer c.repliesMu.Unlock()
	if err := proto.WriteFrame(c.cfg.Replies, proto.CoreFrameToGame, addr, flow.replyPort, payload); err != nil {
		applog.Printf("[hydra-client] reply write: %v", err)
	}
}
