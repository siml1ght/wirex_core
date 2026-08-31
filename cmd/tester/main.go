package main

import (
	"bufio"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"

	"github.com/siml1ght/wirex_core/internal/proto"
)

// debug relay that mimics the neko stdio bridge: udp datagrams in, wire frames to the core, replies back out.
// ingress datagrams use the core frame format [len][type][ip:4][port:2][payload] so the target is explicit.
func main() {
	local := flag.String("local", ":16335", "local UDP listen address")
	core := flag.String("core", "hydra-client.exe", "path to the hydra core binary")
	flag.Parse()
	coreArgs := flag.Args()

	cmd := exec.Command(*core, coreArgs...)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		die("stdin pipe: %v", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		die("stdout pipe: %v", err)
	}
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		die("spawn core: %v", err)
	}
	fmt.Fprintf(os.Stderr, "[tester] core spawned: %s %s\n", *core, strings.Join(coreArgs, " "))

	conn, err := net.ListenUDP("udp", resolve(*local))
	if err != nil {
		cmd.Process.Kill()
		die("local udp: %v", err)
	}
	fmt.Fprintf(os.Stderr, "[tester] relay listening on %s (send core-framed datagrams here)\n", conn.LocalAddr())

	clients := make(map[string]*net.UDPAddr)

	go func() {
		reader := bufio.NewReaderSize(stdout, 1<<16)
		for {
			frameType, addr, port, payload, err := proto.ReadFrame(reader)
			if err != nil {
				fmt.Fprintf(os.Stderr, "[tester] core stream ended: %v\n", err)
				conn.Close()
				return
			}
			if frameType != proto.CoreFrameToGame {
				continue
			}
			key := frameKey(addr, port)
			dst, ok := clients[key]
			if !ok {
				fmt.Fprintf(os.Stderr, "[tester] reply for unknown target %s dropped\n", key)
				continue
			}
			conn.WriteToUDP(payload, dst)
		}
	}()

	buf := make([]byte, 65535)
	go func() {
		for {
			n, src, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if len(buf) < 9 {
				continue
			}
			var dst [4]byte
			copy(dst[:], buf[3:7])
			port := uint16(buf[7])<<8 | uint16(buf[8])
			clients[frameKey(dst, port)] = src
			proto.WriteFrame(stdin, proto.CoreFrameFromGame, dst, port, buf[9:n])
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig
	fmt.Fprintln(os.Stderr, "[tester] shutting down")
	conn.Close()
	stdin.Close()
	cmd.Process.Kill()
}

func frameKey(addr [4]byte, port uint16) string {
	return fmt.Sprintf("%d.%d.%d.%d:%d", addr[0], addr[1], addr[2], addr[3], port)
}

func resolve(addr string) *net.UDPAddr {
	a, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		die("bad local address: %v", err)
	}
	return a
}

func die(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "[tester] "+format+"\n", args...)
	os.Exit(1)
}
