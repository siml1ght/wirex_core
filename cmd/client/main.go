package main

import (
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/siml1ght/wirex_core/internal/applog"
	"github.com/siml1ght/wirex_core/internal/client"
	"github.com/siml1ght/wirex_core/internal/proto"
)

const defaultKeyHex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"

const kDnsBasePort = 53

func main() {
	serverHost := flag.String("server", "127.0.0.1", "hydra-server address")
	portOffset := flag.Int("port-offset", 0, "offset for base channel ports (53, 3478)")
	portBase := flag.Int("port", 53, "base port of the DNS channel (equivalent to --port-offset port-53)")
	sessionID := flag.Uint("session", 0xC0FFEE01, "uint32 session id")
	keyHex := flag.String("key", defaultKeyHex, "32-byte ChaCha20-Poly1305 key, hex")
	secretAlias := flag.String("secret", "", "alias for --key")
	hopSecret := flag.String("hop-secret", "", "TOTP hopping secret (defaults to the key)")
	hopBase := flag.Int("hop-base", 44000, "first port of the hopping range")
	hopRange := flag.Int("hop-range", 10, "hopping range size (0 disables the channel)")
	verbose := flag.Bool("verbose", false, "log to stderr; without it the core is fully silent")
	flag.Parse()

	applog.SetVerbose(*verbose)

	offset := *portOffset
	if *portBase != 53 {
		offset = *portBase - kDnsBasePort
		if offset < 0 {
			fmt.Fprintf(os.Stderr, "hydra-client: --port %d is below the DNS base port (%d)\n", *portBase, kDnsBasePort)
			os.Exit(1)
		}
	}
	effectiveKey := *keyHex
	if *secretAlias != "" {
		effectiveKey = *secretAlias
	}
	key, err := hex.DecodeString(effectiveKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "hydra-client: bad key: %v\n", err)
		os.Exit(1)
	}
	channels, err := proto.ShiftedChannels(offset)
	if err != nil {
		fmt.Fprintf(os.Stderr, "hydra-client: %v\n", err)
		os.Exit(1)
	}
	secret := *hopSecret
	if secret == "" {
		secret = effectiveKey
	}

	cl, err := client.New(client.Config{
		ServerHost: *serverHost,
		SessionID:  uint32(*sessionID),
		Key:        key,
		Channels:   channels,
		Hopping: client.HoppingOptions{
			Secret: secret,
			Base:   *hopBase,
			Range:  *hopRange,
		},
		Core:    os.Stdin,
		Replies: os.Stdout,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "hydra-client: %v\n", err)
		os.Exit(1)
	}

	applog.Printf("[hydra-client] neko core mode: sess=%08X server=%s dns:%d stun:%d hop:%s",
		*sessionID, *serverHost, channels[0].Port, channels[1].Port, hopInfo(*hopBase, *hopRange))
	applog.Printf("[hydra-client] stdin: [len][ip:4][port:2][payload] frames, stdout: reply frames")

	done := make(chan struct{})
	go func() {
		cl.Wait()
		close(done)
	}()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	select {
	case <-ctx.Done():
	case <-done:
	}
	cl.Close()
	applog.Printf("[hydra-client] shutdown complete")
}

func hopInfo(base, size int) string {
	if size <= 0 {
		return "off"
	}
	return fmt.Sprintf("%d..%d", base, base+size-1)
}
