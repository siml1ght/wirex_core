package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"os"

	"github.com/siml1ght/wirex_core/internal/applog"
	"github.com/siml1ght/wirex_core/internal/proto"
	"github.com/siml1ght/wirex_core/internal/server"
)

const defaultKeyHex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"

const kDnsBasePort = 53

func parseKey(keyHex string) ([]byte, error) {
	key, err := hex.DecodeString(keyHex)
	if err != nil {
		return nil, fmt.Errorf("bad key: %w", err)
	}
	return key, nil
}

func main() {
	portOffset := flag.Int("port-offset", 0, "offset for base channel ports (53, 3478)")
	portBase := flag.Int("port", 53, "base port of the DNS channel (equivalent to --port-offset port-53)")
	idleTimeout := flag.Duration("idle-timeout", 0, "idle timeout for game flows (default 2m)")
	sweepEvery := flag.Duration("sweep-every", 0, "background sweep interval (default 15s)")
	keyHex := flag.String("key", defaultKeyHex, "32-byte ChaCha20-Poly1305 key, hex")
	secretAlias := flag.String("secret", "", "alias for --key")
	hopSecret := flag.String("hop-secret", "", "TOTP hopping secret (defaults to the key)")
	hopBase := flag.Int("hop-base", 44000, "first port of the hopping range")
	hopRange := flag.Int("hop-range", 10, "hopping pool size (0 disables the channel)")
	verbose := flag.Bool("verbose", false, "log to stderr; without it the server is fully silent")
	flag.Parse()

	applog.SetVerbose(*verbose)

	offset := *portOffset
	if *portBase != 53 {
		offset = *portBase - kDnsBasePort
		if offset < 0 {
			fmt.Fprintf(os.Stderr, "hydra-server: --port %d is below the DNS base port (%d)\n", *portBase, kDnsBasePort)
			os.Exit(1)
		}
	}
	effectiveKey := *keyHex
	if *secretAlias != "" {
		effectiveKey = *secretAlias
	}
	key, err := parseKey(effectiveKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "hydra-server: %v\n", err)
		os.Exit(1)
	}
	channels, err := proto.ShiftedChannels(offset)
	if err != nil {
		fmt.Fprintf(os.Stderr, "hydra-server: %v\n", err)
		os.Exit(1)
	}
	secret := *hopSecret
	if secret == "" {
		secret = effectiveKey
	}
	srv, err := server.NewWithOptions(key, server.Options{
		NAT: server.NATOptions{
			IdleTimeout:   *idleTimeout,
			SweepInterval: *sweepEvery,
		},
		Hopping: server.HoppingOptions{
			Secret: secret,
			Base:   *hopBase,
			Range:  *hopRange,
		},
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "hydra-server: %v\n", err)
		os.Exit(1)
	}
	applog.Printf("[hydra-server] up: dns:%d stun:%d hop:%d..%d (totp %s), idle-timeout=%s sweep=%s",
		channels[0].Port, channels[1].Port, *hopBase, *hopBase+*hopRange-1, secretLabel(secret), *idleTimeout, *sweepEvery)
	if err := srv.Listen(channels); err != nil {
		fmt.Fprintf(os.Stderr, "hydra-server: %v\n", err)
		os.Exit(1)
	}
}

func secretLabel(secret string) string {
	if len(secret) > 4 {
		return "****" + secret[len(secret)-4:]
	}
	return "****"
}
