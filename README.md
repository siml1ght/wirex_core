# ⚡ Wire-X (Hydra) — High-Performance Multi-Path UDP Tunneling Protocol

A stateful UDP transport layer for online games and other low-latency traffic, engineered to survive DPI systems with AI-assisted behavioral analysis (traffic timing, packet sizing, tick-rate fingerprinting, per-flow IP:port correlation). The protocol fragments a game stream across several camouflage channels and reassembles it server-side, so no single flow ever looks like gameplay.

## ✦ Core Features & Architecture

### Polymorphic Multi-Path Transport

Client traffic is split across three independent channels, each wearing a different disguise:

| Channel | Wire destination | Camouflage |
|---------|-----------------|------------|
| `dns`   | UDP 53          | genuine RFC 1035 TXT queries — payload rides in a base32 QNAME under the camouflage domain |
| `stun`  | UDP 3478        | genuine RFC 8489 Binding Requests — payload rides in a comprehension-optional attribute |
| `hop`   | pseudo-random UDP ports | port derived as `SHA256(secret ‖ step)` over 5-second steps |

Datagrams leaving every channel are valid protocol messages, and the server answers probes honestly: foreign DNS queries are forwarded to a real recursive resolver and relayed back, foreign STUN probes get a genuine XOR-MAPPED-ADDRESS binding response, garbage gets FORMERR. A port scanner sees a working DNS resolver and a working STUN server — not silence.

Every channel carries identical ChaCha20-Poly1305-protected payloads; the entire Wire-X header — session, flow, sequence — lives inside the AEAD zone, so DPI never observes the internal addressing.

### Asynchronous Proactive Replication

Packets under 200 bytes (the dominant size class of game input: actions, inputs, movements) are encrypted once and sent over the **two channels with the lowest RTT** (measured continuously via keepalive pings on a jittered 0.8–1.4 s timer). The tunnel endpoint accepts whichever copy arrives first and drops the later ones; observed RTT converges to the fastest path at every millisecond, and single-channel loss becomes statistically irrelevant. Larger packets travel round-robin to conserve bandwidth.

### Traffic Shaping

Every encrypted packet is wrapped in a plaintext padding envelope (inside the AEAD zone) that snaps its size to one of the classes `{128, 256, 512, 1024}` bytes with crypto-random filler, collapsing the per-tick size distribution into four buckets. The same keepalive pings that carry RTT probes keep all channels breathing through idle windows, so traffic never goes silent and never ticks in a perfectly regular pattern.

### Stateful Flow Isolation

The server performs stateful UDP NAT keyed by `SessionID + FlowID`. Flow lifecycle is three packet types, compressing the in-band overhead to 13 bytes for the steady-state `DATA` case:

```
OPEN  (0x01): Type(1) SessionID(4) FlowID(4) TxSeq(4) AddrType(1) TargetAddr(var) TargetPort(2) Payload
DATA  (0x02): Type(1) SessionID(4) FlowID(4) Seq(4) Payload
CLOSE (0x03): Type(1) SessionID(4) FlowID(4) Seq(4)
```

Idle flows are swept by a background ticker (15 s interval, 120 s timeout): the server closes the NAT socket, emits `CLOSE`, and frees the mapping.

### Sequence Buffer & Serial Arithmetic

Both directions run a reorder/dedup window of 4096 sequence numbers. Ordering comparisons use 32-bit serial arithmetic per RFC 1982, so wrap-around at 2³² is handled correctly; anything below the accepted window is treated as a replay and destroyed before any NAT side effect takes place.

## 🚀 Quick Start (Server Deployment)

One command on a clean Ubuntu (amd64) VPS:

```bash
git clone https://github.com/siml1ght/wirex_core && cd wirex_core && chmod +x deploy/install.sh && ./deploy/install.sh
```

The installer verifies the environment, provisions Go if needed, builds `hydra-server`, opens UFW for `53/udp`, `3478/udp` and the hopping range, registers a systemd service, and prints the four parameters required by the client:

- **Server IP** — public address of the VPS
- **Base Port** — `53`
- **Secret Key** — freshly generated, 64 hex chars
- **Session ID** — freshly generated uint32

The service starts on boot and restarts on failure (`systemctl status hydra-server`).

## 🛠 Client Compilation

From a machine with Go 1.25+ (Windows or Linux), with the NekoBox fork checked out next to this repository:

```bash
make build-client
```

This cross-compiles `hydra-client.exe` (`windows/amd64`, console hidden via `-H windowsgui`) and installs it into the fork's resource tree (`resources/bin/` and the application root, where the runtime resource lookup expects it). Override the checkout location with `make build-client HYDRA_NKOBOX_DIR=/path/to/nekobox`.

## 🔌 NekoBox (NyameBox) Integration

1. Add Profile → protocol **Hydra-Tunnel**.
2. Fill in the four values printed by the server installer: **Server IP**, **Base Port**, **Secret Key**, **Session ID**.
3. Optional: hopping range and local relay port (defaults match the server defaults: `44000`, 10 ports, relay `16335`).
4. Enable TUN mode (or a per-game routing rule) so the game's UDP reaches the tunnel; everything else keeps going out directly.

The GUI launches `hydra-client.exe` as a stdio core: game datagrams flow in as length-prefixed frames, replies flow out, and diagnostics stay on stderr (add `--verbose` to the core arguments to see them).

## 🖥 Server Reference

| Flag | Default | Description |
|------|---------|-------------|
| `--port` | `53` | base port of the DNS channel (STUN = base + 3425) |
| `--secret` / `--key` | dev key | ChaCha20-Poly1305 key, 64 hex chars |
| `--session` | dev id | accepted session id (client must match) |
| `--hop-base` | `44000` | first port of the hopping range |
| `--hop-range` | `10` | hopping pool size (`0` disables the channel) |
| `--idle-timeout` | `2m` | flow inactivity timeout |
| `--sweep-every` | `15s` | background cleanup interval |
| `--verbose` | off | log to stderr; off = fully silent |
| `--dns-domain` | `cdn-updates.net` | camouflage domain for the DNS channel (must match on client and server) |
| `--dns-upstream` | system | resolver used to answer forwarded DNS probes (server only) |

The client accepts the same flags plus core I/O over stdin/stdout when launched by NekoBox. `--server` accepts either an IP or a **domain name**, bootstrapped over DoH (RFC 8484, Cloudflare/Google endpoints, system resolver fallback) so profiles never need to carry a bare address.

## License

MIT.
