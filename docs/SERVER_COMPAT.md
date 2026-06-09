# Server-side compatibility requirements

This document is for an engineer who maintains the **WG server-side
proxy** (typically `Moroka8/vk-turn-proxy` running on the host that
WireGuard ultimately terminates at, e.g. `77.90.8.199:56010` in our
current setup).

The iOS TurnBridge client has evolved past the upstream proxy in a
handful of ways. Most of the changes don't need server cooperation —
the TLS-fingerprint impersonation, the captcha-v2 algorithm changes,
the runtime memory tunings all live in the client. The exceptions are
listed below; without these the corresponding feature either silently
no-ops or breaks the data path entirely.

Versions referenced below come from
`truvvor/turnbridge@claude/build-project-br5tJ`. The client today is
**1.3.18**.

---

## 1. SRTP/Opus mimicry wrap (**REQUIRED for any client where wrap key is set**) — HIGHEST PRIORITY

### What it is

A custom AEAD layer placed **between** our DTLS-over-TURN payload and
the TURN ChannelData frame on the wire. The wrapper re-frames each
DTLS record (or any other payload our client sends through the relay)
into a packet that looks byte-identical to a real WebRTC SRTP/Opus
voice frame.

VK's TURN relay appears to fast-path SRTP-shaped ChannelData payloads
and rate-limit anything that doesn't match (DTLS application-data
records are the dominant pattern that gets throttled).

### Where in the data path

```
   Client side (iOS)               Server side (vk-turn-proxy)
   ----------------                ---------------------------
   WireGuard packets               WireGuard packets
        |                                 ^
        v                                 |
      DTLS encrypt                     DTLS decrypt
        |                                 ^
        v                                 |
   ┌─ wrap.wrapInto ─┐               ┌─ wrap.unwrapPacket ─┐
   │  prepend RTP    │               │  AEAD-verify         │
   │  hdr + nonce,   │  ───────────▶ │  strip RTP+nonce,    │
   │  AEAD-encrypt   │   ChannelData │  return plaintext    │
   └─────────────────┘   over TURN   └──────────────────────┘
        |                                 ^
        v                                 |
   TURN ChannelData              TURN ChannelData receive
        |                                 ^
        v                                 |
       UDP socket  ───── wire ──────  VK TURN relay (forwards opaque
                                       ChannelData byte-for-byte)
```

The wrap is **outside DTLS** (DTLS payloads are the plaintext fed into
wrap), and **inside TURN** (wrapped bytes are the payload of the
ChannelData frame). The TURN relay never sees inside the wrap, never
sees inside DTLS, so neither the WireGuard tunnel nor the wrap key
need to be known to VK.

### Reference implementation

Verbatim source: `wireguard-apple/Sources/WireGuardKitGo/wrap.go` in
the truvvor repo, which is itself a verbatim port of
`pkg/clientcore/wrap.go` from `Moroka8/vk-turn-proxy`. If
`Moroka8/vk-turn-proxy` is what you're patching, **the file already
exists in your tree** — the port mirrors it exactly.

### Wire format

Per packet, the wrap layer produces / consumes:

```
[ 12-byte RTP header | 12-byte explicit nonce | AEAD ciphertext | 16-byte tag ]
```

Layout details:

| Offset | Length | Content |
|---|---|---|
| 0     | 1  | `0x80` — RTP version=2, P=0, X=0, CC=0 |
| 1     | 1  | `0x6F` — Marker=0, payload type 111 (Opus) |
| 2     | 2  | Sequence number, big-endian, monotonic, init random |
| 4     | 4  | Timestamp, big-endian, monotonic, **+960 per packet** (20 ms at 48 kHz Opus framing) |
| 8     | 4  | SSRC (random per `wrapConn`, MSB encodes direction) |
| 12    | 4  | nonce part 1: sessionID (random per `wrapConn`, MSB matches SSRC MSB) |
| 16    | 8  | nonce part 2: counter, big-endian, monotonic, init random uint64 |
| 24    | N  | AEAD ciphertext (length == plaintext length) |
| 24+N  | 16 | AEAD authentication tag |

Total overhead per packet: **40 bytes** (12 header + 12 nonce + 16 tag).

### AEAD

- **Algorithm:** ChaCha20-Poly1305 (RFC 7539). NOT AES-GCM. Real
  WebRTC SRTP usually uses AES-GCM (RFC 7714); the ciphertext+tag
  lengths are identical so the wire shape matches regardless. We use
  ChaCha20-Poly1305 because it's faster than AES-GCM on mobile CPUs
  without AES-NI and the wire fingerprint doesn't expose the cipher.
- **Key:** 32 bytes, shared between client and server out of band.
- **Nonce:** the 12-byte explicit nonce field (offset 12-23). Both
  endpoints use the **same key** but **disjoint nonce subspaces** via
  the direction bit (below) and per-conn random init, so accidental
  nonce reuse is computationally impossible.
- **AAD:** the first 24 bytes of the packet (RTP header || nonce). This
  authenticates the SSRC/seq/timestamp so VK can't reorder packets to
  smuggle different ciphertext to a different sequence position.

### Per-`wrapConn` state initialisation

Each `wrapConn` is created on session start (one per `oneTurnConnection`
on the client side; one per equivalent on the server side). State to
initialise:

| Field | Width | How initialised |
|---|---|---|
| `sessionID[0..4]` | 4 bytes | `crypto/rand`; then byte 0 has its high bit set/cleared by direction |
| `ssrc[0..4]`      | 4 bytes | `crypto/rand`; then byte 0 has its high bit set/cleared by direction |
| `seq`             | uint32  | `crypto/rand`-derived random uint16 stored into a uint32 |
| `timestamp`       | uint32  | random uint32 from `crypto/rand` |
| `counter`         | uint64  | random uint64 from `crypto/rand` |

### Direction bit (CRITICAL — server-side requires `isServer=true`)

The client builds `wrapConn` with `isServer=false`:
```go
sessionID[0] &^= 0x80   // clear MSB
ssrc[0] &^= 0x80        // clear MSB
```

The server **MUST** build `wrapConn` with `isServer=true`:
```go
sessionID[0] |= 0x80    // set MSB
ssrc[0] |= 0x80         // set MSB
```

This guarantees that even with the same shared AEAD key the two ends
write into completely disjoint nonce spaces — client packets always
have `nonce[0] & 0x80 == 0`, server packets always have
`nonce[0] & 0x80 == 1`. This is a hard correctness requirement, not a
defense-in-depth nicety: if both ends pick the same direction the
counter+sessionID space collides and AEAD reuse is possible.

### Encrypt path (client → relay → server)

```go
seq := w.seq.Add(1) - 1                  // atomic monotonic
ts := w.timestamp.Add(960) - 960         // atomic monotonic, +960/packet

dst[0] = 0x80
dst[1] = 0x6F
binary.BigEndian.PutUint16(dst[2:4], uint16(seq))
binary.BigEndian.PutUint32(dst[4:8], ts)
copy(dst[8:12], w.ssrc[:])

copy(dst[12:16], w.sessionID[:])
ctr := w.counter.Add(1) - 1              // atomic monotonic
binary.BigEndian.PutUint64(dst[16:24], ctr)

nonce := dst[12:24]
aad   := dst[:24]
copy(dst[24:], plaintext)
aead.Seal(dst[24:24], nonce, dst[24:24+len(plaintext)], aad)

// dst now contains wireLen = 24 + len(plaintext) + 16 bytes.
```

### Decrypt path (relay → server)

```go
if len(wire) < 24+16 { return error("short") }

nonce := wire[12:24]
aad   := wire[:24]
ct    := wire[24:]

plain, err := aead.Open(ct[:0], nonce, ct, aad)
if err != nil { return error("AEAD"); /* drop packet, do NOT tear down */ }
// hand `plain` to the DTLS terminator (the next layer up).
```

### Server-side error handling

- **AEAD-open failure on a single packet:** drop the packet, **do
  not** tear down the TURN allocation or the WireGuard session. The
  most common cause of a one-off AEAD failure is a stray un-wrapped
  packet arriving right at session bring-up (the client hasn't fully
  configured wrap yet, or the relay re-delivered an old datagram).
  Continue reading from the relay.
- **Repeated AEAD failures (e.g., >100 in a row from the same client
  5-tuple):** log + close that allocation. Almost always indicates a
  key mismatch.
- **Out-of-order packets (sequence regression):** accept them
  silently. Our pipeline downstream of wrap is DTLS, which already
  has its own anti-replay (32-packet replay window per RFC 6347), and
  WireGuard's anti-replay is downstream of that. The wrap layer
  itself is anti-replay-naive on purpose — adding a window here would
  break legitimate reordering that the lower-layer crypto tolerates.

### Config surface on the server

Exactly one operator-supplied input:

- **Wrap key** — 64 hex chars (32 bytes after decoding). Same value
  that the iOS client has configured. Provided via either:
  - a CLI flag (`-wrap -wrap-key=<hex>` is what `Moroka8/vk-turn-proxy`
    already uses), or
  - an env var (`WRAP_KEY=<hex>` is cleaner for systemd / Docker).

If the key is empty / unset, the server should accept un-wrapped
ChannelData payloads (legacy DTLS-over-TURN, what we used before
1.3.18). Mixing per-allocation (wrap on for some sessions, off for
others) is acceptable; the server can sniff the first datagram per
allocation:

- if bytes `[0:2] == 0x80 0x6F` → wrap on, run unwrap path
- otherwise → un-wrapped, run legacy path

This auto-detect lets the operator deploy the server with WRAP
support without coordinating a sharp cutover on the client side.

### What MUST NOT change

- **Don't validate the RTP header semantically.** Specifically:
  don't reject packets with a regressing sequence number, don't
  enforce the +960 timestamp step, don't reject mismatched SSRCs
  within a session. The header is purely cover-traffic for VK's DPI
  — the AEAD AAD makes any tampering AEAD-fail, so semantic
  validation buys no security and costs you legitimate packets.
- **Don't add additional metadata** before or after the wrap envelope.
  Anything you prepend or append moves the visible TURN ChannelData
  payload away from the SRTP/Opus shape, defeating the whole
  point.
- **Don't reuse the wrap key across unrelated client groups.** AEAD
  with a shared key requires disjoint nonce spaces; the direction
  bit handles client-vs-server, but two independent client devices
  sharing the same key would collide. Each (client, server) pair
  needs its own key.

---

## 2. Stream Aggregation 17-byte preamble (**existing — confirm support**)

The client already sends a 17-byte preamble at the start of every
DTLS stream when `streamAggregation=true` (default for our deployment):

```
[16-byte sessionID | 1-byte streamID]
```

`Moroka8/vk-turn-proxy` already supports this — no change needed —
but flagging it here so the patching engineer knows it's still on the
wire and the wrap layer (item 1) wraps the preamble too. The preamble
is plaintext inside DTLS, so on the server side it's seen AFTER both
the wrap and the DTLS layers are stripped.

---

## 3. TURN allocation count (**no protocol change**)

Client may open up to **100 concurrent TURN allocations** against the
same relay (default cap 60, configurable up to 100). Each is a normal
RFC 5766 Allocate with long-term auth; no protocol extension. The
server only needs to ensure its TURN allocation limit per source IP
isn't lower than the client's `N`.

---

## 4. Minimal TURN client behaviour (**informational**)

As of 1.3.16 the iOS client uses a hand-rolled minimal TURN client
(`turn_min.go`) instead of `github.com/pion/turn/v5`. From the relay's
perspective this is a **pure RFC 5766 client** — Allocate with
long-term auth (REALM + NONCE challenge), ChannelBind for the single
peer, ChannelData for the data plane, Refresh at half-lifetime. No
extension attributes, no proprietary tweaks. Any RFC-5766-compliant
relay (which is what the VK TURN servers and what `Moroka8/vk-turn-
proxy` already implement) accepts these unchanged.

If the server is patched at the same time as a wrap rollout, the
server's TURN client (used to dial the upstream VK relay on behalf of
WireGuard if the deployment proxies via TURN — `Moroka8`'s setup
doesn't normally do this, but mention it for completeness) likewise
needs no change.

---

## Checklist for the server engineer

1. [ ] Pull the latest `Moroka8/vk-turn-proxy` (or your fork). Confirm
       `pkg/clientcore/wrap.go` (and `wrap_test.go`) exist and pass
       `go test ./...`.
2. [ ] Decide how the server consumes the wrap key — CLI flag or env
       var. Both are fine; pick one for consistency with the rest of
       the deployment.
3. [ ] On the server's per-allocation receive loop, before passing
       the ChannelData payload to the DTLS terminator, branch on
       wrap-on (`payload[0:2] == 0x80 0x6F`) vs wrap-off (legacy). On
       wrap-on, run `wrapConn.unwrapPacket`. AEAD failure on a single
       packet → drop, continue.
4. [ ] On the server's per-allocation send loop, after the DTLS
       terminator hands you the encrypted bytes and before you stuff
       them into a ChannelData frame, run `wrapConn.wrapInto`. The
       `wrapConn` was built once with `isServer=true` at allocation
       setup.
5. [ ] Test against the iOS client at 1.3.18:
       - Set the same key on both ends.
       - Connect. Confirm in client logs: `wrap: enabled (key set,
         32 bytes)` at startup and at least one `Established DTLS
         connection!` per session.
       - Confirm in server logs no `AEAD open` errors after the first
         packet.
       - Pull data through the tunnel (any HTTP through the WG
         interface). Confirm throughput and that VK's relay isn't
         shaping (sustained ≥1 Mbps per session over several minutes
         is the smoke test).
6. [ ] **Backwards compat smoke**: with wrap key set on the server,
       connect a 1.3.17 client (no wrap support) and confirm the
       legacy path still works because the server's first-packet
       sniff falls through to the un-wrapped branch.

---

## Out-of-scope on the server

These are client-side only and the server should ignore:

- **TLS fingerprint impersonation** (`bogdanfinn/tls-client` + `fhttp`,
  Safari iOS 18 profile). Only affects the iOS↔VK captcha API path,
  which is captcha-service traffic to `api.vk.com`/`id.vk.com`, not
  WG-relay traffic.
- **Captcha v2 algorithm** (dynamic `debug_info`, slim device shape,
  show-type routing). Same as above — captcha pipeline, not WG.
- **WARP egress** (`WARP_INTERFACE` env var on `captcha-service`).
  Server-side only on the **captcha-service**, not the WG server.
- **Bounded packet pipe / readBufPool / minimal TURN goroutine zoo
  reduction**. Client-side memory optimisations; the server sees the
  same wire bytes as before.
