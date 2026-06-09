// wrap.go — SRTP/Opus mimicry layer between our DTLS-encrypted WG
// payload and the TURN ChannelData frame on the wire.
//
// What VK's DPI sees on real call traffic between two clients via TURN:
//   - DTLS handshake records (type 0x16) at the start
//   - then SRTP frames carrying Opus voice — RTP header version=2,
//     payload type 111 (Opus), monotonic seq+timestamp+SSRC, followed
//     by an AEAD ciphertext.
//
// What VK sees on OUR traffic without wrap:
//   - DTLS handshake records (fine)
//   - then DTLS application-data records (type 0x17) forever
//
// The two diverge sharply after the handshake completes. VK appears to
// run a fast-path classifier on TURN ChannelData payloads: SRTP-shaped
// gets forwarded freely, anything else (incl. plain DTLS application-
// data) gets the rate-limit treatment we've been observing. wrap.go
// re-frames our DTLS records so the wire bytes match the shape of a
// real Opus voice stream — VK can't DPI past the AEAD ciphertext so
// they can't tell our "Opus" is actually WireGuard inside DTLS.
//
// Wire format (per packet):
//
//   [12B RTP header | 12B explicit nonce | AEAD ciphertext | 16B tag]
//
// RTP header (RFC 3550):
//   byte 0:    0x80         V=2, P=0, X=0, CC=0
//   byte 1:    0x6F         M=0, PT=111 (Opus)
//   byte 2-3:  seq16 BE     monotonic, init random
//   byte 4-7:  ts32 BE      monotonic, init random, +960 per packet
//                           (20ms at 48kHz, the standard Opus framing)
//   byte 8-11: SSRC         random per conn, MSB encodes direction
//
// 12B explicit nonce = 4B sessionID || 8B counter (BE). sessionID MSB
// matches SSRC MSB (direction bit so client and server pick disjoint
// nonce subspaces despite sharing the same key). counter starts at a
// random uint64.
//
// AAD = first 24 bytes (RTP header || nonce). Authenticating these
// means the seq/timestamp/SSRC are spoof-proof — VK can't reorder
// or replay one packet's bytes into another's slot without AEAD
// failure.
//
// AEAD is ChaCha20-Poly1305 (RFC 7539). The shared 32-byte key is
// configured out of band; both ends must have the same key. Real SRTP
// uses AES-GCM (RFC 7714); we use ChaCha20-Poly1305 because the wire
// ciphertext/tag length is the same and ChaCha20 is faster on mobile
// CPUs without AES-NI. VK's DPI can't distinguish — it's looking at
// the RTP framing, not the cipher choice.
//
// Verbatim port from Moroka8/vk-turn-proxy/pkg/clientcore/wrap.go.
// Server-side counterpart lives in that same project and must be
// configured with the matching key.

package main

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"sync/atomic"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	wrapKeyLen     = 32
	wrapRTPHdrLen  = 12
	wrapNonceLen   = 12
	wrapTagLen     = 16
	wrapHeaderLen  = wrapRTPHdrLen + wrapNonceLen
	wrapOverhead   = wrapHeaderLen + wrapTagLen
	wrapRTPVersion = 0x80
	wrapRTPPT      = 0x6F
	wrapTSStep     = 960
)

type wrapConn struct {
	aead      cipher.AEAD
	sessionID [4]byte
	ssrc      [4]byte
	counter   atomic.Uint64
	seq       atomic.Uint32
	timestamp atomic.Uint32
}

func newWrapConn(key []byte, isServer bool) (*wrapConn, error) {
	if len(key) != wrapKeyLen {
		return nil, fmt.Errorf("wrap: key must be %d bytes (got %d)", wrapKeyLen, len(key))
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, fmt.Errorf("wrap: aead init: %w", err)
	}
	w := &wrapConn{aead: aead}

	var rnd [16]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return nil, fmt.Errorf("wrap: rand init: %w", err)
	}
	copy(w.sessionID[:], rnd[0:4])
	copy(w.ssrc[:], rnd[4:8])
	if isServer {
		w.sessionID[0] |= 0x80
		w.ssrc[0] |= 0x80
	} else {
		w.sessionID[0] &^= 0x80
		w.ssrc[0] &^= 0x80
	}
	w.seq.Store(uint32(binary.BigEndian.Uint16(rnd[8:10])))
	w.timestamp.Store(binary.BigEndian.Uint32(rnd[10:14]))

	var cb [8]byte
	if _, err := rand.Read(cb[:]); err != nil {
		return nil, fmt.Errorf("wrap: counter rand: %w", err)
	}
	w.counter.Store(binary.BigEndian.Uint64(cb[:]))
	return w, nil
}

func wrapMaxWire(payloadLen int) int {
	return wrapOverhead + payloadLen
}

func (w *wrapConn) wrapInto(dst, payload []byte) (int, error) {
	wireLen := wrapOverhead + len(payload)
	if len(dst) < wireLen {
		return 0, errors.New("wrap: dst buffer too small")
	}

	dst[0] = wrapRTPVersion
	dst[1] = wrapRTPPT
	seq := uint16(w.seq.Add(1) - 1)
	binary.BigEndian.PutUint16(dst[2:4], seq)
	ts := w.timestamp.Add(wrapTSStep) - wrapTSStep
	binary.BigEndian.PutUint32(dst[4:8], ts)
	copy(dst[8:12], w.ssrc[:])

	noncePos := wrapRTPHdrLen
	copy(dst[noncePos:noncePos+4], w.sessionID[:])
	ctr := w.counter.Add(1) - 1
	binary.BigEndian.PutUint64(dst[noncePos+4:noncePos+wrapNonceLen], ctr)

	nonce := dst[noncePos : noncePos+wrapNonceLen]
	aad := dst[:wrapHeaderLen]
	ctPos := wrapHeaderLen
	copy(dst[ctPos:], payload)
	w.aead.Seal(dst[ctPos:ctPos], nonce, dst[ctPos:ctPos+len(payload)], aad)

	return wireLen, nil
}

func (w *wrapConn) unwrapPacket(wire, dst []byte) (int, error) {
	if len(wire) < wrapOverhead {
		return 0, errors.New("wrap: packet too short")
	}
	nonce := wire[wrapRTPHdrLen : wrapRTPHdrLen+wrapNonceLen]
	aad := wire[:wrapHeaderLen]
	ct := wire[wrapHeaderLen:]

	plain, err := w.aead.Open(ct[:0], nonce, ct, aad)
	if err != nil {
		return 0, fmt.Errorf("wrap: AEAD open: %w", err)
	}
	if len(plain) > len(dst) {
		return 0, errors.New("wrap: dst buffer too small")
	}
	copy(dst[:len(plain)], plain)
	return len(plain), nil
}

func genWrapKeyHex() (string, error) {
	key := make([]byte, wrapKeyLen)
	if _, err := rand.Read(key); err != nil {
		return "", fmt.Errorf("wrap: key gen: %w", err)
	}
	return hex.EncodeToString(key), nil
}

func decodeWrapKey(enabled bool, raw string) ([]byte, error) {
	if !enabled {
		return nil, nil
	}
	if raw == "" {
		return nil, errors.New("wrap enabled but key is empty")
	}
	key, err := hex.DecodeString(raw)
	if err != nil {
		return nil, fmt.Errorf("wrap-key invalid hex: %w", err)
	}
	if len(key) != wrapKeyLen {
		return nil, fmt.Errorf("wrap-key must decode to %d bytes (got %d)", wrapKeyLen, len(key))
	}
	return key, nil
}
