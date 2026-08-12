// wrap_handshake.go — WINGS-N in-band WRAP negotiation (client side).
//
// The server (truvvor/vk-turn-proxy, #46 "adopt WINGS-N transport
// wholesale") replaced the old static-wrap protocol with a negotiated
// one: the client sends a sessionproto SESSION ClientHello as the first
// DTLS application-data record; the server replies with a ServerHello
// selecting a WRAP cipher; only then does WRAP (SRTP-mimicry) turn on.
// A client that sends statically-wrapped bytes with no hello (what we
// did before) is treated as a legacy plaintext client and its wrapped
// bytes are garbage to the server — which is why the tunnel broke even
// though the -wrap-key was unchanged.
//
// This handshake rides INSIDE DTLS (dtlsConn.Write / .Read), so it is
// carried end-to-end to the server regardless of which TURN relay flow
// it traverses. Because our DTLS uses Connection IDs, the negotiated
// session survives TURN allocation rotation, so negotiation happens
// once per DTLS session.
//
// Wire framing (control envelope, sessionproto/control.go):
//   [ 57 56 4d 58 01 | kind | protobuf ]   kind: 0x05 req, 0x06 resp
// No length prefix — the DTLS record boundary delimits the message.

package main

import (
	"fmt"
	"log"
	"net"
	"time"

	"github.com/amnezia-vpn/amneziawg-apple/internal/wrap"
	"github.com/amnezia-vpn/amneziawg-apple/sessionproto"
)

const (
	// wrapProtocolVersion is the sessionproto version the server
	// validates against (mu/v1). ClientHello.version must equal it.
	wrapProtocolVersion = 1
	// wrapHelloWriteTimeout / wrapHelloReadTimeout bound the single
	// hello round-trip. The server waits ~750ms for the hello and
	// replies immediately; 3s read covers the DTLS + TURN + server RTT
	// with headroom. There is no app-layer retransmit — a miss fails
	// the stream and the reconnect loop starts fresh.
	wrapHelloWriteTimeout = 5 * time.Second
	wrapHelloReadTimeout  = 3 * time.Second
)

// negotiateWrap performs the in-band WRAP handshake over the DTLS
// plaintext conn and returns the Cipher to enable on the relay (nil if
// the server declined WRAP), plus the selected cipher enum so the
// caller can re-derive the cipher on relay reconnect.
//
// sessionID must be 16 bytes (mu session id; also groups streams for
// aggregation). streamID is this stream's index within the session.
// key is the 32-byte shared WRAP key, or nil when WRAP is disabled —
// in which case the hello offers no cipher and the server runs the
// session raw.
func negotiateWrap(dtlsConn net.Conn, sessionID []byte, streamID int, key []byte) (wrap.Cipher, sessionproto.WrapCipher, error) {
	var supported []sessionproto.WrapCipher
	if key != nil {
		// Offer ChaCha20 first (our historical cipher, fast on mobile
		// without AES-NI), AES-GCM as fallback. The server picks the
		// first of these that is in its allowlist.
		supported = []sessionproto.WrapCipher{
			sessionproto.WrapCipher_WRAP_CIPHER_SRTP_CHACHA20_POLY1305,
			sessionproto.WrapCipher_WRAP_CIPHER_SRTP_AES_256_GCM,
		}
	}

	hello := &sessionproto.ClientHello{
		Version:              wrapProtocolVersion,
		Type:                 sessionproto.ClientHelloType_CLIENT_HELLO_TYPE_SESSION,
		SessionId:            sessionID,
		StreamId:             uint32(streamID),
		RequestedTransport:   sessionproto.TransportMode_TRANSPORT_MODE_DATAGRAM,
		SupportedTransports:  []sessionproto.TransportMode{sessionproto.TransportMode_TRANSPORT_MODE_DATAGRAM},
		SupportedWrapCiphers: supported,
	}
	if key != nil {
		// Preset -wrap-key on the server always wins; this proposal is
		// only used if the server runs -wrap-accept-client-keys with no
		// preset. Harmless to send when both sides share the key.
		hello.WrapKeyProposal = key
	}

	helloBytes, err := sessionproto.MarshalClientHello(hello)
	if err != nil {
		return nil, sessionproto.WrapCipher_WRAP_CIPHER_UNSPECIFIED, fmt.Errorf("marshal client hello: %w", err)
	}
	packet := sessionproto.BuildControlSessionRequest(helloBytes)

	if err := dtlsConn.SetWriteDeadline(time.Now().Add(wrapHelloWriteTimeout)); err != nil {
		return nil, sessionproto.WrapCipher_WRAP_CIPHER_UNSPECIFIED, fmt.Errorf("set write deadline: %w", err)
	}
	if _, err := dtlsConn.Write(packet); err != nil {
		return nil, sessionproto.WrapCipher_WRAP_CIPHER_UNSPECIFIED, fmt.Errorf("write client hello: %w", err)
	}

	if err := dtlsConn.SetReadDeadline(time.Now().Add(wrapHelloReadTimeout)); err != nil {
		return nil, sessionproto.WrapCipher_WRAP_CIPHER_UNSPECIFIED, fmt.Errorf("set read deadline: %w", err)
	}
	buf := make([]byte, 2048)
	n, err := dtlsConn.Read(buf)
	// Clear deadlines regardless — the data pump must run without them.
	_ = dtlsConn.SetReadDeadline(time.Time{})
	_ = dtlsConn.SetWriteDeadline(time.Time{})
	if err != nil {
		return nil, sessionproto.WrapCipher_WRAP_CIPHER_UNSPECIFIED, fmt.Errorf("read server hello: %w", err)
	}

	inner, ok := sessionproto.ParseControlSessionResponse(buf[:n])
	if !ok {
		return nil, sessionproto.WrapCipher_WRAP_CIPHER_UNSPECIFIED,
			fmt.Errorf("server reply is not a control session response (prefix=%x)", buf[:min(n, 8)])
	}
	sh, err := sessionproto.ParseServerHelloMessage(inner)
	if err != nil {
		return nil, sessionproto.WrapCipher_WRAP_CIPHER_UNSPECIFIED, fmt.Errorf("parse server hello: %w", err)
	}
	if !sh.GetMuSupported() {
		return nil, sessionproto.WrapCipher_WRAP_CIPHER_UNSPECIFIED,
			fmt.Errorf("server rejected session: %q", sh.GetError())
	}

	selected := sh.GetSelectedWrapCipher()
	log.Printf("[STREAM %d] session negotiated: mu=%t wrap=%s", streamID, sh.GetMuSupported(), selected)

	if selected == sessionproto.WrapCipher_WRAP_CIPHER_UNSPECIFIED ||
		selected == sessionproto.WrapCipher_WRAP_CIPHER_NONE {
		// Server declined WRAP — run the session raw. Still a valid
		// (unobfuscated) tunnel; VK TURN may rate-limit it, but that is
		// the server's policy call, not a failure.
		return nil, selected, nil
	}
	if key == nil {
		return nil, selected, fmt.Errorf("server selected WRAP %s but no local key", selected)
	}

	cipher, err := wrap.New(selected, key, false /* isServer */)
	if err != nil {
		return nil, selected, fmt.Errorf("wrap cipher init (selected=%s): %w", selected, err)
	}
	return cipher, selected, nil
}
