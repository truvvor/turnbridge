package wrap

import (
	"bytes"
	"testing"

	"github.com/amnezia-vpn/amneziawg-apple/sessionproto"
)

// TestSRTPChaChaRoundtrip validates that a client-sealed datagram opens
// on a server cipher under the same key (the exact client↔server path),
// for the SRTP-ChaCha20 suite the handshake negotiates.
func TestSRTPChaChaRoundtrip(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	cli, err := New(sessionproto.WrapCipher_WRAP_CIPHER_SRTP_CHACHA20_POLY1305, key, false)
	if err != nil {
		t.Fatalf("client cipher: %v", err)
	}
	srv, err := New(sessionproto.WrapCipher_WRAP_CIPHER_SRTP_CHACHA20_POLY1305, key, true)
	if err != nil {
		t.Fatalf("server cipher: %v", err)
	}
	plain := []byte("wireguard-inside-dtls-inside-srtp")
	wire, err := cli.Seal(plain)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if wire[0] != 0x80 {
		t.Fatalf("sealed packet not SRTP-shaped: first byte %#x", wire[0])
	}
	got, err := srv.Open(wire)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("roundtrip mismatch: %q != %q", got, plain)
	}
}
