package sessionproto

import (
	"testing"

	"google.golang.org/protobuf/proto"
)

// TestDescriptorInitAndRoundtrip forces package init() (which parses the
// embedded FileDescriptor rawDesc) and a marshal roundtrip. A corrupt
// rawDesc — e.g. a blind module-path sed that desyncs a length prefix —
// panics here at init, which on iOS aborts the whole network extension
// at load. This guards that regression.
func TestDescriptorInitAndRoundtrip(t *testing.T) {
	ch := &ClientHello{
		Version:              1,
		Type:                 ClientHelloType_CLIENT_HELLO_TYPE_SESSION,
		SessionId:            make([]byte, SessionIDLen),
		StreamId:             3,
		SupportedWrapCiphers: []WrapCipher{WrapCipher_WRAP_CIPHER_SRTP_CHACHA20_POLY1305},
	}
	b, err := proto.Marshal(ch)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out ClientHello
	if err := proto.Unmarshal(b, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out.GetStreamId() != 3 || out.GetType() != ClientHelloType_CLIENT_HELLO_TYPE_SESSION {
		t.Fatalf("roundtrip mismatch: %+v", &out)
	}
}
