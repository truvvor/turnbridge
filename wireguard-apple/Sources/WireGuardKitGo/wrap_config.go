// wrap_config.go — Swift→Go bridge for the wrap-key configuration.
//
// Swift sets the wrap key (64 hex chars = 32 bytes) before calling
// StartProxy. Empty key disables wrap entirely; oneTurnConnection
// then takes the legacy code path. Non-empty key must decode
// successfully or StartProxy logs and aborts before spawning sessions
// — there's no point opening 60 TURN allocations that VK will then
// drop on the wire-format mismatch.

package main

/*
#include <stdlib.h>
*/
import "C"

import (
	"log"
	"sync/atomic"
)

// wrapKeyBytes holds the decoded 32-byte key. nil = wrap disabled.
// Updated atomically by TurnBridgeSetWrapKey before StartProxy reads
// it; oneTurnConnection re-reads on every session start so the value
// in effect always matches what Swift last published.
var wrapKeyBytes atomic.Pointer[[]byte]

//export TurnBridgeSetWrapKey
func TurnBridgeSetWrapKey(cKey *C.char) {
	if cKey == nil {
		wrapKeyBytes.Store(nil)
		log.Printf("wrap: disabled (nil key)")
		return
	}
	raw := C.GoString(cKey)
	if raw == "" {
		wrapKeyBytes.Store(nil)
		log.Printf("wrap: disabled (empty key)")
		return
	}
	key, err := decodeWrapKey(true, raw)
	if err != nil {
		// Don't half-enable: leave the previous value intact so a
		// bad input doesn't suddenly turn a working session off.
		log.Printf("wrap: TurnBridgeSetWrapKey rejected: %v", err)
		return
	}
	wrapKeyBytes.Store(&key)
	log.Printf("wrap: enabled (key set, %d bytes)", len(key))
}

// currentWrapKey returns the active wrap key or nil if disabled.
// Each oneTurnConnection calls this once on session start so a key
// change mid-flight takes effect on the next reconnect, not on
// already-live sessions (changing it mid-stream would just AEAD-fail
// every subsequent packet on the existing allocation).
func currentWrapKey() []byte {
	p := wrapKeyBytes.Load()
	if p == nil {
		return nil
	}
	return *p
}

//export TurnBridgeGenerateWrapKey
func TurnBridgeGenerateWrapKey() *C.char {
	// Convenience for the iOS Settings UI: generates a fresh 32-byte
	// random key and returns it as 64 hex chars. Swift takes the
	// returned string, displays it for the user to copy to the
	// server config, and persists it locally. Caller MUST free the
	// returned string via free() — see SwiftBridge.swift.
	hex, err := genWrapKeyHex()
	if err != nil {
		log.Printf("wrap: genWrapKeyHex failed: %v", err)
		return nil
	}
	return C.CString(hex)
}
