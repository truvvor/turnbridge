// SPDX-License-Identifier: MIT
//
// Stream-Aggregation handshake compatible with the kiper292/vk-turn-proxy
// server fork. When enabled, every DTLS session this client establishes
// writes a 17-byte preamble immediately after the DTLS handshake
// completes:
//
//   bytes 0..15:  Session ID (UUID v4 binary, shared across all N streams)
//   byte  16:     Stream ID (0..N-1)
//
// The receiver-side aggregator reads this preamble, groups every stream
// that carries the same Session ID under one logical session, and
// presents them to the upstream WireGuard server as a SINGLE endpoint.
// That stops the WG server from endpoint-thrashing when N parallel TURN
// allocations deliver packets from N distinct VK relay ports.
//
// Without a compatible server-side aggregator the preamble would be
// fed directly into WireGuard as the first bytes of "WG data", garbling
// the very first handshake. The flag therefore defaults to off and is
// only toggled on by Swift at StartProxy time when the active profile
// has streamAggregation=true.

package main

/*
#include <stdlib.h>
*/
import "C"

import (
	"crypto/rand"
	"sync"
	"sync/atomic"
)

var (
	streamAggEnabled atomic.Bool // true ⇔ write the 17-byte preamble on each session

	streamAggSessionMu sync.Mutex
	streamAggSessionID [16]byte // re-rolled once per StartProxy when the flag is on
	streamAggHasID     bool
)

//export TurnBridgeSetStreamAggregation
func TurnBridgeSetStreamAggregation(enabled C.int) {
	streamAggEnabled.Store(enabled != 0)
	if enabled == 0 {
		// Clear the cached session ID so the next "on" re-rolls a fresh one.
		streamAggSessionMu.Lock()
		streamAggHasID = false
		streamAggSessionMu.Unlock()
	}
}

func streamAggIsEnabled() bool {
	return streamAggEnabled.Load()
}

// freshStreamAggSession re-rolls the shared Session ID. Called from
// StartProxy at the moment all N sessions are about to be spawned, so
// every set of TURN allocations from a single connect attempt shares
// one ID and the server-side aggregator can fuse them.
func freshStreamAggSession() [16]byte {
	streamAggSessionMu.Lock()
	defer streamAggSessionMu.Unlock()
	if _, err := rand.Read(streamAggSessionID[:]); err != nil {
		// crypto/rand failing on iOS is practically impossible, but if it
		// does we'd rather have a fixed-zero ID than crash StartProxy;
		// the aggregator will at least bucket all streams together.
		for i := range streamAggSessionID {
			streamAggSessionID[i] = 0
		}
	}
	// Set the UUID v4 marker bits (RFC 4122 §4.4) so the bytes look like
	// a valid v4 UUID on the wire — matches what the reference Go
	// implementation produces via uuid.New().MarshalBinary().
	streamAggSessionID[6] = (streamAggSessionID[6] & 0x0f) | 0x40
	streamAggSessionID[8] = (streamAggSessionID[8] & 0x3f) | 0x80
	streamAggHasID = true
	return streamAggSessionID
}

func currentStreamAggSession() ([16]byte, bool) {
	streamAggSessionMu.Lock()
	defer streamAggSessionMu.Unlock()
	if !streamAggHasID {
		return [16]byte{}, false
	}
	return streamAggSessionID, true
}
