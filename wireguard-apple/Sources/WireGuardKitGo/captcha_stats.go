// SPDX-License-Identifier: MIT
//
// Per-connect captcha solve counters and saturation flags.
//
// Two egress IPs feed our captcha solves once phased bring-up is on:
//
//   * "direct"  — the user's mobile IP, used by the bootstrap session
//                 before WG comes up.
//   * "tunnel"  — the WG server's egress IP, used by every session
//                 spawned AFTER WG handshake completes (the extension's
//                 own net/http auto-routes through utun under
//                 includeAllNetworks=true).
//
// VK enforces captcha.isNotRobot rate-limits per source IP, so the two
// pools have independent budgets. The UI surfaces both counts so the
// user can see how many sessions came up via each route. The two
// saturation flags (`direct` / `tunnel`) flip on the first
// ERROR_LIMIT seen in that mode and let StartProxy stop spawning new
// sessions once the tunneled egress is also exhausted.

package main

/*
#include <stdlib.h>
*/
import "C"

import (
	"sync/atomic"
)

var (
	captchaDirectOK         atomic.Int64
	captchaTunnelOK         atomic.Int64
	captchaDirectAttempts   atomic.Int64 // total captcha solve attempts started on direct egress
	captchaTunnelAttempts   atomic.Int64 // ditto for tunnel egress
	captchaDirectInFlight   atomic.Int64 // currently mid-solve on direct
	captchaTunnelInFlight   atomic.Int64 // ditto for tunnel
	captchaDirectFailStreak atomic.Int64 // consecutive ERROR_LIMITs on direct egress without a success
	captchaTunnelFailStreak atomic.Int64 // ditto for tunnel
	captchaTunnelEgress     atomic.Bool  // true once we believe HTTP from this extension routes through utun
	captchaSessionsReady    atomic.Int64 // DTLS sessions that have reached sessionOk
	captchaSessionsTarget   atomic.Int64 // requested N
)

// satThreshold is the number of consecutive ERROR_LIMITs that count as
// "egress saturated, stop spawning more sessions there". One failure is
// noise; three in a row is a genuine rate-limit pattern.
const satThreshold = 3

func resetCaptchaStats() {
	captchaDirectOK.Store(0)
	captchaTunnelOK.Store(0)
	captchaDirectAttempts.Store(0)
	captchaTunnelAttempts.Store(0)
	captchaDirectInFlight.Store(0)
	captchaTunnelInFlight.Store(0)
	captchaDirectFailStreak.Store(0)
	captchaTunnelFailStreak.Store(0)
	captchaTunnelEgress.Store(false)
	captchaSessionsReady.Store(0)
	captchaSessionsTarget.Store(0)
}

func markCaptchaAttemptStart() (isTunnel bool) {
	if captchaTunnelEgress.Load() {
		captchaTunnelAttempts.Add(1)
		captchaTunnelInFlight.Add(1)
		return true
	}
	captchaDirectAttempts.Add(1)
	captchaDirectInFlight.Add(1)
	return false
}

func markCaptchaAttemptDone(isTunnel bool) {
	if isTunnel {
		captchaTunnelInFlight.Add(-1)
	} else {
		captchaDirectInFlight.Add(-1)
	}
}

func markCaptchaSuccess() {
	if captchaTunnelEgress.Load() {
		captchaTunnelOK.Add(1)
		captchaTunnelFailStreak.Store(0)
	} else {
		captchaDirectOK.Add(1)
		captchaDirectFailStreak.Store(0)
	}
}

func markCaptchaSaturated() {
	if captchaTunnelEgress.Load() {
		captchaTunnelFailStreak.Add(1)
	} else {
		captchaDirectFailStreak.Add(1)
	}
}

func directSaturated() bool { return captchaDirectFailStreak.Load() >= satThreshold }
func tunnelSaturated() bool { return captchaTunnelFailStreak.Load() >= satThreshold }

//export TurnBridgeGetCaptchaDirectCount
func TurnBridgeGetCaptchaDirectCount() C.int {
	return C.int(captchaDirectOK.Load())
}

//export TurnBridgeGetCaptchaTunnelCount
func TurnBridgeGetCaptchaTunnelCount() C.int {
	return C.int(captchaTunnelOK.Load())
}

//export TurnBridgeGetCaptchaDirectAttempts
func TurnBridgeGetCaptchaDirectAttempts() C.int {
	return C.int(captchaDirectAttempts.Load())
}

//export TurnBridgeGetCaptchaTunnelAttempts
func TurnBridgeGetCaptchaTunnelAttempts() C.int {
	return C.int(captchaTunnelAttempts.Load())
}

//export TurnBridgeGetCaptchaDirectInFlight
func TurnBridgeGetCaptchaDirectInFlight() C.int {
	return C.int(captchaDirectInFlight.Load())
}

//export TurnBridgeGetCaptchaTunnelInFlight
func TurnBridgeGetCaptchaTunnelInFlight() C.int {
	return C.int(captchaTunnelInFlight.Load())
}

//export TurnBridgeIsCaptchaDirectSaturated
func TurnBridgeIsCaptchaDirectSaturated() C.int {
	if directSaturated() {
		return 1
	}
	return 0
}

//export TurnBridgeIsCaptchaTunnelSaturated
func TurnBridgeIsCaptchaTunnelSaturated() C.int {
	if tunnelSaturated() {
		return 1
	}
	return 0
}

//export TurnBridgeGetSessionsReady
func TurnBridgeGetSessionsReady() C.int {
	return C.int(captchaSessionsReady.Load())
}

//export TurnBridgeGetSessionsTarget
func TurnBridgeGetSessionsTarget() C.int {
	return C.int(captchaSessionsTarget.Load())
}
