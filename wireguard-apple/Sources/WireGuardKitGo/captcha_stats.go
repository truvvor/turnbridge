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
	captchaDirectOK     atomic.Int64
	captchaTunnelOK     atomic.Int64
	captchaDirectSat    atomic.Bool // ERROR_LIMIT seen on direct egress
	captchaTunnelSat    atomic.Bool // ERROR_LIMIT seen on tunnel egress
	captchaTunnelEgress atomic.Bool // true once we believe HTTP from this extension routes through utun
)

func resetCaptchaStats() {
	captchaDirectOK.Store(0)
	captchaTunnelOK.Store(0)
	captchaDirectSat.Store(false)
	captchaTunnelSat.Store(false)
	captchaTunnelEgress.Store(false)
}

func markCaptchaSuccess() {
	if captchaTunnelEgress.Load() {
		captchaTunnelOK.Add(1)
	} else {
		captchaDirectOK.Add(1)
	}
}

func markCaptchaSaturated() {
	if captchaTunnelEgress.Load() {
		captchaTunnelSat.Store(true)
	} else {
		captchaDirectSat.Store(true)
	}
}

//export TurnBridgeGetCaptchaDirectCount
func TurnBridgeGetCaptchaDirectCount() C.int {
	return C.int(captchaDirectOK.Load())
}

//export TurnBridgeGetCaptchaTunnelCount
func TurnBridgeGetCaptchaTunnelCount() C.int {
	return C.int(captchaTunnelOK.Load())
}

//export TurnBridgeIsCaptchaDirectSaturated
func TurnBridgeIsCaptchaDirectSaturated() C.int {
	if captchaDirectSat.Load() {
		return 1
	}
	return 0
}

//export TurnBridgeIsCaptchaTunnelSaturated
func TurnBridgeIsCaptchaTunnelSaturated() C.int {
	if captchaTunnelSat.Load() {
		return 1
	}
	return 0
}
