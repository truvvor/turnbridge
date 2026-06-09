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
	"time"
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
	captchaDirectSatAt      atomic.Int64 // unix-nano timestamp of last ERROR_LIMIT on direct
	captchaTunnelSatAt      atomic.Int64 // unix-nano timestamp of last ERROR_LIMIT on tunnel
	captchaTunnelEgress     atomic.Bool  // true once we believe HTTP from this extension routes through utun
	captchaSessionsReady    atomic.Int64 // DTLS sessions that have reached sessionOk
	captchaSessionsTarget   atomic.Int64 // requested N

	// Remote-server captcha pool stats. Server-cluster solves are
	// completely opaque to the markCaptcha{Attempt,Success,Saturated}
	// helpers above because the captcha never touches this phone's
	// HTTP stack — getCredsRemote just receives a finished cred. The
	// counters below are bumped exclusively from remote_creds.go on
	// every /cred call so the UI can surface the cluster's
	// contribution alongside Direct/Tunnel.
	captchaRemoteOK       atomic.Int64
	captchaRemoteAttempts atomic.Int64
	captchaRemoteInFlight atomic.Int64
)

// satThreshold is the number of consecutive ERROR_LIMITs that count as
// "egress saturated, stop spawning more sessions there". One failure is
// noise; three in a row is a genuine rate-limit pattern.
const satThreshold = 3

// captchaCooldown is how long the saturated flag stays sticky after the
// last ERROR_LIMIT. VK's per-IP captcha rate-limit windows are short
// (~60 s in practice), so once a minute has elapsed without a fresh
// failure we let the spawn paths try again. Without this the system
// gives up forever after one rate-limit burst, even if the network
// would have recovered.
const captchaCooldown = 60 * time.Second

func resetCaptchaStats() {
	captchaDirectOK.Store(0)
	captchaTunnelOK.Store(0)
	captchaDirectAttempts.Store(0)
	captchaTunnelAttempts.Store(0)
	captchaDirectInFlight.Store(0)
	captchaTunnelInFlight.Store(0)
	captchaDirectFailStreak.Store(0)
	captchaTunnelFailStreak.Store(0)
	captchaDirectSatAt.Store(0)
	captchaTunnelSatAt.Store(0)
	captchaTunnelEgress.Store(false)
	captchaSessionsReady.Store(0)
	captchaSessionsTarget.Store(0)
	captchaRemoteOK.Store(0)
	captchaRemoteAttempts.Store(0)
	captchaRemoteInFlight.Store(0)
}

//export TurnBridgeGetCaptchaRemoteCount
func TurnBridgeGetCaptchaRemoteCount() C.int {
	return C.int(captchaRemoteOK.Load())
}

//export TurnBridgeGetCaptchaRemoteAttempts
func TurnBridgeGetCaptchaRemoteAttempts() C.int {
	return C.int(captchaRemoteAttempts.Load())
}

//export TurnBridgeGetCaptchaRemoteInFlight
func TurnBridgeGetCaptchaRemoteInFlight() C.int {
	return C.int(captchaRemoteInFlight.Load())
}

// markCaptchaAttemptStart bumps the in-flight gauge for the egress
// this attempt will use. forceDirect=true means the caller is pinning
// a physical interface to bypass utun (see cellularDial), so the
// attempt should be counted against the direct bucket even though
// captchaTunnelEgress is true.
func markCaptchaAttemptStart(forceDirect bool) (isTunnel bool) {
	isTunnel = captchaTunnelEgress.Load() && !forceDirect
	if isTunnel {
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

// markCaptchaSuccess clears the streak for the egress that just got a
// success_token. The isTunnel flag is the one returned from
// markCaptchaAttemptStart so a force-direct retry credits the right
// pool even when captchaTunnelEgress is globally true.
func markCaptchaSuccess(isTunnel bool) {
	if isTunnel {
		captchaTunnelOK.Add(1)
		captchaTunnelFailStreak.Store(0)
		captchaTunnelSatAt.Store(0)
	} else {
		captchaDirectOK.Add(1)
		captchaDirectFailStreak.Store(0)
		captchaDirectSatAt.Store(0)
	}
}

// markCaptchaSaturated records an ERROR_LIMIT against the egress this
// attempt actually used. Stamps the timestamp so the cooldown in
// directSaturated/tunnelSaturated can auto-clear after captchaCooldown.
func markCaptchaSaturated(isTunnel bool) {
	now := time.Now().UnixNano()
	if isTunnel {
		captchaTunnelFailStreak.Add(1)
		captchaTunnelSatAt.Store(now)
	} else {
		captchaDirectFailStreak.Add(1)
		captchaDirectSatAt.Store(now)
	}
}

// saturatedWithCooldown is the shared check + auto-decay for both
// egresses. If the streak is at threshold but captchaCooldown has
// elapsed since the last ERROR_LIMIT, clear the streak and report
// not-saturated so the spawn paths can probe again.
func saturatedWithCooldown(streak *atomic.Int64, satAt *atomic.Int64) bool {
	if streak.Load() < satThreshold {
		return false
	}
	last := satAt.Load()
	if last == 0 {
		return true
	}
	if time.Now().UnixNano()-last > captchaCooldown.Nanoseconds() {
		streak.Store(0)
		satAt.Store(0)
		return false
	}
	return true
}

func directSaturated() bool {
	return saturatedWithCooldown(&captchaDirectFailStreak, &captchaDirectSatAt)
}
func tunnelSaturated() bool {
	return saturatedWithCooldown(&captchaTunnelFailStreak, &captchaTunnelSatAt)
}

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
