// SPDX-License-Identifier: MIT
//
// Force the in-tunnel TURN/DTLS cycle to tear down and reconnect without
// having to stop and re-start the whole proxy from Swift. This is what
// PacketTunnelProvider hooks into for wake/sleep/network-change events:
// rather than waiting for the next WG packet to discover that the DTLS
// channel is dead, we cancel the currently active oneDtlsConnection
// goroutines and let the existing retry loop spin up fresh ones with
// the pool-cached TURN credentials (no captcha re-prompt).

package main

import "C"
import "log"

//export RestartProxy
func RestartProxy() {
    n := cancelAllActiveDtls()
    if n == 0 {
        log.Printf("RestartProxy: nothing to restart")
        return
    }
    log.Printf("RestartProxy: cancelled %d in-flight DTLS connection(s)", n)
}
