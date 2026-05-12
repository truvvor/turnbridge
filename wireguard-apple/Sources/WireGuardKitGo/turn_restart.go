// SPDX-License-Identifier: MIT
//
// `RestartProxy` keeps existing iOS callers (PacketTunnelProvider's
// debounced wake/path-change path) wired up after the in-tunnel session
// registry was renamed. It delegates to ProxyForceReconnect, which owns
// the per-session cancel map. The log line is preserved verbatim so the
// extension's TransportHealthMonitor pattern-match still flips the
// "transport unhealthy" flag in App Group UserDefaults.

package main

import "C"
import "log"

//export RestartProxy
func RestartProxy() {
    sessionMu.Lock()
    n := len(sessionCancels)
    sessionMu.Unlock()
    if n == 0 {
        log.Printf("RestartProxy: nothing to restart")
        return
    }
    ProxyForceReconnect()
    log.Printf("RestartProxy: cancelled %d in-flight DTLS connection(s)", n)
}
