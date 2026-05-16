// memstats.go — periodic Go heap stats while StartProxy is running.
//
// Companion to the Swift-side memory logger in PacketTunnelProvider:
// Swift logs the OS-level numbers (resident set size + iOS's view of
// remaining memory budget for the extension), Go logs what its own
// runtime is holding so we can attribute spikes to captcha pipeline /
// DTLS state / channel buffers / etc.
//
// Lifetime is tied to the proxy context — stops the moment
// StartProxy's ctx fires Done, so Disconnect doesn't leave a stray
// goroutine logging into nothing.

package main

import (
	"context"
	"log"
	"runtime"
	"runtime/debug"
	"time"
)

const memstatsInterval = 5 * time.Second

// goSoftMemoryLimit caps Go's heap at ~75 MB. iOS extensions get
// ~100 MB total; the rest is C heap (cgo allocations from pion-dtls
// crypto, the WG core, the kernel-side socket buffers we tuned to
// 4 MB each). When Go's heap approaches this cap, the runtime fires
// GC much more aggressively — the cost is CPU time spent collecting
// but the alternative is iOS SIGKILL on the whole extension, which
// is strictly worse. See Go runtime/debug.SetMemoryLimit.
const goSoftMemoryLimit = 75 * 1024 * 1024

// goGCPercent halves the default 100 → the heap doubles between GC
// cycles by default; we cut it to 50 (triples between cycles is the
// default math at 100, so 50 means the heap grows only 1.5x before
// the next GC). Pairs with the memory-limit: under steady-state load
// SetMemoryLimit handles the cap, but during transient spikes
// (captcha solve storm, DTLS handshake burst) GCPercent is what
// keeps the steady-state from drifting upward over minutes.
const goGCPercent = 50

// freeOSMemoryInterval is how often we force returning idle pages
// to the OS. Go normally hands memory back to the OS lazily (it
// keeps reclaimed heap mapped to amortise re-allocation). On iOS
// what matters is RSS, not Go's view — releasing eagerly makes the
// OS see lower RSS, which keeps us further from the SIGKILL line.
const freeOSMemoryInterval = 15 * time.Second

// tuneGoRuntime applies the static-config tunings once at proxy
// startup. SetMemoryLimit and SetGCPercent are global — calling them
// repeatedly is fine but redundant, so we gate behind a runtime.Once
// equivalent by just calling from StartProxy.
func tuneGoRuntime() {
	debug.SetMemoryLimit(goSoftMemoryLimit)
	debug.SetGCPercent(goGCPercent)
	log.Printf("memstats: tuned runtime soft_limit=%s gc_percent=%d",
		humanBytes(goSoftMemoryLimit), goGCPercent)
}

func startMemstatsLogger(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(memstatsInterval)
		defer ticker.Stop()
		freeTicker := time.NewTicker(freeOSMemoryInterval)
		defer freeTicker.Stop()
		logMemstats("startup")
		for {
			select {
			case <-ctx.Done():
				logMemstats("shutdown")
				return
			case <-ticker.C:
				logMemstats("tick")
			case <-freeTicker.C:
				// FreeOSMemory does a STW GC and returns idle pages
				// to the OS. The STW pause is short (~ms at this
				// heap size) and only fires every 15s — well below
				// the threshold where it would be visible as a
				// data-plane stall, but enough to keep RSS from
				// ratcheting up between captcha storms.
				debug.FreeOSMemory()
			}
		}
	}()
}

func logMemstats(label string) {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	log.Printf("memstats(%s): heap_alloc=%s heap_sys=%s sys=%s goroutines=%d gc=%d",
		label,
		humanBytes(m.HeapAlloc),
		humanBytes(m.HeapSys),
		humanBytes(m.Sys),
		runtime.NumGoroutine(),
		m.NumGC,
	)
}

func humanBytes(b uint64) string {
	const (
		KB = 1024
		MB = 1024 * KB
	)
	switch {
	case b >= MB:
		return fmtDecimal(b, MB) + "MB"
	case b >= KB:
		return fmtDecimal(b, KB) + "KB"
	default:
		return fmtDecimal(b, 1) + "B"
	}
}

func fmtDecimal(value, unit uint64) string {
	if unit == 1 {
		return formatUint(value)
	}
	whole := value / unit
	frac := (value * 10 / unit) % 10
	if frac == 0 {
		return formatUint(whole)
	}
	return formatUint(whole) + "." + formatUint(frac)
}

func formatUint(v uint64) string {
	if v == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	return string(buf[i:])
}
