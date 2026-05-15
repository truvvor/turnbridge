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
	"time"
)

const memstatsInterval = 5 * time.Second

func startMemstatsLogger(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(memstatsInterval)
		defer ticker.Stop()
		logMemstats("startup")
		for {
			select {
			case <-ctx.Done():
				logMemstats("shutdown")
				return
			case <-ticker.C:
				logMemstats("tick")
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
