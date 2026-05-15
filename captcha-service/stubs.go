// stubs.go — server-side replacements for iOS-specific globals that
// vk_captcha.go and captcha_slider.go reach for. The server has a
// single egress IP (no tunnel/direct split), no manual-captcha UI,
// and writes debug artefacts to a directory rather than handing them
// to a Swift bridge.

package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
)

// maxConcurrentCaptchaSolves caps in-flight captcha solves per server.
// VK rate-limits captchaNotRobot per source IP; 5 is the same value
// the iOS client uses and is well below the actual ERROR_LIMIT
// trigger on a fresh per-IP budget.
const maxConcurrentCaptchaSolves = 5

// captchaTunnelEgress — always false on server. The server has one
// physical egress; the "tunnel egress" notion only matters on the
// iOS client where post-WG-handshake traffic leaves through utun.
var captchaTunnelEgress atomic.Bool

// saturation: a single per-egress flag. Tripped when a captcha solve
// hits ERROR_LIMIT; auto-clears after captchaCooldown.
const captchaCooldown = 60 * time.Second

var (
	saturatedAt atomic.Int64 // unix nano of last ERROR_LIMIT
)

func directSaturated() bool {
	at := saturatedAt.Load()
	if at == 0 {
		return false
	}
	return time.Since(time.Unix(0, at)) < captchaCooldown
}

func tunnelSaturated() bool { return false }

// cellularDial — on iOS this pins to a physical interface; on server
// there's no utun to escape from, so just delegate to customDial.
var cellularDial = customDial

// manual-captcha UI — server never runs in manual mode.
func manualCaptchaForcedMode() bool { return false }

func requestManualCaptcha(redirectURI string, timeout time.Duration) (string, error) {
	return "", fmt.Errorf("manual captcha not supported on server")
}

// markCaptcha* — stats hooks. The iOS bridge ships these to Swift for
// the live counter UI; on server we keep an in-memory tally for the
// /stats endpoint and trip saturation on ERROR_LIMIT.
type captchaStats struct {
	mu                    sync.Mutex
	attempts, successes   int64
	saturatedTotal        int64
	inFlight              int64
}

var stats captchaStats

func markCaptchaAttemptStart(forceDirect bool) bool {
	stats.mu.Lock()
	stats.attempts++
	stats.inFlight++
	stats.mu.Unlock()
	return false // returned bool = isTunnel; always false on server
}

func markCaptchaAttemptDone(isTunnel bool) {
	stats.mu.Lock()
	stats.inFlight--
	stats.mu.Unlock()
}

func markCaptchaSuccess(isTunnel bool) {
	stats.mu.Lock()
	stats.successes++
	stats.mu.Unlock()
}

func markCaptchaSaturated(isTunnel bool) {
	stats.mu.Lock()
	stats.saturatedTotal++
	stats.mu.Unlock()
	saturatedAt.Store(time.Now().UnixNano())
}

// captchaTrap — debug artefact collector. On iOS this writes into an
// AppGroup directory the user can browse from the app; on server it
// writes into $CAPTCHA_TRAP_DIR (default ./trap), or stays in memory
// if the dir isn't writable. Commit() materialises everything Note'd
// and Save'd since New; Discard() throws it all away.
type captchaTrap struct {
	mu       sync.Mutex
	prefix   string
	created  time.Time
	notes    []string
	saves    map[string][]byte
	finished bool
}

var trapBaseDir = func() string {
	if d := os.Getenv("CAPTCHA_TRAP_DIR"); d != "" {
		return d
	}
	return "./trap"
}()

func newCaptchaTrap(prefix string) *captchaTrap {
	return &captchaTrap{
		prefix:  prefix,
		created: time.Now(),
		saves:   make(map[string][]byte),
	}
}

func (t *captchaTrap) Note(format string, args ...interface{}) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.notes = append(t.notes, fmt.Sprintf("[%s] ", time.Now().UTC().Format(time.RFC3339Nano))+fmt.Sprintf(format, args...))
}

func (t *captchaTrap) Save(name string, data []byte) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	// Copy so the caller can reuse the buffer.
	buf := make([]byte, len(data))
	copy(buf, data)
	t.saves[name] = buf
}

func (t *captchaTrap) Commit(reason string) {
	if t == nil {
		return
	}
	t.mu.Lock()
	if t.finished {
		t.mu.Unlock()
		return
	}
	t.finished = true
	prefix := t.prefix
	notes := t.notes
	saves := t.saves
	t.mu.Unlock()

	if trapBaseDir == "" || prefix == "" {
		return
	}
	stamp := t.created.UTC().Format("20060102_150405")
	dir := filepath.Join(trapBaseDir, fmt.Sprintf("%s_%s_%s", stamp, prefix, reason))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return
	}
	if len(notes) > 0 {
		var b []byte
		for _, n := range notes {
			b = append(b, n...)
			b = append(b, '\n')
		}
		_ = os.WriteFile(filepath.Join(dir, "notes.log"), b, 0o644)
	}
	for name, data := range saves {
		_ = os.WriteFile(filepath.Join(dir, name), data, 0o644)
	}
}

func (t *captchaTrap) Discard() {
	if t == nil {
		return
	}
	t.mu.Lock()
	t.finished = true
	t.notes = nil
	t.saves = nil
	t.mu.Unlock()
}

// Compile-time assertion: cellularDial has the same signature as
// customDial. Catches anyone changing the dialer shape.
var _ func(context.Context, string, string) (net.Conn, error) = cellularDial
