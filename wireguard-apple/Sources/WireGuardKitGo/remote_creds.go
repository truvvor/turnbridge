// remote_creds.go — optional offload of getCreds to an external
// captcha-service. Configured at runtime by Swift via
// ProxySetRemoteCaptchaService. When configured AND the local
// captcha pipeline has already produced `remoteHandoverThreshold`
// unique TURN identities (i.e. WG is comfortably up and we just
// need more sessions for stream-aggregation throughput), subsequent
// getCreds calls route to the server instead of consuming the local
// per-IP rate-limit budget.
//
// The server (see captcha-service/) does the captcha solving from
// ITS own IP — that's the whole point: it doesn't share VK's
// per-IP ERROR_LIMIT bucket with the user's mobile IP, and the
// 70 MB slider rendering happens on a real machine with proper
// memory.

package main

/*
#include <stdlib.h>
*/
import "C"

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
	"unsafe"
)

// remoteHandoverThreshold — number of LOCAL successful captcha
// solves before subsequent solves are offloaded to the remote
// service. ONE is the minimum: as soon as the user has paid for
// the bootstrap captcha and the WG tunnel has actual data flowing,
// every subsequent getCreds call routes to the server cluster.
// The user's explicit ask (1.3.29): never see more than 3 captcha
// sheets per StartProxy. The combination of threshold=1 here +
// manualCaptchaQuotaPerSession=3 in captcha_manual.go gives us
// that bound even in the worst case where the remote /cred path
// is briefly degraded — local fallback can still produce up to
// 3 prompts before the quota kicks in.
const remoteHandoverThreshold = 1

type remoteCaptchaConfig struct {
	url    atomic.Value // string
	apiKey atomic.Value // string
}

var remoteCaptcha remoteCaptchaConfig

// errDeferToRemote is returned from the local captcha path
// (requestManualCaptcha specifically) when, by the time the goroutine
// is about to actually inconvenience the user with a sheet, the
// remote captcha-service is preferred (≥1 session ready, no
// cooldown). The call bubbles back up to getCredsRouted which then
// re-routes to the server cluster. The user only sees the sheet for
// the captchas that genuinely have to happen on the device.
var errDeferToRemote = errors.New("defer to remote captcha service")

// shouldDeferToRemoteNow reports whether the remote captcha-service
// is configured, has at least one local solve under its belt (so the
// remote path's auth isn't going to fight ERROR_LIMIT alongside the
// mobile IP for the bootstrap window), and isn't currently in a
// 429-cooldown. Goroutines queued behind the serialise lock check
// this AFTER they acquire the lock — see captcha_manual.go.
func shouldDeferToRemoteNow() bool {
	if !remoteCaptchaEnabled() {
		return false
	}
	if captchaSessionsReady.Load() < int64(remoteHandoverThreshold) {
		return false
	}
	return !remoteInCooldown()
}

func remoteCaptchaURL() string {
	v, _ := remoteCaptcha.url.Load().(string)
	return v
}

func remoteCaptchaAPIKey() string {
	v, _ := remoteCaptcha.apiKey.Load().(string)
	return v
}

func remoteCaptchaEnabled() bool {
	return remoteCaptchaURL() != "" && remoteCaptchaAPIKey() != ""
}

//export ProxySetRemoteCaptchaService
func ProxySetRemoteCaptchaService(cURL *C.char, cAPIKey *C.char) {
	url := strings.TrimSpace(C.GoString(cURL))
	apiKey := strings.TrimSpace(C.GoString(cAPIKey))
	remoteCaptcha.url.Store(url)
	remoteCaptcha.apiKey.Store(apiKey)
	if url == "" || apiKey == "" {
		log.Printf("remote-captcha: disabled")
		return
	}
	log.Printf("remote-captcha: configured (url=%s, handover-after=%d local solves)", url, remoteHandoverThreshold)
}

// remoteCooldownDefault — how long the client treats the remote
// service as unavailable when the master returns 429 without a
// usable Retry-After header. Matches the server's own ERROR_LIMIT
// cooldown so the two ends recover in lockstep.
const remoteCooldownDefault = 60 * time.Second

// remoteCooldownUntilNano is a UnixNano timestamp; calls to
// getCredsRemote skip the round trip entirely while now() < this
// value. Lets `getCredsRouted` fall through to local immediately
// during a saturation window instead of paying 90 s of HTTP timeout
// per session waiting for the server to refuse again.
var remoteCooldownUntilNano atomic.Int64

func remoteInCooldown() bool {
	until := remoteCooldownUntilNano.Load()
	if until == 0 {
		return false
	}
	return time.Now().UnixNano() < until
}

func setRemoteCooldown(d time.Duration) {
	if d <= 0 {
		return
	}
	until := time.Now().Add(d).UnixNano()
	for {
		cur := remoteCooldownUntilNano.Load()
		// Only extend; never shorten. Two concurrent 429s with
		// different Retry-After values shouldn't clobber the
		// longer one.
		if until <= cur {
			return
		}
		if remoteCooldownUntilNano.CompareAndSwap(cur, until) {
			return
		}
	}
}

// remoteCredsClient is dedicated to /cred calls. Its DialContext is
// customDial so it benefits from DoH + fallback IPs when api.vk.com
// is censored, but the actual target host is the user's own server.
//
// Timeout was 90 s originally ("server-side solve can take up to
// 80 s"). Field log 1.3.36 (quota=1, N=10) showed the cost of being
// patient when the server isn't actually replying: three concurrent
// /cred calls held poolCreds's solveSlot semaphore (3 slots) for the
// full 90 s, sessions 4…N starved on solveSlot acquire,
// poolCreds's recycle-fallback never fired, and the user disconnected
// after 84 s with 1/10 sessions up. 15 s is enough headroom for a
// healthy server (typical p95 ~5 s) and short enough that a degraded
// server surfaces in time for poolCreds to recycle the bootstrap
// identity onto the remaining sessions.
var remoteCredsClient = &http.Client{
	Timeout: 15 * time.Second,
	Transport: &http.Transport{
		DialContext:         customDial,
		MaxIdleConns:        20,
		MaxIdleConnsPerHost: 20,
		IdleConnTimeout:     120 * time.Second,
	},
}

type remoteCredResponse struct {
	User      string    `json:"user"`
	Pass      string    `json:"pass"`
	Addr      string    `json:"addr"`
	ExpiresAt time.Time `json:"expires_at"`
	Error     string    `json:"error,omitempty"`
}

func getCredsRemote(ctx context.Context, link string) (string, string, string, error) {
	url := remoteCaptchaURL()
	apiKey := remoteCaptchaAPIKey()
	if url == "" || apiKey == "" {
		return "", "", "", errors.New("remote captcha not configured")
	}

	attemptID := captchaRemoteAttempts.Add(1)
	inFlight := captchaRemoteInFlight.Add(1)
	defer captchaRemoteInFlight.Add(-1)
	started := time.Now()
	// Field log 1.3.34 showed 3 defer-to-remote calls firing in the
	// same second after the user's manual solve, then 50+ s of
	// silence — no TURN allocate, no DTLS, no "deferred retry failed"
	// log. The calls were stuck inside remoteCredsClient.Do (90 s
	// HTTP timeout) without any indication to the operator. Log
	// every remote call's start and end with duration + outcome so
	// the next field log shows exactly whether the server is slow,
	// erroring, or simply not reached. The shorter "deferred retry
	// failed" line still fires from getCredsRouted on error; this is
	// the per-call ground truth.
	log.Printf("remote-captcha: call #%d START (in_flight=%d, url=%s)", attemptID, inFlight, url)
	defer func() {
		// elapsed captured at defer-time; success/error is inferred
		// from the named return values, but we don't have access to
		// those from a plain defer — instead the END log lives at
		// each return path below, and this just covers the panic
		// case (which shouldn't happen but is cheap insurance).
		_ = started
	}()

	body, _ := json.Marshal(map[string]string{"link": link})
	req, err := http.NewRequestWithContext(ctx, "POST", strings.TrimRight(url, "/")+"/cred", bytes.NewReader(body))
	if err != nil {
		log.Printf("remote-captcha: call #%d END error build_request elapsed=%s err=%v", attemptID, time.Since(started).Round(time.Millisecond), err)
		return "", "", "", fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+apiKey)

	httpResp, err := remoteCredsClient.Do(req)
	if err != nil {
		log.Printf("remote-captcha: call #%d END error transport elapsed=%s err=%v", attemptID, time.Since(started).Round(time.Millisecond), err)
		return "", "", "", fmt.Errorf("call server: %w", err)
	}
	defer httpResp.Body.Close()

	rawBody, _ := io.ReadAll(httpResp.Body)
	var resp remoteCredResponse
	if jsonErr := json.Unmarshal(rawBody, &resp); jsonErr != nil {
		log.Printf("remote-captcha: call #%d END error decode elapsed=%s status=%d body_len=%d err=%v",
			attemptID, time.Since(started).Round(time.Millisecond), httpResp.StatusCode, len(rawBody), jsonErr)
		return "", "", "", fmt.Errorf("decode server response (status=%d): %w", httpResp.StatusCode, jsonErr)
	}
	if httpResp.StatusCode == http.StatusTooManyRequests {
		// Master is reporting that every peer it knows about is
		// saturated. Trip our local cooldown so we don't pile on
		// during the recovery window — the next ~60 s of getCreds
		// calls will skip the HTTP round trip and go straight to
		// the local solver (which on a single-IP deployment is
		// often also saturated, but at least skipping spares us
		// the 90 s remote timeout per session).
		cooldown := remoteCooldownDefault
		if ra := httpResp.Header.Get("Retry-After"); ra != "" {
			if secs, err := strconv.Atoi(strings.TrimSpace(ra)); err == nil && secs > 0 {
				cooldown = time.Duration(secs) * time.Second
			}
		}
		setRemoteCooldown(cooldown)
		log.Printf("remote-captcha: master saturated, cooling down for %v", cooldown)
		msg := resp.Error
		if msg == "" {
			msg = "all peers saturated"
		}
		log.Printf("remote-captcha: call #%d END saturated elapsed=%s status=429 cooldown=%v msg=%q",
			attemptID, time.Since(started).Round(time.Millisecond), cooldown, msg)
		return "", "", "", fmt.Errorf("server: %s", msg)
	}
	if httpResp.StatusCode != http.StatusOK {
		msg := resp.Error
		if msg == "" {
			msg = fmt.Sprintf("HTTP %d", httpResp.StatusCode)
		}
		log.Printf("remote-captcha: call #%d END http_error elapsed=%s status=%d msg=%q",
			attemptID, time.Since(started).Round(time.Millisecond), httpResp.StatusCode, msg)
		return "", "", "", fmt.Errorf("server: %s", msg)
	}
	if resp.User == "" || resp.Pass == "" || resp.Addr == "" {
		log.Printf("remote-captcha: call #%d END incomplete elapsed=%s user=%q pass=%q addr=%q",
			attemptID, time.Since(started).Round(time.Millisecond), resp.User, resp.Pass, resp.Addr)
		return "", "", "", fmt.Errorf("server returned incomplete creds")
	}
	captchaRemoteOK.Add(1)
	log.Printf("remote-captcha: call #%d END ok elapsed=%s addr=%s",
		attemptID, time.Since(started).Round(time.Millisecond), resp.Addr)
	return resp.User, resp.Pass, resp.Addr, nil
}

// getCredsRouted picks local vs remote at call time. The first
// `remoteHandoverThreshold` cred acquisitions stay local (regardless
// of how many recycle-fallbacks happen) so the WG tunnel can come up
// on the user's own mobile IP; after that, calls prefer the remote
// service. Remote failures cleanly fall through to local — same
// recycle-pool behaviour as before, no client-side regression.
//
// When the master is in 429-cooldown (see setRemoteCooldown), skip
// the HTTP attempt entirely. The cooldown is established by a real
// 429 response; once the window passes the next call will try remote
// again. This keeps the recovery-window log clean and stops us from
// burning 90 s timeouts on each session-spawn while the cluster
// recovers.
func getCredsRouted(ctx context.Context, link string) (string, string, string, error) {
	useRemote := remoteCaptchaEnabled() && captchaSessionsReady.Load() >= int64(remoteHandoverThreshold)
	if useRemote && !remoteInCooldown() {
		u, p, a, err := getCredsRemote(ctx, link)
		if err == nil {
			log.Printf("remote-captcha: cred from server (sessions_ready=%d)", captchaSessionsReady.Load())
			return u, p, a, nil
		}
		log.Printf("remote-captcha: server call failed (%v) — falling back to local", err)
	}
	u, p, a, err := getCreds(ctx, link)
	// Local path can defer to remote when the goroutine was queued
	// behind manualCaptchaSerialise long enough for the first session
	// to come up. Honour the deferral and try the server cluster.
	if errors.Is(err, errDeferToRemote) && remoteCaptchaEnabled() && !remoteInCooldown() {
		log.Printf("remote-captcha: local deferred to remote, retrying via server")
		ru, rp, ra, rerr := getCredsRemote(ctx, link)
		if rerr == nil {
			return ru, rp, ra, nil
		}
		log.Printf("remote-captcha: deferred retry failed (%v) — returning original local error", rerr)
	}
	return u, p, a, err
}

// Compile-time sanity: keep "unsafe" import referenced if cgo tooling
// ever decides it's "unused".
var _ unsafe.Pointer
