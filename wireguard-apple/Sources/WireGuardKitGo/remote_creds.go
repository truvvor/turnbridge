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
// service. The first few sessions bootstrap the WG tunnel using
// the mobile IP's fresh per-IP captcha budget; once WG is up we
// hand off to the server cluster so the phone IP doesn't burn its
// remaining ERROR_LIMIT budget on sessions 6+. 3 is lower than the
// original 5 because the gap between "first session ready" and the
// counter actually hitting the threshold is filled by other
// in-flight getCreds calls that have already committed to local —
// dropping the threshold by 2 buys ~4 more remote-routed solves at
// no extra latency cost.
const remoteHandoverThreshold = 3

type remoteCaptchaConfig struct {
	url    atomic.Value // string
	apiKey atomic.Value // string
}

var remoteCaptcha remoteCaptchaConfig

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
var remoteCredsClient = &http.Client{
	Timeout: 90 * time.Second, // server-side solve can take up to 80 s; add slack.
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

	body, _ := json.Marshal(map[string]string{"link": link})
	req, err := http.NewRequestWithContext(ctx, "POST", strings.TrimRight(url, "/")+"/cred", bytes.NewReader(body))
	if err != nil {
		return "", "", "", fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+apiKey)

	httpResp, err := remoteCredsClient.Do(req)
	if err != nil {
		return "", "", "", fmt.Errorf("call server: %w", err)
	}
	defer httpResp.Body.Close()

	rawBody, _ := io.ReadAll(httpResp.Body)
	var resp remoteCredResponse
	if jsonErr := json.Unmarshal(rawBody, &resp); jsonErr != nil {
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
		return "", "", "", fmt.Errorf("server: %s", msg)
	}
	if httpResp.StatusCode != http.StatusOK {
		msg := resp.Error
		if msg == "" {
			msg = fmt.Sprintf("HTTP %d", httpResp.StatusCode)
		}
		return "", "", "", fmt.Errorf("server: %s", msg)
	}
	if resp.User == "" || resp.Pass == "" || resp.Addr == "" {
		return "", "", "", fmt.Errorf("server returned incomplete creds")
	}
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
	return getCreds(ctx, link)
}

// Compile-time sanity: keep "unsafe" import referenced if cgo tooling
// ever decides it's "unused".
var _ unsafe.Pointer
