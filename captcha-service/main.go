// captcha-service — server-side companion to the iOS TurnBridge
// extension. Hosts the VK captcha + identity-registration pipeline
// outside the 50-100 MB NetworkExtension sandbox. Clients POST a VK
// call link, the server returns ready-to-use TURN credentials the
// client then uses for its own Allocate.
//
// TURN allocations are bound by RFC 5766 to the 5-tuple that issued
// them, so the server CANNOT hand off a live allocation. What it
// hands off is the username/password/relay-address tuple returned
// from vchat.joinConversationByLink — those are HMAC-signed by VK's
// TURN secret and the client can use them from any source IP within
// the ~50 s rotation window.
//
// V2 adds peer-to-peer fan-out (see cluster.go): every binary can
// act as both master (for the client URL it's behind) and slave
// (for sibling masters). Configure with PEERS + SELF_URL env vars.

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type credResponse struct {
	User      string    `json:"user"`
	Pass      string    `json:"pass"`
	Addr      string    `json:"addr"`
	ExpiresAt time.Time `json:"expires_at"`
}

type errorResponse struct {
	Error string `json:"error"`
}

var (
	apiKey     string
	solveSlot  chan struct{}
	credsTotal atomic.Int64
	credsErrs  atomic.Int64
)

func main() {
	addr := os.Getenv("LISTEN_ADDR")
	if addr == "" {
		addr = ":8080"
	}
	apiKey = os.Getenv("API_KEY")
	if apiKey == "" {
		log.Fatal("API_KEY env var is required")
	}
	solveSlot = make(chan struct{}, maxConcurrentCaptchaSolves)
	initPeers()

	mux := http.NewServeMux()
	mux.HandleFunc("/cred", handleCred)
	mux.HandleFunc("/internal/cred", handleInternalCred)
	mux.HandleFunc("/stats", handleStats)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	srv := &http.Server{
		Addr:              addr,
		Handler:           withLogging(mux),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      120 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	log.Printf("captcha-service listening on %s (max concurrent solves=%d)", addr, maxConcurrentCaptchaSolves)
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("ListenAndServe: %v", err)
	}
}

func withLogging(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		h.ServeHTTP(w, r)
		log.Printf("%s %s %s in %v", r.Method, r.URL.Path, r.RemoteAddr, time.Since(start))
	})
}

func authorized(r *http.Request) bool {
	got := r.Header.Get("Authorization")
	return strings.HasPrefix(got, "Bearer ") && strings.TrimPrefix(got, "Bearer ") == apiKey
}

func writeJSON(w http.ResponseWriter, code int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// handleCred — POST /cred {"link":"..."} → {user,pass,addr,expires_at}.
// Public client-facing endpoint. Acts as MASTER: round-robins through
// the peer list (including self), forwards to /internal/cred when the
// chosen peer isn't self, falls through to the next peer on
// saturation or transient failure. Single-node mode (no PEERS env)
// reduces to "always solve locally", matching V1 behaviour.
func handleCred(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, errorResponse{"POST only"})
		return
	}
	if !authorized(r) {
		writeJSON(w, http.StatusUnauthorized, errorResponse{"invalid api key"})
		return
	}

	var req struct {
		Link string `json:"link"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{fmt.Sprintf("bad body: %v", err)})
		return
	}
	if req.Link == "" {
		writeJSON(w, http.StatusBadRequest, errorResponse{"link is required"})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 100*time.Second)
	defer cancel()

	tried := make([]bool, len(peers))
	var lastErr error

	for attempt := 0; attempt < len(peers); attempt++ {
		p := pickPeer(tried)
		if p == nil {
			break
		}

		var creds *credResponse
		var saturated bool
		var err error

		if p.Self {
			creds, saturated, err = solveLocally(ctx, req.Link)
		} else {
			creds, saturated, err = forwardToPeer(ctx, p, req.Link)
		}

		if saturated {
			p.markSaturated()
			log.Printf("cluster: peer %s marked saturated for %v", p.statusLabel(), captchaCooldown)
		}

		if err != nil {
			lastErr = err
			log.Printf("cluster: peer %s attempt failed: %v", p.statusLabel(), err)
			continue
		}

		credsTotal.Add(1)
		w.Header().Set("X-Captcha-Served-By", p.statusLabel())
		writeJSON(w, http.StatusOK, *creds)
		return
	}

	// Distinguish "all peers in cooldown" (return 429 with Retry-After)
	// from "we tried and they all errored on this request" (502).
	allSaturated := true
	for _, p := range peers {
		if p.isAvailable() {
			allSaturated = false
			break
		}
	}
	credsErrs.Add(1)
	if allSaturated {
		w.Header().Set("Retry-After", "60")
		writeJSON(w, http.StatusTooManyRequests, errorResponse{"all peers saturated, retry after cooldown"})
		return
	}
	msg := "all peers failed"
	if lastErr != nil {
		msg = lastErr.Error()
	}
	writeJSON(w, http.StatusBadGateway, errorResponse{msg})
}

// handleInternalCred — peer-only endpoint. Same auth gate as /cred,
// but solves locally and never forwards to other peers. This is what
// other masters call when round-robin lands on this binary; using a
// distinct path prevents accidental HTTP loops where a misconfigured
// PEERS list makes a peer forward to itself via /cred.
//
// Response always sets X-Captcha-Self-Saturated so the caller knows
// our current rate-limit state without making a separate /stats call.
func handleInternalCred(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, errorResponse{"POST only"})
		return
	}
	if !authorized(r) {
		writeJSON(w, http.StatusUnauthorized, errorResponse{"invalid api key"})
		return
	}

	var req struct {
		Link string `json:"link"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{fmt.Sprintf("bad body: %v", err)})
		return
	}
	if req.Link == "" {
		writeJSON(w, http.StatusBadRequest, errorResponse{"link is required"})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 80*time.Second)
	defer cancel()

	creds, saturated, err := solveLocally(ctx, req.Link)

	if saturated {
		w.Header().Set("X-Captcha-Self-Saturated", "1")
	}

	if err != nil {
		credsErrs.Add(1)
		if saturated {
			w.Header().Set("Retry-After", "60")
			writeJSON(w, http.StatusTooManyRequests, errorResponse{err.Error()})
			return
		}
		writeJSON(w, http.StatusBadGateway, errorResponse{err.Error()})
		return
	}

	credsTotal.Add(1)
	writeJSON(w, http.StatusOK, *creds)
}

// solveLocally runs one full VK captcha+identity-registration cycle
// using THIS instance's egress. Used both by /internal/cred (peer-
// to-peer leaf) and /cred when round-robin picks self. Returns
// saturated=true when the solve hit ERROR_LIMIT so the master can
// take this peer out of rotation for captchaCooldown.
func solveLocally(ctx context.Context, link string) (*credResponse, bool, error) {
	if directSaturated() {
		return nil, true, fmt.Errorf("egress saturated, retry after cooldown")
	}

	select {
	case solveSlot <- struct{}{}:
	case <-ctx.Done():
		return nil, false, fmt.Errorf("solve queue full or context cancelled")
	}
	defer func() { <-solveSlot }()

	user, pass, addr, err := getCreds(ctx, link)
	if err != nil {
		// directSaturated() flips during the captcha pipeline when
		// VK returns ERROR_LIMIT — re-check after so the caller can
		// mark this peer for cooldown even on the request that
		// tripped the limit.
		return nil, directSaturated(), err
	}

	return &credResponse{
		User:      user,
		Pass:      pass,
		Addr:      addr,
		ExpiresAt: time.Now().Add(45 * time.Second), // VK rotates ~50 s; 45 s is the safe usable window.
	}, directSaturated(), nil
}

// handleStats — GET /stats → snapshot of solve counters and cluster
// peer state. No auth so monitoring can scrape it; only counters,
// no per-cred info.
func handleStats(w http.ResponseWriter, r *http.Request) {
	type peerStat struct {
		URL                string `json:"url"`
		Self               bool   `json:"self"`
		Available          bool   `json:"available"`
		SaturatedRemaining int64  `json:"saturated_remaining_seconds"`
	}
	peerStats := make([]peerStat, 0, len(peers))
	now := time.Now()
	for _, p := range peers {
		p.mu.Lock()
		remaining := int64(0)
		if p.saturatedUntil.After(now) {
			remaining = int64(p.saturatedUntil.Sub(now).Seconds())
		}
		peerStats = append(peerStats, peerStat{
			URL:                p.statusLabel(),
			Self:               p.Self,
			Available:          p.saturatedUntil.Before(now),
			SaturatedRemaining: remaining,
		})
		p.mu.Unlock()
	}

	stats.mu.Lock()
	snap := struct {
		Attempts      int64      `json:"attempts"`
		Successes     int64      `json:"successes"`
		Saturated     int64      `json:"saturated"`
		InFlight      int64      `json:"in_flight"`
		CredsTotal    int64      `json:"creds_total"`
		CredsErrors   int64      `json:"creds_errors"`
		SaturatedNow  bool       `json:"saturated_now"`
		UptimeSeconds int64      `json:"uptime_seconds"`
		Peers         []peerStat `json:"peers"`
	}{
		Attempts:      stats.attempts,
		Successes:     stats.successes,
		Saturated:     stats.saturatedTotal,
		InFlight:      stats.inFlight,
		CredsTotal:    credsTotal.Load(),
		CredsErrors:   credsErrs.Load(),
		SaturatedNow:  directSaturated(),
		UptimeSeconds: int64(time.Since(startedAt).Seconds()),
		Peers:         peerStats,
	}
	stats.mu.Unlock()
	writeJSON(w, http.StatusOK, snap)
}

var startedAt = time.Now()

// Compile-time guard so go-mod-tidy doesn't drop the imports if some
// helpers are inadvertently dead-coded during refactors.
var _ = sync.Mutex{}
