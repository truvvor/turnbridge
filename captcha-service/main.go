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

	mux := http.NewServeMux()
	mux.HandleFunc("/cred", handleCred)
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
		WriteTimeout:      90 * time.Second,
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
// Blocks until one cred is solved (typically 2-10 s), or 80 s timeout.
// Concurrency is capped by solveSlot so a burst of N=20 from one
// client doesn't trip VK's rate-limit ahead of our own pacing.
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

	// Quick reject if we're cooling down from ERROR_LIMIT — sending
	// another solve attempt against a saturated IP just extends the
	// cooldown. The client should retry after the response says so.
	if directSaturated() {
		credsErrs.Add(1)
		w.Header().Set("Retry-After", "60")
		writeJSON(w, http.StatusTooManyRequests, errorResponse{"egress saturated, retry after cooldown"})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 80*time.Second)
	defer cancel()

	select {
	case solveSlot <- struct{}{}:
	case <-ctx.Done():
		credsErrs.Add(1)
		writeJSON(w, http.StatusServiceUnavailable, errorResponse{"solve queue full"})
		return
	}
	defer func() { <-solveSlot }()

	user, pass, addr, err := getCreds(ctx, req.Link)
	if err != nil {
		credsErrs.Add(1)
		writeJSON(w, http.StatusBadGateway, errorResponse{err.Error()})
		return
	}

	credsTotal.Add(1)
	writeJSON(w, http.StatusOK, credResponse{
		User:      user,
		Pass:      pass,
		Addr:      addr,
		ExpiresAt: time.Now().Add(45 * time.Second), // VK rotates ~50 s; 45 s is the safe usable window.
	})
}

// handleStats — GET /stats → snapshot of solve counters. No auth so
// monitoring can scrape it; only counters, no per-cred info.
func handleStats(w http.ResponseWriter, r *http.Request) {
	stats.mu.Lock()
	snap := struct {
		Attempts       int64 `json:"attempts"`
		Successes      int64 `json:"successes"`
		Saturated      int64 `json:"saturated"`
		InFlight       int64 `json:"in_flight"`
		CredsTotal     int64 `json:"creds_total"`
		CredsErrors    int64 `json:"creds_errors"`
		SaturatedNow   bool  `json:"saturated_now"`
		UptimeSeconds  int64 `json:"uptime_seconds"`
	}{
		Attempts:      stats.attempts,
		Successes:     stats.successes,
		Saturated:     stats.saturatedTotal,
		InFlight:      stats.inFlight,
		CredsTotal:    credsTotal.Load(),
		CredsErrors:   credsErrs.Load(),
		SaturatedNow:  directSaturated(),
		UptimeSeconds: int64(time.Since(startedAt).Seconds()),
	}
	stats.mu.Unlock()
	writeJSON(w, http.StatusOK, snap)
}

var startedAt = time.Now()

// Compile-time guard so go-mod-tidy doesn't drop the imports if some
// helpers are inadvertently dead-coded during refactors.
var _ = sync.Mutex{}
