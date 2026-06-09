// SPDX-License-Identifier: MIT
//
// Manual captcha bridge. Lets the Swift app/extension show a real browser
// (WKWebView) for the VK NotRobot captcha when the auto solver can't beat
// it. Swift registers a single C callback via TurnBridgeSetManualCaptchaCallback;
// when the auto-solver bails, Go invokes that callback with a redirect_uri
// and blocks until Swift answers via TurnBridgeSubmitManualCaptchaToken or
// TurnBridgeCancelManualCaptcha.

package main

/*
#include <stdint.h>
#include <stdlib.h>

typedef void (*manual_captcha_cb)(const char* request_id, const char* redirect_uri);

static inline void invoke_manual_captcha_cb(manual_captcha_cb cb,
                                            const char* request_id,
                                            const char* redirect_uri) {
    cb(request_id, redirect_uri);
}
*/
import "C"

import (
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"
)

type manualCaptchaSlot struct {
	tokenCh    chan string
	// responseCh carries the full JSON response when the WebView did
	// the follow-up VK API call itself instead of just extracting the
	// success_token. The follow-up runs inside the same browser
	// session that solved the captcha — same cookies, same TLS, same
	// IP — so VK sees a single coherent actor instead of "token minted
	// here, redeemed over there". Empty retryURL = WebView falls back
	// to the legacy tokenCh path.
	responseCh chan string
	errCh      chan error
	// retryURL + retryBody are the request the WebView should make
	// after extracting success_token. retryBody contains the literal
	// string "__TOKEN__" which the WebView's injected JS replaces
	// with the actual token before sending.
	retryURL  string
	retryBody string
}

// manualCaptchaQuotaPerSession bounds how many times the iOS UI may
// be prompted within a single StartProxy session. Without this cap a
// forced-mode user at N=60 would face up to 60 sequential captcha
// sheets — past the first ~5 the perceived "stuck sheet" reports
// flood in even though the pipeline is working as designed.
//
// Once the quota is exhausted, manualCaptchaForcedMode /
// manualCaptchaFallbackAvailable return false for the remainder of
// the session and the caller degrades gracefully (auto-only with
// recycle on failure). Quota resets on the next StartProxy via the
// counter being reset there.
const manualCaptchaQuotaPerSession = 5

var manualCaptchaInvocations atomic.Int64

// resetManualCaptchaQuota is called from StartProxy at the top so
// each fresh session starts the user out at full quota again.
func resetManualCaptchaQuota() {
	manualCaptchaInvocations.Store(0)
}

func manualCaptchaQuotaRemaining() int64 {
	used := manualCaptchaInvocations.Load()
	rem := int64(manualCaptchaQuotaPerSession) - used
	if rem < 0 {
		return 0
	}
	return rem
}

// manualCaptchaSerialise enforces that only one captcha sheet is
// shown to the user at a time. Without it — see the 1.3.27 field
// log — the first wave of N=60 session goroutines all called
// requestManualCaptcha within the same millisecond. Each one
// publishRequest'd its own PendingRequest into the App Group
// UserDefaults under the SAME KEY; only the last write survived.
// The Swift Manager only ever saw the LATEST request, the sheet
// kept swapping URLs under the user's fingers, and the visible
// "stuck on green checkmark" was actually the page from one
// request being overwritten by the next request's URL while the
// JS helper from the first request was mid-flight.
//
// Serialising at the Go entry point means goroutines line up in
// arrival order. Each waits for the previous one to fully finish
// (solve, cancel, or timeout) before publishRequest fires the
// callback. The Swift side never sees overlapping requests.
//
// Quota and serialisation interact cleanly: the lock acquisition
// happens first, then quota is checked (and decrements on
// rejection). At most 5 ever hold the lock; the 6th — 60th wait
// in line until the 5th completes, then immediately fall through
// to the quota-exhausted branch.
// manualCaptchaSerialise is a binary semaphore implemented as a
// 1-buffered channel: send to claim, receive to release. Channel
// pick at send time is FIFO-ish under Go's runtime, which matches
// the "arrival order" intent better than sync.Mutex's unspecified
// wakeup order.
var manualCaptchaSerialise = make(chan struct{}, 1)

const (
	manualCaptchaModeOff      = 0
	manualCaptchaModeForced   = 1
	manualCaptchaModeFallback = 2
)

var (
	manualCaptchaMu      sync.RWMutex
	manualCaptchaCB      C.manual_captcha_cb
	manualCaptchaMode    int
	manualCaptchaSlotsMu sync.Mutex
	manualCaptchaSlots   = make(map[string]*manualCaptchaSlot)
)

//export TurnBridgeSetManualCaptchaMode
func TurnBridgeSetManualCaptchaMode(mode C.int) {
	manualCaptchaMu.Lock()
	defer manualCaptchaMu.Unlock()
	manualCaptchaMode = int(mode)
}

// manualCaptchaForcedMode reports whether every captcha challenge
// should bypass the auto solver and go straight to the UI prompt.
// Returns false if mode is off, fallback, no UI callback is
// installed (without a callback there's no way to display the
// prompt), OR the per-session quota has been exhausted (see
// manualCaptchaQuotaPerSession — without the cap a forced-mode user
// at N=60 would face 60 sequential sheets in a row).
func manualCaptchaForcedMode() bool {
	manualCaptchaMu.RLock()
	defer manualCaptchaMu.RUnlock()
	if manualCaptchaMode != manualCaptchaModeForced || manualCaptchaCB == nil {
		return false
	}
	return manualCaptchaQuotaRemaining() > 0
}

// manualCaptchaFallbackAvailable reports whether the UI prompt can
// be used as a last-resort fallback when both the auto solver and
// the remote /cred path have given up on this captcha. Different
// from forced mode: only consulted by solveVkCaptcha at the end of
// the auto chain, not at the start. Same per-session quota applies.
func manualCaptchaFallbackAvailable() bool {
	manualCaptchaMu.RLock()
	defer manualCaptchaMu.RUnlock()
	if manualCaptchaMode != manualCaptchaModeFallback || manualCaptchaCB == nil {
		return false
	}
	return manualCaptchaQuotaRemaining() > 0
}

//export TurnBridgeSetManualCaptchaCallback
func TurnBridgeSetManualCaptchaCallback(cb C.manual_captcha_cb) {
	manualCaptchaMu.Lock()
	defer manualCaptchaMu.Unlock()
	manualCaptchaCB = cb
}

//export TurnBridgeSubmitManualCaptchaToken
func TurnBridgeSubmitManualCaptchaToken(cReqID *C.char, cToken *C.char) {
	if cReqID == nil {
		return
	}
	reqID := C.GoString(cReqID)
	token := ""
	if cToken != nil {
		token = C.GoString(cToken)
	}

	manualCaptchaSlotsMu.Lock()
	slot, ok := manualCaptchaSlots[reqID]
	manualCaptchaSlotsMu.Unlock()
	if !ok {
		return
	}
	select {
	case slot.tokenCh <- token:
	default:
	}
}

//export TurnBridgeCancelManualCaptcha
func TurnBridgeCancelManualCaptcha(cReqID *C.char, cReason *C.char) {
	if cReqID == nil {
		return
	}
	reqID := C.GoString(cReqID)
	reason := "user cancelled"
	if cReason != nil {
		if s := C.GoString(cReason); s != "" {
			reason = s
		}
	}

	manualCaptchaSlotsMu.Lock()
	slot, ok := manualCaptchaSlots[reqID]
	manualCaptchaSlotsMu.Unlock()
	if !ok {
		return
	}
	select {
	case slot.errCh <- fmt.Errorf("%s", reason):
	default:
	}
}

// requestManualCaptcha asks the registered handler (the iOS app, via
// the extension) to solve the captcha at redirectURI. Blocks until
// the WebView responds.
//
// If retryURL is non-empty, the WebView will use the just-solved
// browser session to POST retryBody (with literal "__TOKEN__"
// replaced by the actual success_token) to retryURL, and return the
// resulting JSON response as `response`. The caller can use that
// response directly, skipping its own retry — VK never sees a
// session switch between captcha solve and API redemption.
//
// If retryURL is empty OR if the WebView's in-session retry fails
// (network error, fetch threw, response not extractable), it falls
// back to returning just the success_token via `token`. The caller
// then does the legacy retry from its own HTTP client.
//
// Exactly one of (token, response, err) is non-empty on return.
func requestManualCaptcha(redirectURI, retryURL, retryBody string, timeout time.Duration) (token, response string, err error) {
	manualCaptchaMu.RLock()
	cb := manualCaptchaCB
	manualCaptchaMu.RUnlock()
	if cb == nil {
		return "", "", fmt.Errorf("manual captcha handler not registered")
	}
	if redirectURI == "" {
		return "", "", fmt.Errorf("manual captcha redirect_uri is empty")
	}

	// Serialise: only one captcha sheet is shown at a time. See
	// manualCaptchaSerialise comment. Goroutines stack up here and
	// release the slot on return (success, cancel, or timeout).
	// CRITICAL: the slot is held across the entire user-facing
	// solve so PendingRequest in App Group UserDefaults isn't
	// overwritten by the next goroutine while the user is still
	// looking at the current sheet.
	manualCaptchaSerialise <- struct{}{}
	defer func() { <-manualCaptchaSerialise }()

	// Reserve a slot in the per-session quota AFTER acquiring the
	// serialise lock. Without that ordering, all 60 goroutines
	// could race past the quota gate at once (Add(1) returns a
	// monotonic counter but doesn't block), then only the first 5
	// to acquire the lock actually run. The remaining 55 would
	// have already burned a slot. With this ordering, only as
	// many slots are spent as sheets are actually shown.
	used := manualCaptchaInvocations.Add(1)
	if used > int64(manualCaptchaQuotaPerSession) {
		manualCaptchaInvocations.Add(-1)
		return "", "", fmt.Errorf("manual captcha quota exhausted (%d/%d)", used-1, manualCaptchaQuotaPerSession)
	}
	log.Printf("[Captcha] manual prompt %d/%d this session", used, manualCaptchaQuotaPerSession)

	reqID := randomHex(8)
	slot := &manualCaptchaSlot{
		tokenCh:    make(chan string, 1),
		responseCh: make(chan string, 1),
		errCh:      make(chan error, 1),
		retryURL:   retryURL,
		retryBody:  retryBody,
	}

	manualCaptchaSlotsMu.Lock()
	manualCaptchaSlots[reqID] = slot
	manualCaptchaSlotsMu.Unlock()
	defer func() {
		manualCaptchaSlotsMu.Lock()
		delete(manualCaptchaSlots, reqID)
		manualCaptchaSlotsMu.Unlock()
	}()

	cReqID := C.CString(reqID)
	cURI := C.CString(redirectURI)
	defer C.free(unsafe.Pointer(cReqID))
	defer C.free(unsafe.Pointer(cURI))

	C.invoke_manual_captcha_cb(cb, cReqID, cURI)

	select {
	case resp := <-slot.responseCh:
		if resp == "" {
			return "", "", fmt.Errorf("manual captcha returned empty response")
		}
		return "", resp, nil
	case t := <-slot.tokenCh:
		if t == "" {
			return "", "", fmt.Errorf("manual captcha returned empty token")
		}
		return t, "", nil
	case e := <-slot.errCh:
		return "", "", e
	case <-time.After(timeout):
		return "", "", fmt.Errorf("manual captcha timeout after %s", timeout)
	}
}

// TurnBridgeGetManualCaptchaRetryRequest lets Swift fetch the retry
// URL + body template for a given request ID right after the
// callback fires. Returns a JSON string {"url":..., "body":...} or
// empty string if no retry is configured for this slot. Caller must
// free() the returned pointer. We use this pull-from-Swift pattern
// rather than passing retry params as callback arguments to avoid
// breaking the existing C callback ABI.
//
//export TurnBridgeGetManualCaptchaRetryRequest
func TurnBridgeGetManualCaptchaRetryRequest(cReqID *C.char) *C.char {
	if cReqID == nil {
		return nil
	}
	reqID := C.GoString(cReqID)

	manualCaptchaSlotsMu.Lock()
	slot, ok := manualCaptchaSlots[reqID]
	manualCaptchaSlotsMu.Unlock()
	if !ok || slot.retryURL == "" {
		return nil
	}
	payload := struct {
		URL  string `json:"url"`
		Body string `json:"body"`
	}{URL: slot.retryURL, Body: slot.retryBody}
	b, err := json.Marshal(payload)
	if err != nil {
		return nil
	}
	return C.CString(string(b))
}

// TurnBridgeSubmitManualCaptchaResponse is the WebView's "I did the
// retry myself, here's the full JSON response" entry. Swift calls
// this instead of TurnBridgeSubmitManualCaptchaToken when the
// in-WebView fetch succeeded.
//
//export TurnBridgeSubmitManualCaptchaResponse
func TurnBridgeSubmitManualCaptchaResponse(cReqID *C.char, cResponseJSON *C.char) {
	if cReqID == nil {
		return
	}
	reqID := C.GoString(cReqID)
	resp := ""
	if cResponseJSON != nil {
		resp = C.GoString(cResponseJSON)
	}

	manualCaptchaSlotsMu.Lock()
	slot, ok := manualCaptchaSlots[reqID]
	manualCaptchaSlotsMu.Unlock()
	if !ok {
		return
	}
	select {
	case slot.responseCh <- resp:
	default:
	}
}
