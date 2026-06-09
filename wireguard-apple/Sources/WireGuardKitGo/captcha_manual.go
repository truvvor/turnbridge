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
	"sync"
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

// Captcha solve mode. 0 = off (auto only, on auto-fail the caller
// recycles a previously-acquired identity). 1 = forced (every captcha
// is handed to the UI immediately, auto solver is never tried). 2 =
// fallback (auto solver runs first; if it fails AND the remote /cred
// cluster has nothing for us either, the UI gets the prompt as a
// last resort before we degrade to identity recycling). Values
// preserved across the old 0/1 bool API: 1 still means "forced".
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
// Returns false if mode is off, fallback, or no UI callback is
// installed (without a callback there's no way to display the prompt).
func manualCaptchaForcedMode() bool {
	manualCaptchaMu.RLock()
	defer manualCaptchaMu.RUnlock()
	return manualCaptchaMode == manualCaptchaModeForced && manualCaptchaCB != nil
}

// manualCaptchaFallbackAvailable reports whether the UI prompt can
// be used as a last-resort fallback when both the auto solver and
// the remote /cred path have given up on this captcha. Different
// from forced mode: only consulted by solveVkCaptcha at the end of
// the auto chain, not at the start.
func manualCaptchaFallbackAvailable() bool {
	manualCaptchaMu.RLock()
	defer manualCaptchaMu.RUnlock()
	return manualCaptchaMode == manualCaptchaModeFallback && manualCaptchaCB != nil
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
