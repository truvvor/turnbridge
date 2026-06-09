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
	"fmt"
	"sync"
	"time"
	"unsafe"
)

type manualCaptchaSlot struct {
	tokenCh chan string
	errCh   chan error
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

// requestManualCaptcha asks the registered handler (the iOS app, via the
// extension) to solve the captcha at redirectURI and return the
// success_token VK assigned. Blocks the caller until Swift responds or
// timeout elapses.
func requestManualCaptcha(redirectURI string, timeout time.Duration) (string, error) {
	manualCaptchaMu.RLock()
	cb := manualCaptchaCB
	manualCaptchaMu.RUnlock()
	if cb == nil {
		return "", fmt.Errorf("manual captcha handler not registered")
	}
	if redirectURI == "" {
		return "", fmt.Errorf("manual captcha redirect_uri is empty")
	}

	reqID := randomHex(8)
	slot := &manualCaptchaSlot{
		tokenCh: make(chan string, 1),
		errCh:   make(chan error, 1),
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
	case token := <-slot.tokenCh:
		if token == "" {
			return "", fmt.Errorf("manual captcha returned empty token")
		}
		return token, nil
	case err := <-slot.errCh:
		return "", err
	case <-time.After(timeout):
		return "", fmt.Errorf("manual captcha timeout after %s", timeout)
	}
}
