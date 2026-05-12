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

var (
	manualCaptchaMu      sync.RWMutex
	manualCaptchaCB      C.manual_captcha_cb
	manualCaptchaEnabled bool
	manualCaptchaSlotsMu sync.Mutex
	manualCaptchaSlots   = make(map[string]*manualCaptchaSlot)
)

//export TurnBridgeSetManualCaptchaMode
func TurnBridgeSetManualCaptchaMode(enabled C.int) {
	manualCaptchaMu.Lock()
	defer manualCaptchaMu.Unlock()
	manualCaptchaEnabled = enabled != 0
}

func manualCaptchaForcedMode() bool {
	manualCaptchaMu.RLock()
	defer manualCaptchaMu.RUnlock()
	return manualCaptchaEnabled && manualCaptchaCB != nil
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
