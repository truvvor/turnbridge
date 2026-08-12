// captcha_client.go — HTTP client for the VK captcha solver that
// impersonates Safari iOS at the TLS + HTTP/2 layer.
//
// Why this exists: in mid-2026 VK upgraded its anti-bot to fingerprint
// every captcha request by JA3/JA4 (TLS ClientHello shape) and HTTP/2
// SETTINGS + header-order. Go's net/http has a distinctive ClientHello
// and writes HTTP/2 headers in a stable but non-Chrome/Safari order.
// VK's classifier now flags us as a non-browser and either traffic-
// shapes the IP or returns ERROR_LIMIT on captcha solve, even when
// our UA + cookies + behavioral signals are pristine.
//
// bogdanfinn/tls-client (built on utls) lets us send TLS handshakes
// with byte-identical ClientHello to a real Safari iOS 18, plus
// HTTP/2 SETTINGS frame and pseudo-header order. fhttp (a fork of
// net/http) preserves the original header order via the magic
// HeaderOrderKey, so the server sees the exact sequence Safari emits.
// Pure Go, no cgo, runs unchanged inside the iOS NetworkExtension.
//
// Limitation vs the old newCaptchaClient: tls-client's WithDialer
// takes a net.Dialer struct, not a DialContext function, so we can't
// plug our customDial / cellularDial / DoH fallback chain (see
// dns_resolver.go) directly. iOS system resolver handles the captcha
// hosts (api.vk.ru, id.vk.ru) just fine in practice; the DoH chain
// was a paranoia-fallback for Russian carriers that NXDOMAIN
// vk-family hosts, which the captcha-service field log hasn't shown
// in the wild. If that path becomes necessary, the path is
// pre-resolve-via-DoH + dial-by-IP + WithServerNameOverwrite.

package main

import (
	"context"

	fhttp "github.com/bogdanfinn/fhttp"
	"github.com/bogdanfinn/fhttp/cookiejar"
	tlsclient "github.com/bogdanfinn/tls-client"
	tlsprofiles "github.com/bogdanfinn/tls-client/profiles"
)

// COHERENT DESKTOP CHROME IDENTITY (1.3.41)
// -----------------------------------------
// Field diagnosis after VK started hard-flagging us as BOT on both
// auto and manual paths: the auto-solver was presenting a
// self-contradicting fingerprint — iPhone Safari UA + Safari_IOS_18_0
// TLS, but the `device` JSON in componentDone/check reported a
// 1920×1080 8-core DESKTOP with no touch and no motion sensors. VK's
// classifier reads "an iPhone that renders like a desktop" as an
// obvious script. A broken auto-solve from the user's mobile IP then
// poisons that IP's reputation, so the subsequent *legitimate* WebKit
// manual solve from the same IP also draws BOT.
//
// Moroka8/vk-turn-proxy (the reference the field asked us to absorb)
// solves this by being COHERENTLY desktop Chrome everywhere: Chrome
// UA + sec-ch-ua client hints + Chrome_146 TLS + desktop device JSON,
// all aligned. We adopt that identity for the auto-solver's HTTP
// layer. The manual WebView path is untouched — it's real mobile
// WebKit and coherent by construction.

// chromeCaptchaUA is the desktop Chrome 146 (Windows) User-Agent the
// auto-solver presents. MUST stay aligned with the sec-ch-ua trio
// below, the Chrome_146 TLS profile, and the desktop device JSON in
// vk_captcha.go — any divergence is a bot tell.
const (
	chromeCaptchaUA            = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36"
	chromeCaptchaSecChUa       = `"Chromium";v="146", "Not-A.Brand";v="24", "Google Chrome";v="146"`
	chromeCaptchaSecChUaMobile = "?0"
	chromeCaptchaSecChUaPlat   = `"Windows"`
)

// chromeHeaderOrder is the order Chrome 146 writes HTTP/2 request
// headers in. Order matters for VK's classifier even though HTTP/2 is
// semantically order-insensitive — Chrome and Safari diverge here and
// it's a cheap bot tell. Mirrors Moroka8's captchaV2HeaderOrder.
var chromeHeaderOrder = []string{
	"host",
	"content-length",
	"sec-ch-ua-platform",
	"accept-language",
	"sec-ch-ua",
	"content-type",
	"sec-ch-ua-mobile",
	"user-agent",
	"accept",
	"origin",
	"sec-fetch-site",
	"sec-fetch-mode",
	"sec-fetch-dest",
	"referer",
	"accept-encoding",
	"priority",
	"cookie",
}

// chromePHeaderOrder is the order Chrome writes HTTP/2 pseudo-headers.
var chromePHeaderOrder = []string{
	":method",
	":authority",
	":scheme",
	":path",
}

// newTLSCaptchaClient returns a tls-client HttpClient with Chrome 146
// fingerprint and a fresh cookie jar (each captcha solve gets its own
// jar — VK's classifier checks for prior session state and an empty
// jar simulates a clean browser launch).
//
// forceDirect was previously a hook to route HTTP through a non-utun
// interface when the tunnel egress hit a per-IP rate-limit. tls-
// client doesn't expose a DialContext slot the same way net/http
// does, so for now forceDirect is honored only as a documentation
// signal — the actual dial goes through whatever route iOS picks.
func newTLSCaptchaClient(forceDirect bool) (tlsclient.HttpClient, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}
	opts := []tlsclient.HttpClientOption{
		tlsclient.WithTimeoutSeconds(20),
		tlsclient.WithClientProfile(tlsprofiles.Chrome_146),
		tlsclient.WithCookieJar(jar),
		tlsclient.WithDisableHttp3(),
	}
	_ = forceDirect // see comment above
	return tlsclient.NewHttpClient(tlsclient.NewNoopLogger(), opts...)
}

// applyCaptchaBrowserHeaders sets the coherent desktop-Chrome identity
// headers (UA + sec-ch-ua client hints + Accept-Language) and stamps
// the fhttp HeaderOrderKey / PHeaderOrderKey so the RoundTripper
// writes headers in Chrome's order. Call after setting the
// request-specific headers (Accept, Sec-Fetch-*, Origin, Referer,
// Content-Type). Unlike the old Safari path we DO send sec-ch-ua —
// real Chrome always does, and omitting them from a Chrome UA is
// itself the tell.
func applyCaptchaBrowserHeaders(req *fhttp.Request) {
	req.Header.Set("User-Agent", chromeCaptchaUA)
	req.Header.Set("sec-ch-ua", chromeCaptchaSecChUa)
	req.Header.Set("sec-ch-ua-mobile", chromeCaptchaSecChUaMobile)
	req.Header.Set("sec-ch-ua-platform", chromeCaptchaSecChUaPlat)
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header[fhttp.HeaderOrderKey] = chromeHeaderOrder
	req.Header[fhttp.PHeaderOrderKey] = chromePHeaderOrder
}

// withCaptchaCtx attaches ctx to req — fhttp.NewRequest doesn't take
// a context the way net/http.NewRequestWithContext does, so we apply
// it post-hoc. Centralised so callers don't forget.
func withCaptchaCtx(ctx context.Context, req *fhttp.Request) *fhttp.Request {
	return req.WithContext(ctx)
}
