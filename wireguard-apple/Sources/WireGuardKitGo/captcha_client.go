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

// safariHeaderOrder is the order Safari iOS 18 writes HTTP/2 request
// headers in. Order matters for VK's classifier even though HTTP/2
// is semantically order-insensitive — Chrome and Safari diverge here
// and that's one of the cheap bot tells. Keep this in sync with
// whatever profile we pass to WithClientProfile below.
var safariHeaderOrder = []string{
	"host",
	"accept",
	"sec-fetch-site",
	"accept-encoding",
	"sec-fetch-mode",
	"user-agent",
	"accept-language",
	"sec-fetch-dest",
	"referer",
	"priority",
	"cookie",
	"content-type",
	"content-length",
	"origin",
}

// safariPHeaderOrder is the order Safari iOS writes HTTP/2 pseudo-
// headers. Almost every HTTP/2 client writes :method, :scheme,
// :path, :authority — but the exact order varies and is yet another
// bot tell. Safari iOS is the order below.
var safariPHeaderOrder = []string{
	":method",
	":scheme",
	":path",
	":authority",
}

// newTLSCaptchaClient returns a tls-client HttpClient with Safari
// iOS 18.0 fingerprint and a fresh cookie jar (each captcha solve
// gets its own jar — VK's classifier checks for prior session state
// and an empty jar simulates a clean browser launch).
//
// forceDirect was previously a hook to route HTTP through a non-utun
// interface when the tunnel egress hit a per-IP rate-limit. tls-
// client doesn't expose a DialContext slot the same way net/http
// does, so for now forceDirect is honored only as a documentation
// signal — the actual dial goes through whatever route iOS picks.
// If the field-log starts showing tunnel-egress rate-limits on
// captcha calls again, revisit by either (a) WithLocalAddr to a
// physical-interface IP we discover via getifaddrs, or (b) fork
// tls-client to add a DialContext option.
func newTLSCaptchaClient(forceDirect bool) (tlsclient.HttpClient, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}
	opts := []tlsclient.HttpClientOption{
		tlsclient.WithTimeoutSeconds(20),
		tlsclient.WithClientProfile(tlsprofiles.Safari_IOS_18_0),
		tlsclient.WithCookieJar(jar),
		// HTTP/3 isn't worth racing for VK's API hosts; HTTP/2 is
		// faster to first byte and matches what mobile Safari uses
		// for these endpoints anyway.
		tlsclient.WithDisableHttp3(),
	}
	_ = forceDirect // see comment above
	return tlsclient.NewHttpClient(tlsclient.NewNoopLogger(), opts...)
}

// applySafariHeaderOrder stamps the magic fhttp.HeaderOrderKey and
// PHeaderOrderKey on a request so the underlying RoundTripper writes
// headers in Safari's order. Call after setting all real headers.
func applySafariHeaderOrder(req *fhttp.Request) {
	req.Header[fhttp.HeaderOrderKey] = safariHeaderOrder
	req.Header[fhttp.PHeaderOrderKey] = safariPHeaderOrder
}

// withCaptchaCtx attaches ctx to req — fhttp.NewRequest doesn't take
// a context the way net/http.NewRequestWithContext does, so we apply
// it post-hoc. Centralised so callers don't forget.
func withCaptchaCtx(ctx context.Context, req *fhttp.Request) *fhttp.Request {
	return req.WithContext(ctx)
}
