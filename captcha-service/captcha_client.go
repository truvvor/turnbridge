// captcha_client.go — server-side equivalent of the iOS-side
// captcha_client.go. Builds a Safari iOS 18.0 TLS+HTTP/2 impersonator
// for VK API calls. See the iOS file for the full rationale of why
// we use bogdanfinn/tls-client + fhttp instead of net/http.
//
// Server-side specific: the underlying net.Dialer carries the WARP
// SO_BINDTODEVICE control hook so outbound captcha traffic egresses
// via Cloudflare's WARP edge when WARP_INTERFACE is configured. See
// warp_dialer.go.

package main

import (
	"context"

	fhttp "github.com/bogdanfinn/fhttp"
	"github.com/bogdanfinn/fhttp/cookiejar"
	tlsclient "github.com/bogdanfinn/tls-client"
	tlsprofiles "github.com/bogdanfinn/tls-client/profiles"
)

// Header / pseudo-header order Safari iOS 18 emits. Order is a
// classifier signal even though HTTP/2 is order-insensitive in the
// spec. Mirror of the iOS-side list — keep in sync.
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

var safariPHeaderOrder = []string{
	":method",
	":scheme",
	":path",
	":authority",
}

func newTLSCaptchaClient() (tlsclient.HttpClient, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}
	opts := []tlsclient.HttpClientOption{
		tlsclient.WithTimeoutSeconds(20),
		tlsclient.WithClientProfile(tlsprofiles.Safari_IOS_18_0),
		tlsclient.WithCookieJar(jar),
		tlsclient.WithDisableHttp3(),
		// WARP-pinned dialer if WARP_INTERFACE is set; otherwise a
		// vanilla net.Dialer with a no-op control hook.
		tlsclient.WithDialer(newWARPNetDialer()),
	}
	return tlsclient.NewHttpClient(tlsclient.NewNoopLogger(), opts...)
}

func applySafariHeaderOrder(req *fhttp.Request) {
	req.Header[fhttp.HeaderOrderKey] = safariHeaderOrder
	req.Header[fhttp.PHeaderOrderKey] = safariPHeaderOrder
}

func withCaptchaCtx(ctx context.Context, req *fhttp.Request) *fhttp.Request {
	return req.WithContext(ctx)
}
