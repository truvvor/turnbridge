// captcha_debug_info.go — dynamic debug_info hash for VK captcha.
//
// VK's not_robot_captcha.js embeds a per-version 64-char hex string in
// a debug_info constant. The captchaNotRobot.check API call expects
// the same string echoed back as a debug_info query param — VK uses it
// as a "did this client actually load the same script the page
// referenced" signal. Sending the wrong value (or a stale one from a
// previous JS version) is one of the easiest bot tells they have.
//
// Our pre-v2 code pasted a hard-coded SHA-256 from one specific build
// of not_robot_captcha.js. VK pushes the script regularly; whenever
// they do, every solve from us starts failing with status=BOT until
// someone notices and updates the constant. The Moroka8 reference
// implementation handles this by fetching the script live, regex-
// extracting the hash, and caching it by script URL — which is what
// this file does.
//
// The script URL itself rotates infrequently (versioned path like
// `/vkid/2.5.7/not_robot_captcha.js`), so the cache hit-rate is high.

package main

import (
	"context"
	"fmt"
	"io"
	"regexp"
	"sync"

	fhttp "github.com/bogdanfinn/fhttp"
	tlsclient "github.com/bogdanfinn/tls-client"
)

// debugInfoCache maps script URL → 64-char hex debug_info. sync.Map
// because reads dominate writes and we want lock-free hits on the
// common path. Entries never expire — when VK ships a new version the
// URL changes, the cache miss kicks fetchDebugInfo, and the old entry
// stays around harmlessly (tens of bytes).
var debugInfoCache sync.Map

// scriptURLRe pulls the not_robot_captcha.js URL out of the bootstrap
// HTML. The path shape has stayed stable across the redesigns we've
// observed: `/vkid/<version>/not_robot_captcha.js` under one of a few
// CDN hosts. We match the whole src URL so we can fetch it directly.
var scriptURLRe = regexp.MustCompile(`<script[^>]+src="([^"]+not_robot_captcha\.js[^"]*)"`)

// debugInfoRe pulls the 64-hex-char debug_info constant out of the
// minified script. VK has used a few syntactic forms (assignment to a
// const, embedded in a larger string with || operators); the regex
// tolerates both.
var debugInfoRe = regexp.MustCompile(`debug_info\s*:\s*(?:[^"]*\|\|\s*)?"([a-fA-F0-9]{64})"`)

// extractScriptURL finds the not_robot_captcha.js URL in the bootstrap
// HTML. Returns "" if not present (typical when VK responds with a
// non-captcha page) — caller should fall back to the legacy hard-coded
// hash in that case.
func extractScriptURL(html string) string {
	if m := scriptURLRe.FindStringSubmatch(html); len(m) >= 2 {
		return m[1]
	}
	return ""
}

// fetchDebugInfo returns the debug_info hash for the given script URL,
// fetching and caching on first miss. ctx-aware so cancellation
// propagates. Returns "" + error if the fetch failed or the regex
// didn't match — caller should NOT fall back to a stale constant when
// this errors; better to fail the solve and retry on the next run
// (where the cache might be warm or VK might be in a healable state).
func fetchDebugInfo(ctx context.Context, client tlsclient.HttpClient, profile Profile, scriptURL string) (string, error) {
	if scriptURL == "" {
		return "", fmt.Errorf("empty scriptURL")
	}
	if cached, ok := debugInfoCache.Load(scriptURL); ok {
		return cached.(string), nil
	}

	req, err := fhttp.NewRequest("GET", scriptURL, nil)
	if err != nil {
		return "", err
	}
	req = withCaptchaCtx(ctx, req)
	req.Header.Set("User-Agent", profile.UserAgent)
	req.Header.Set("Accept", "text/javascript,application/javascript,*/*;q=0.1")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Referer", "https://id.vk.com/")
	req.Header.Set("Sec-Fetch-Site", "same-site")
	req.Header.Set("Sec-Fetch-Mode", "no-cors")
	req.Header.Set("Sec-Fetch-Dest", "script")
	applySafariHeaderOrder(req)

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("fetch script: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read script: %w", err)
	}

	m := debugInfoRe.FindSubmatch(body)
	if len(m) < 2 {
		return "", fmt.Errorf("debug_info constant not found in %s", scriptURL)
	}
	di := string(m[1])
	debugInfoCache.Store(scriptURL, di)
	return di, nil
}
