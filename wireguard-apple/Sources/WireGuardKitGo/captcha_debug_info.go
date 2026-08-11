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
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
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

// hex64Re matches a bare 64-hex-char literal — the windowed fallback
// when the structured debug_info pattern misses because VK renamed the
// `window.vk.X` wrapper between builds (script-format drift). Idea
// ported from WINGS-N/vk-turn-proxy@cc712ba (via samosvalishe).
var hex64Re = regexp.MustCompile(`"([a-fA-F0-9]{64})"`)

// scriptVersionRe extracts the version segment from the script URL
// (`/vkid/<version>/not_robot_captcha.js`) so we can log once per
// distinct build and correlate a rise in BOT rejections with a VK
// script push we can actually see in the field logs.
var scriptVersionRe = regexp.MustCompile(`/vkid/([^/]+)/not_robot_captcha\.js`)

// scriptVersionSeen dedupes the once-per-version drift log.
var scriptVersionSeen sync.Map

// warnScriptVersionDrift logs the observed not_robot_captcha.js version
// once per distinct value. We have no single hard-coded "tested"
// baseline (VK ships often), so instead of asserting against one we
// surface every new version we see — if BOT rates climb, the log shows
// which build shipped just before.
func warnScriptVersionDrift(scriptURL string) {
	m := scriptVersionRe.FindStringSubmatch(scriptURL)
	if len(m) < 2 || m[1] == "" {
		return
	}
	if _, seen := scriptVersionSeen.LoadOrStore(m[1], struct{}{}); seen {
		return
	}
	log.Printf("[Captcha] not_robot_captcha.js version %s observed; wire unverified against this build — re-check if BOT rejections rise", m[1])
}

// extractDebugInfoHash pulls the 64-hex debug_info constant from the
// script body. Primary: the structured debug_info regex. Fallback
// (returns usedFallback=true): the first bare 64-hex literal within a
// window right after the `debug_info` marker, for when VK's wrapper
// name drifted and the structured pattern missed.
func extractDebugInfoHash(body []byte) (hash string, usedFallback bool, err error) {
	if m := debugInfoRe.FindSubmatch(body); len(m) >= 2 {
		return string(m[1]), false, nil
	}
	idx := bytes.Index(body, []byte("debug_info"))
	if idx < 0 {
		return "", false, fmt.Errorf("debug_info marker not found in script")
	}
	end := idx + 400
	if end > len(body) {
		end = len(body)
	}
	if m := hex64Re.FindSubmatch(body[idx:end]); len(m) >= 2 {
		return string(m[1]), true, nil
	}
	return "", false, fmt.Errorf("debug_info hash not found near marker")
}

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
	req.Header.Set("Accept", "text/javascript,application/javascript,*/*;q=0.1")
	req.Header.Set("Referer", "https://id.vk.com/")
	req.Header.Set("Sec-Fetch-Site", "same-site")
	req.Header.Set("Sec-Fetch-Mode", "no-cors")
	req.Header.Set("Sec-Fetch-Dest", "script")
	// Coherent desktop-Chrome identity — must match the auto-solver's
	// other requests so VK sees one browser fetch the script then call
	// the API.
	applyCaptchaBrowserHeaders(req)
	_ = profile

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("fetch script: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read script: %w", err)
	}

	warnScriptVersionDrift(scriptURL)

	di, usedFallback, err := extractDebugInfoHash(body)
	if err != nil {
		return "", fmt.Errorf("%w in %s", err, scriptURL)
	}
	if usedFallback {
		log.Printf("[Captcha] debug_info primary pattern missed; used windowed fallback (script-format drift) for %s", scriptURL)
	}
	debugInfoCache.Store(scriptURL, di)
	return di, nil
}
