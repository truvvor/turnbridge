// captcha_debug_info.go — mirror of the iOS-side file. See that file
// for the full rationale.

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

var debugInfoCache sync.Map

var scriptURLRe = regexp.MustCompile(`<script[^>]+src="([^"]+not_robot_captcha\.js[^"]*)"`)

var debugInfoRe = regexp.MustCompile(`debug_info\s*:\s*(?:[^"]*\|\|\s*)?"([a-fA-F0-9]{64})"`)

func extractScriptURL(html string) string {
	if m := scriptURLRe.FindStringSubmatch(html); len(m) >= 2 {
		return m[1]
	}
	return ""
}

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
