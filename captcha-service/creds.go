// creds.go — captcha-and-identity pipeline against VK Calls.
//
// Lifted verbatim from wireguard-apple/Sources/WireGuardKitGo/turn_proxy.go.
// Keep changes in sync when the iOS side gets fixes — eventually the
// shared logic should move into a third Go package both consume, but
// for V1 we copy.

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	neturl "net/url"
	"strings"
	"time"

	"github.com/google/uuid"
)

type getCredsFunc func(context.Context, string) (string, string, string, error)

// sharedAuthClient — package-level so the connection pool spans the
// whole server lifetime. See F4 in the iOS-side commit history.
var sharedAuthClient = &http.Client{
	Timeout: 20 * time.Second,
	Transport: &http.Transport{
		DialContext:         customDial,
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 100,
		IdleConnTimeout:     90 * time.Second,
	},
}

func getCreds(ctx context.Context, link string) (resUser string, resPass string, resTurn string, resErr error) {
	profile := getRandomProfile()
	name := generateName()
	escapedName := neturl.QueryEscape(name)

	log.Printf("Connecting - Name: %s | UA: %s", name, profile.UserAgent)

	doRequest := func(data string, url string) (resp map[string]interface{}, err error) {
		req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer([]byte(data)))
		if err != nil {
			return nil, err
		}

		req.Header.Add("User-Agent", profile.UserAgent)
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

		httpResp, err := sharedAuthClient.Do(req)
		if err != nil {
			return nil, err
		}
		defer func() {
			if closeErr := httpResp.Body.Close(); closeErr != nil {
				log.Printf("close response body: %s", closeErr)
			}
		}()

		body, err := io.ReadAll(httpResp.Body)
		if err != nil {
			return nil, err
		}

		err = json.Unmarshal(body, &resp)
		if err != nil {
			return nil, err
		}

		return resp, nil
	}

	var resp map[string]interface{}
	defer func() {
		if r := recover(); r != nil {
			log.Printf("get TURN creds error (bad JSON?): %v\n\n", resp)
			resErr = fmt.Errorf("panic in getCreds: %v", r)
		}
	}()

	data := "client_id=6287487&token_type=messages&client_secret=QbYic1K3lEV5kTGiqlq2&version=1&app_id=6287487"
	url := "https://login.vk.com/?act=get_anonym_token"

	resp, err := doRequest(data, url)
	if err != nil {
		return "", "", "", fmt.Errorf("request error:%s", err)
	}

	token1 := resp["data"].(map[string]interface{})["access_token"].(string)

	data = fmt.Sprintf("vk_join_link=https://vk.com/call/join/%s&name=%s&access_token=%s", link, escapedName, token1)
	reqURL := "https://api.vk.com/method/calls.getAnonymousToken?v=5.274&client_id=6287487"

	var token2 string
	const maxCaptchaAttempts = 3
	for attempt := 0; attempt <= maxCaptchaAttempts; attempt++ {
		resp, err = doRequest(data, reqURL)
		if err != nil {
			return "", "", "", fmt.Errorf("request error:%s", err)
		}

		if errObj, hasErr := resp["error"].(map[string]interface{}); hasErr {
			errCode, _ := errObj["error_code"].(float64)
			if errCode == 14 {
				if attempt == maxCaptchaAttempts {
					return "", "", "", fmt.Errorf("captcha failed after %d attempts", maxCaptchaAttempts)
				}

				captchaErr := ParseVkCaptchaError(errObj)
				if captchaErr.IsCaptchaError() {
					log.Printf("[Captcha] Attempt %d/%d: solving...", attempt+1, maxCaptchaAttempts)

					successToken, solveErr := solveVkCaptcha(ctx, captchaErr)
					if solveErr != nil {
						return "", "", "", fmt.Errorf("captcha solve error: %v", solveErr)
					}

					if captchaErr.CaptchaAttempt == "0" || captchaErr.CaptchaAttempt == "" {
						captchaErr.CaptchaAttempt = "1"
					}

					data = fmt.Sprintf("vk_join_link=https://vk.com/call/join/%s&name=%s"+
						"&captcha_key=&captcha_sid=%s&is_sound_captcha=0&success_token=%s"+
						"&captcha_ts=%s&captcha_attempt=%s&access_token=%s",
						link, escapedName, captchaErr.CaptchaSid, successToken,
						captchaErr.CaptchaTs, captchaErr.CaptchaAttempt, token1)
					continue
				}
			}
			return "", "", "", fmt.Errorf("VK API error: %v", errObj)
		}

		token2 = resp["response"].(map[string]interface{})["token"].(string)
		break
	}

	data = fmt.Sprintf("%s%s%s", "session_data=%7B%22version%22%3A2%2C%22device_id%22%3A%22", uuid.New(), "%22%2C%22client_version%22%3A1.1%2C%22client_type%22%3A%22SDK_JS%22%7D&method=auth.anonymLogin&format=JSON&application_key=CGMMEJLGDIHBABABA")
	url = "https://calls.okcdn.ru/fb.do"

	resp, err = doRequest(data, url)
	if err != nil {
		return "", "", "", fmt.Errorf("request error:%s", err)
	}

	token3 := resp["session_key"].(string)

	data = fmt.Sprintf("joinLink=%s&isVideo=false&protocolVersion=5&anonymToken=%s&method=vchat.joinConversationByLink&format=JSON&application_key=CGMMEJLGDIHBABABA&session_key=%s", link, token2, token3)
	url = "https://calls.okcdn.ru/fb.do"

	resp, err = doRequest(data, url)
	if err != nil {
		return "", "", "", fmt.Errorf("request error:%s", err)
	}

	user := resp["turn_server"].(map[string]interface{})["username"].(string)
	pass := resp["turn_server"].(map[string]interface{})["credential"].(string)
	turn := resp["turn_server"].(map[string]interface{})["urls"].([]interface{})[0].(string)

	clean := strings.Split(turn, "?")[0]
	address := strings.TrimPrefix(strings.TrimPrefix(clean, "turn:"), "turns:")

	return user, pass, address, nil
}
