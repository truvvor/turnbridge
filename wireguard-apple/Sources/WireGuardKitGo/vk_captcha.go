package main

import (
    "context"
    "crypto/rand"
    "crypto/sha256"
    "encoding/base64"
    "encoding/hex"
    "encoding/json"
    "errors"
    "fmt"
    "io"
    "log"
    mathrand "math/rand"
    "net/url"
    "regexp"
    "strconv"
    "strings"
    "time"

    fhttp "github.com/bogdanfinn/fhttp"
    tlsclient "github.com/bogdanfinn/tls-client"
)

type VkCaptchaError struct {
    ErrorCode               int
    ErrorMsg                string
    CaptchaSid              string
    CaptchaImg              string
    RedirectUri             string
    IsSoundCaptchaAvailable bool
    SessionToken            string
    CaptchaTs               string
    CaptchaAttempt          string
}

func randomHex(n int) string {
    bytes := make([]byte, n)
    if _, err := rand.Read(bytes); err != nil {
        for i := range bytes {
            bytes[i] = byte(mathrand.Intn(256))
        }
    }
    return hex.EncodeToString(bytes)
}

// newCaptchaClient is kept for backwards compat with call sites and
// just defers to the TLS-fingerprinted client. See captcha_client.go
// for the full rationale and the forceDirect caveat.
func newCaptchaClient(forceDirect bool) tlsclient.HttpClient {
    c, err := newTLSCaptchaClient(forceDirect)
    if err != nil {
        // tls-client.NewHttpClient can only fail on misconfigured
        // options. Our options are static and tested, so a panic
        // here means we built bogus options at compile time.
        panic(fmt.Sprintf("newTLSCaptchaClient: %v", err))
    }
    return c
}

func ParseVkCaptchaError(errData map[string]interface{}) *VkCaptchaError {
    codeFloat, _ := errData["error_code"].(float64)
    code := int(codeFloat)

    redirectUri, _ := errData["redirect_uri"].(string)
    captchaSid, _ := errData["captcha_sid"].(string)
    captchaImg, _ := errData["captcha_img"].(string)
    errorMsg, _ := errData["error_msg"].(string)

    var sessionToken string
    if redirectUri != "" {
        if parsed, err := url.Parse(redirectUri); err == nil {
            sessionToken = parsed.Query().Get("session_token")
        }
    }

    isSound, _ := errData["is_sound_captcha_available"].(bool)

    var captchaTs string
    if tsFloat, ok := errData["captcha_ts"].(float64); ok {
        captchaTs = fmt.Sprintf("%.0f", tsFloat)
    } else if tsStr, ok := errData["captcha_ts"].(string); ok {
        captchaTs = tsStr
    }

    var captchaAttempt string
    if attFloat, ok := errData["captcha_attempt"].(float64); ok {
        captchaAttempt = fmt.Sprintf("%.0f", attFloat)
    } else if attStr, ok := errData["captcha_attempt"].(string); ok {
        captchaAttempt = attStr
    }

    return &VkCaptchaError{
        ErrorCode:               code,
        ErrorMsg:                errorMsg,
        CaptchaSid:              captchaSid,
        CaptchaImg:              captchaImg,
        RedirectUri:             redirectUri,
        IsSoundCaptchaAvailable: isSound,
        SessionToken:            sessionToken,
        CaptchaTs:               captchaTs,
        CaptchaAttempt:          captchaAttempt,
    }
}

func (e *VkCaptchaError) IsCaptchaError() bool {
    return e.ErrorCode == 14 && e.RedirectUri != "" && e.SessionToken != ""
}

// solveVkCaptcha returns either a success_token (legacy path: caller
// retries the failing VK API call themselves) OR a full JSON response
// (new path: the WebView did the retry inside its own browser
// session, so the caller skips its own retry and uses the response
// directly).
//
// retryURL + retryBody describe the request the WebView should make
// after extracting success_token. retryBody contains the literal
// "__TOKEN__" placeholder. Pass empty strings to fall back to the
// token-only flow — that's still wired and works for backwards
// compat with older Swift bridges that don't know about the new
// response path.
func solveVkCaptcha(ctx context.Context, captchaErr *VkCaptchaError, retryURL, retryBody string) (string, string, error) {
    if manualCaptchaForcedMode() {
        log.Printf("[Captcha] Manual mode enabled — handing the challenge to the UI")
        // Manual solves run inside the iOS WebView, which is bound to
        // the user's mobile IP regardless of utun state — count them
        // as Direct. Field log 1.3.37 showed the UI badge sitting at
        // 0/0/0 even after a successful solve because requestManualCaptcha
        // bypassed the stats path entirely. Wrap with the same
        // markCaptchaAttemptStart/Done pair the auto-solver uses so the
        // user sees their bootstrap solve credited to Direct.
        isTunnel := markCaptchaAttemptStart(true /* forceDirect */)
        defer markCaptchaAttemptDone(isTunnel)
        tok, resp, err := requestManualCaptcha(captchaErr.RedirectUri, retryURL, retryBody, 180*time.Second)
        if err == nil {
            markCaptchaSuccess(isTunnel)
        }
        return tok, resp, err
    }

    // Bootstrap-manual-first. Under hard network blocking there is no
    // tunnel and no reachable captcha-service until the very first
    // session is up, so the first few identities MUST be earned by
    // hand. Running the tls-client auto-solver first in that window is
    // actively harmful: it reliably draws status:BOT, and that BOT
    // verdict poisons the captcha session / source IP that the user is
    // about to solve in a real WebKit engine moments later. So while no
    // session is ready (and the user opted into prompts at all), skip
    // the auto chain and go straight to the manual sheet. Gated on
    // mode != off so pure-auto users never see a surprise prompt, and
    // bounded by the per-session prompt quota inside requestManualCaptcha.
    if manualCaptchaBootstrapActive() {
        log.Printf("[Captcha] bootstrap (sessions_ready=0) — manual-first, skipping auto solve to avoid poisoning the session")
        tok, resp, err := requestManualCaptcha(captchaErr.RedirectUri, retryURL, retryBody, 180*time.Second)
        if err == nil {
            // Bootstrap manual SUCCESS: credit Direct. Bump both attempts
            // and OK so the ratio renders cleanly (1/1 not 1/0). Skip
            // the markCaptchaAttemptStart/Done pair the auto branch uses
            // because this branch can fall through to auto on
            // errDeferToRemote, and that branch has its own START — pre-
            // marking would double-count attempts for one user action.
            captchaDirectAttempts.Add(1)
            captchaDirectOK.Add(1)
            return tok, resp, nil
        }
        // errDeferToRemote (quota exhausted / a session came up while we
        // queued) means "let the normal routing take over" — fall
        // through to the auto chain rather than failing the solve.
        if !errors.Is(err, errDeferToRemote) {
            return "", "", err
        }
        log.Printf("[Captcha] bootstrap manual deferred (%v) — falling through to auto chain", err)
    }

    // Egress decision. The default is whatever captchaTunnelEgress
    // dictates (direct pre-handshake, tunnel post-handshake). When
    // tunnel is saturated AND direct still has budget, we override
    // and pin a physical interface (cellular / WiFi) for this attempt
    // so the request bypasses utun — that's the only way to retry
    // the direct egress after WG comes up. cellularDial falls back
    // to the system route if no usable physical interface is found.
    forceDirect := captchaTunnelEgress.Load() && tunnelSaturated() && !directSaturated()
    if forceDirect {
        log.Printf("[Captcha] tunnel egress saturated — forcing physical-interface egress")
    }

    // Bump the in-flight gauge for this egress so the UI sees an
    // increase the moment a solve starts. Released on every return
    // path via defer.
    isTunnel := markCaptchaAttemptStart(forceDirect)
    defer markCaptchaAttemptDone(isTunnel)

    // Anti-bot pacing used to live here as a 1.5-2.5 s pre-solve
    // sleep, but it was held INSIDE poolCreds' solveSlot semaphore
    // which throttles 5 in-flight solves. The slot now covers only
    // the real PoW + HTTP work; pacing has been moved to poolCreds'
    // pre-slot wait so the same wall-clock delay overlaps the slot
    // queue instead of serialising inside it.

    log.Printf("[Captcha] Solving Not Robot Captcha...")

    sessionToken := captchaErr.SessionToken
    if sessionToken == "" {
        return "", "", fmt.Errorf("no session_token in redirect_uri")
    }

    profile := getRandomProfile()
    client := newCaptchaClient(forceDirect)

    powInput, difficulty, htmlSettings, err := fetchPowInput(ctx, client, profile, captchaErr.RedirectUri)
    if err != nil {
        return "", "", fmt.Errorf("failed to fetch PoW input: %w", err)
    }

    log.Printf("[Captcha] PoW input: %s, difficulty: %d, htmlSettings=%v", powInput, difficulty, htmlSettings != nil)

    hash := solvePoW(powInput, difficulty)
    log.Printf("[Captcha] PoW solved: hash=%s", hash)

    successToken, err := callCaptchaNotRobot(ctx, client, profile, sessionToken, hash, htmlSettings, isTunnel)
    if err != nil {
        // Manual-fallback mode: hand the redirect_uri to the iOS UI
        // and let the user solve in SFSafariViewController instead of
        // returning failure to the caller (which would recycle a
        // stale identity). Only consulted when the auto chain has
        // actually run AND failed, so user only sees prompts for the
        // 15-20% of identities the solver couldn't earn on its own.
        if manualCaptchaFallbackAvailable() {
            log.Printf("[Captcha] auto failed (%v) — escalating to manual prompt", err)
            tok, resp, mErr := requestManualCaptcha(captchaErr.RedirectUri, retryURL, retryBody, 180*time.Second)
            if mErr == nil {
                log.Printf("[Captcha] Success via manual fallback (response_path=%v)", resp != "")
                markCaptchaSuccess(isTunnel)
                return tok, resp, nil
            }
            return "", "", fmt.Errorf("captchaNotRobot API failed: %w (manual fallback also failed: %v)", err, mErr)
        }
        return "", "", fmt.Errorf("captchaNotRobot API failed: %w", err)
    }

    log.Printf("[Captcha] Success! Got success_token")
    return successToken, "", nil
}

func fetchPowInput(ctx context.Context, client tlsclient.HttpClient, profile Profile, redirectUri string) (string, int, map[string]interface{}, error) {
    req, err := fhttp.NewRequest("GET", redirectUri, nil)
    if err != nil {
        return "", 0, nil, err
    }
    req = withCaptchaCtx(ctx, req)

    req.Header.Set("User-Agent", profile.UserAgent)
    req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8")
    req.Header.Set("Accept-Language", "en-US,en;q=0.9")
    // Safari iOS deliberately doesn't implement Client Hints — sending
    // sec-ch-ua* from a Safari UA was itself a bot tell on the old
    // net/http path. With Safari_IOS_18_0 fingerprint we mirror real
    // Safari at every layer, so we drop these unconditionally.
    req.Header.Set("Sec-Fetch-Site", "none")
    req.Header.Set("Sec-Fetch-Mode", "navigate")
    req.Header.Set("Sec-Fetch-Dest", "document")
    applySafariHeaderOrder(req)

    resp, err := client.Do(req)
    if err != nil {
        return "", 0, nil, err
    }
    defer resp.Body.Close()

    body, err := io.ReadAll(resp.Body)
    if err != nil {
        return "", 0, nil, err
    }

    html := string(body)

    // Parse PoW input
    powInputRe := regexp.MustCompile(`const\s+powInput\s*=\s*"([^"]+)"`)
    powInputMatch := powInputRe.FindStringSubmatch(html)
    if len(powInputMatch) < 2 {
        return "", 0, nil, fmt.Errorf("powInput not found in captcha HTML")
    }
    powInput := powInputMatch[1]

    // Parse difficulty
    diffRe := regexp.MustCompile(`startsWith\('0'\.repeat\((\d+)\)\)`)
    diffMatch := diffRe.FindStringSubmatch(html)
    difficulty := 2
    if len(diffMatch) >= 2 {
        if d, err := strconv.Atoi(diffMatch[1]); err == nil {
            difficulty = d
        }
    }

    // Parse window.init for slider captcha settings
    var htmlSettings map[string]interface{}
    initRe := regexp.MustCompile(`(?s)window\.init\s*=\s*(\{.*?\})\s*;\s*window\.lang`)
    if initMatch := initRe.FindStringSubmatch(html); len(initMatch) >= 2 {
        var initPayload map[string]interface{}
        if err := json.Unmarshal([]byte(initMatch[1]), &initPayload); err == nil {
            if data, ok := initPayload["data"].(map[string]interface{}); ok {
                htmlSettings = map[string]interface{}{"response": data}
                log.Printf("[Captcha] Parsed window.init htmlSettings")
            }
        }
    }

    // Locate not_robot_captcha.js so callCaptchaNotRobot can fetch
    // the live debug_info hash from it (see captcha_debug_info.go).
    // Empty string is OK — the caller handles the absent-script path.
    scriptURL := extractScriptURL(html)
    if scriptURL != "" {
        // Stash on htmlSettings so we don't need to grow the function
        // signature. The map is opaque downstream apart from
        // captchaNotRobot.check.
        if htmlSettings == nil {
            htmlSettings = map[string]interface{}{}
        }
        htmlSettings["_scriptURL"] = scriptURL
    }

    return powInput, difficulty, htmlSettings, nil
}

func solvePoW(powInput string, difficulty int) string {
    target := strings.Repeat("0", difficulty)

    for nonce := 1; nonce <= 10000000; nonce++ {
        data := powInput + strconv.Itoa(nonce)
        hash := sha256.Sum256([]byte(data))
        hexHash := hex.EncodeToString(hash[:])

        if strings.HasPrefix(hexHash, target) {
            return hexHash
        }
    }
    return ""
}

func callCaptchaNotRobot(ctx context.Context, client tlsclient.HttpClient, profile Profile, sessionToken, hash string, htmlSettings map[string]interface{}, isTunnel bool) (string, error) {
    vkReq := func(method string, postData string) (map[string]interface{}, error) {
        requestURL := "https://api.vk.com/method/" + method + "?v=5.131"

        req, err := fhttp.NewRequest("POST", requestURL, strings.NewReader(postData))
        if err != nil {
            return nil, err
        }
        req = withCaptchaCtx(ctx, req)

        req.Header.Set("User-Agent", profile.UserAgent)
        req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
        req.Header.Set("Accept", "*/*")
        req.Header.Set("Accept-Language", "en-US,en;q=0.9")
        req.Header.Set("Origin", "https://id.vk.com")
        req.Header.Set("Referer", "https://id.vk.com/")
        // No sec-ch-ua* — Safari doesn't send them; sending from a
        // Safari fingerprint is itself a classifier tell.
        req.Header.Set("Sec-Fetch-Site", "same-site")
        req.Header.Set("Sec-Fetch-Mode", "cors")
        req.Header.Set("Sec-Fetch-Dest", "empty")
        req.Header.Set("Priority", "u=1, i")
        applySafariHeaderOrder(req)

        httpResp, err := client.Do(req)
        if err != nil {
            return nil, err
        }
        defer httpResp.Body.Close()

        body, err := io.ReadAll(httpResp.Body)
        if err != nil {
            return nil, err
        }

        var resp map[string]interface{}
        if err := json.Unmarshal(body, &resp); err != nil {
            return nil, err
        }

        return resp, nil
    }

    domain := "vk.com"
    baseParams := fmt.Sprintf("session_token=%s&domain=%s&adFp=&access_token=",
        url.QueryEscape(sessionToken), url.QueryEscape(domain))

    // Step 1: settings
    log.Printf("[Captcha] Step 1/4: settings")
    settingsResp, err := vkReq("captchaNotRobot.settings", baseParams)
    if err != nil {
        return "", fmt.Errorf("settings failed: %w", err)
    }
    time.Sleep(time.Duration(100+mathrand.Intn(100)) * time.Millisecond)

    // Step 2: componentDone
    log.Printf("[Captcha] Step 2/4: componentDone")

    // crypto/rand-backed 32-hex-char browser fingerprint. The pre-v2
    // version used math/rand which is seeded weakly and predictably.
    browserFp := randomHex(16)

    // v2 device shape: 11 fixed fields matching what a real desktop
    // browser reports through navigator.* probes. The pre-v2 version
    // randomised resolutions and CPU counts per call, which created
    // a per-solve fingerprint churn that VK's classifier could
    // correlate against the stable TLS fingerprint and flag as bot
    // behaviour. v2 ships the same desktop Chrome 8-core/1080p shape
    // every time; combined with random browser_fp + cursor jitter
    // it's noisy enough on the variable signals that matter.
    const (
        screenW = 1920
        screenH = 1080
    )
    deviceMap := map[string]interface{}{
        "screenWidth":             screenW,
        "screenHeight":            screenH,
        "screenAvailWidth":        screenW,
        "screenAvailHeight":       screenH,
        "innerWidth":              screenW,
        "innerHeight":             951,
        "devicePixelRatio":        1,
        "language":                "en-US",
        "languages":               []string{"en-US", "en"},
        "webdriver":               false,
        "hardwareConcurrency":     8,
        "notificationsPermission": "denied",
    }
    deviceBytes, _ := json.Marshal(deviceMap)

    componentDoneData := baseParams + fmt.Sprintf("&browser_fp=%s&device=%s",
        browserFp, url.QueryEscape(string(deviceBytes)))

    _, err = vkReq("captchaNotRobot.componentDone", componentDoneData)
    if err != nil {
        return "", fmt.Errorf("componentDone failed: %w", err)
    }
    time.Sleep(time.Duration(1500+mathrand.Intn(1000)) * time.Millisecond)

    // Step 3: checkbox check
    log.Printf("[Captcha] Step 3/4: check (checkbox)")

    type Point struct {
        X int   `json:"x"`
        Y int   `json:"y"`
        T int64 `json:"t"`
    }
    var cursor []Point
    startX, startY := screenW/2+mathrand.Intn(200)-100, screenH/2+mathrand.Intn(200)-100
    startTime := time.Now().Add(-300 * time.Millisecond).UnixMilli()

    pointsCount := 4 + mathrand.Intn(5)
    for i := 0; i < pointsCount; i++ {
        cursor = append(cursor, Point{
            X: startX,
            Y: startY,
            T: startTime + int64(i*20+mathrand.Intn(10)),
        })
        startX += mathrand.Intn(30) - 15
        startY += mathrand.Intn(30) - 15
    }
    cursorBytes, _ := json.Marshal(cursor)

    answer := base64.StdEncoding.EncodeToString([]byte("{}"))

    // Fetch debug_info from not_robot_captcha.js (cached). If we can't
    // (no scriptURL in HTML, or fetch failed), fall back to the legacy
    // constant — better than skipping check entirely; on a healthy
    // build the constant happens to match and we degrade gracefully.
    scriptURL, _ := htmlSettings["_scriptURL"].(string)
    debugInfo, debugErr := fetchDebugInfo(ctx, client, profile, scriptURL)
    if debugErr != nil {
        log.Printf("[Captcha] fetchDebugInfo: %v — using legacy constant", debugErr)
        debugInfo = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    }

    // All motion arrays empty per v2 wire shape: VK's classifier looks
    // for "client emits zero device events" as a sign of an honest
    // desktop browser (not a touch-event-streaming mobile). The pre-v2
    // populated connectionDownlink array was a low-signal noise
    // generator that didn't fool anything.
    checkData := baseParams + fmt.Sprintf(
        "&accelerometer=%s&gyroscope=%s&motion=%s&cursor=%s&taps=%s&connectionRtt=%s&connectionDownlink=%s"+
            "&browser_fp=%s&hash=%s&answer=%s&debug_info=%s",
        url.QueryEscape("[]"),
        url.QueryEscape("[]"),
        url.QueryEscape("[]"),
        url.QueryEscape(string(cursorBytes)),
        url.QueryEscape("[]"),
        url.QueryEscape("[]"),
        url.QueryEscape("[]"),
        browserFp,
        hash,
        answer,
        debugInfo,
    )

    checkResp, err := vkReq("captchaNotRobot.check", checkData)
    if err != nil {
        return "", fmt.Errorf("check failed: %w", err)
    }

    respObj, ok := checkResp["response"].(map[string]interface{})
    if !ok {
        return "", fmt.Errorf("invalid check response: %v", checkResp)
    }

    status, _ := respObj["status"].(string)
    showType, _ := respObj["show_captcha_type"].(string)
    log.Printf("[Captcha] checkbox status: %s show_type=%q", status, showType)

    if status == "OK" {
        successToken, ok := respObj["success_token"].(string)
        if ok && successToken != "" {
            log.Printf("[Captcha] Step 4/4: endSession")
            _, _ = vkReq("captchaNotRobot.endSession", baseParams)
            markCaptchaSuccess(isTunnel)
            return successToken, nil
        }
    }

    if status == "ERROR_LIMIT" {
        // VK rate-limited the source IP. The slider path uses the
        // same egress and the same rate-limit bucket, so trying slider
        // would just burn another doomed request and (worse) saturate
        // the next iteration earlier. Surface the error and let the
        // outer retry storm controller decide.
        markCaptchaSaturated(isTunnel)
        return "", fmt.Errorf("captchaNotRobot.check ERROR_LIMIT (no slider fallback under rate-limit)")
    }

    // v2 routing: only attempt slider when VK explicitly says BOT
    // AND we have slider settings to feed it. Other non-OK statuses
    // (server errors, unknown) shouldn't auto-fall-through to slider
    // because slider is a separate, heavier request that VK can also
    // 4xx independently.
    sliderEligible := status == "BOT" && (showType == "" || showType == "slider")
    if !sliderEligible {
        return "", fmt.Errorf("captchaNotRobot.check non-OK status=%q show_type=%q", status, showType)
    }

    log.Printf("[Captcha] Checkbox status=BOT show_type=%q, switching to slider", showType)

    // Use htmlSettings from the HTML page if available, otherwise use API settings
    mergedSettings := settingsResp
    if htmlSettings != nil {
        mergedSettings = htmlSettings
    }

    sliderToken, sliderErr := solveSliderCaptcha(vkReq, baseParams, browserFp, hash, debugInfo, mergedSettings, isTunnel)
    if sliderErr != nil {
        // saturation accounting now happens inside solveSliderCaptcha
        // at the exact branch (ERROR_LIMIT or unparseable_response),
        // so this caller just propagates the error.
        return "", fmt.Errorf("slider captcha also failed: %w", sliderErr)
    }

    log.Printf("[Captcha] Slider solved! endSession...")
    _, _ = vkReq("captchaNotRobot.endSession", baseParams)
    markCaptchaSuccess(isTunnel)
    return sliderToken, nil
}

func buildCaptchaDeviceJSON(profile Profile) string {
    return fmt.Sprintf(
        `{"screenWidth":1920,"screenHeight":1080,"screenAvailWidth":1920,"screenAvailHeight":1040,"innerWidth":1920,"innerHeight":969,"devicePixelRatio":1,"language":"en-US","languages":["en-US"],"webdriver":false,"hardwareConcurrency":8,"deviceMemory":8,"connectionEffectiveType":"4g","notificationsPermission":"default","userAgent":"%s","platform":"Win32"}`,
        profile.UserAgent,
    )
}
