package main

import (
    "bytes"
    "encoding/base64"
    "encoding/json"
    "fmt"
    "image"
    "image/color"
    _ "image/jpeg"
    "log"
    neturl "net/url"
    "sort"
    "strconv"
    "strings"
    "time"
)

const (
    sliderCaptchaType     = "slider"
    defaultSliderAttempts = 4
)

// vkReqFunc is the type for the VK API request helper from callCaptchaNotRobotAPI.
type vkReqFunc func(method, postData string) (map[string]interface{}, error)

type sliderCaptchaContent struct {
    Image    image.Image
    GridW    int   // tile columns
    GridH    int   // tile rows
    Steps    []int // swap pairs
    Attempts int   // max submit attempts
}

type sliderCandidate struct {
    Index       int
    ActiveSteps []int
    Score       int64
}

// solveSliderCaptcha attempts to solve a VK slider captcha automatically.
// It fetches the scrambled image via captchaNotRobot.getContent, analyzes
// tile border continuity to find the correct permutation, and submits the answer.
func solveSliderCaptcha(
    vkReq vkReqFunc,
    baseParams string,
    browserFp string,
    hash string,
    settingsResp map[string]interface{},
) (string, error) {
    // Extract slider settings from the settings response
    sliderSettings := extractSliderSettings(settingsResp)

    log.Printf("slider: fetching captcha content (settings=%q)", sliderSettings)

    // Open a captcha trap. Every artefact we collect during the solve
    // is buffered in memory and either Discarded (on success) or
    // Committed (on any failure path). The deferred Discard is the
    // safety net — explicit Commit calls in the failure branches run
    // first, and Commit/Discard are idempotent.
    trap := newCaptchaTrap("slider")
    defer trap.Discard()
    trap.Note("settings_raw=%q", sliderSettings)

    // Get scrambled image and swap instructions
    getContentData := baseParams
    if sliderSettings != "" {
        getContentData += "&captcha_settings=" + neturl.QueryEscape(sliderSettings)
    }

    resp, err := vkReq("captchaNotRobot.getContent", getContentData)
    if err != nil {
        trap.Note("getContent transport error: %v", err)
        trap.Commit("getContent_transport_err")
        return "", fmt.Errorf("slider getContent: %w", err)
    }

    // Save the raw getContent response and the image bytes as soon as
    // we have them, BEFORE parsing — that way a new captcha variant
    // that breaks parseSliderContent still leaves us a self-contained
    // artefact to inspect.
    if rawJSON, jerr := json.MarshalIndent(resp, "", "  "); jerr == nil {
        trap.Save("getContent_response.json", rawJSON)
    }
    if respMap, ok := resp["response"].(map[string]interface{}); ok {
        if imgStr, ok := respMap["image"].(string); ok && imgStr != "" {
            if rawBytes, derr := base64.StdEncoding.DecodeString(imgStr); derr == nil {
                ext := "bin"
                if e, ok := respMap["extension"].(string); ok && e != "" {
                    ext = strings.ToLower(e)
                }
                trap.Save("image."+ext, rawBytes)
            }
        }
    }

    content, err := parseSliderContent(resp)
    if err != nil {
        // status:ERROR / status:ERROR_LIMIT from slider getContent
        // is VK rate-limiting us at the slider gate — count as a
        // saturation hit so a high-N run doesn't keep spawning more
        // sessions that will all hit the same wall. The fail streak
        // resets on the next success.
        markCaptchaSaturated()
        trap.Note("parseSliderContent failed: %v", err)
        trap.Commit("unparseable_response")
        return "", fmt.Errorf("slider parse: %w", err)
    }
    trap.Note("parsed grid=%dx%d swaps=%d attempts=%d",
        content.GridW, content.GridH, len(content.Steps)/2, content.Attempts)

    log.Printf("slider: image=%dx%d grid=%dx%d steps=%d attempts=%d",
        content.Image.Bounds().Dx(), content.Image.Bounds().Dy(),
        content.GridW, content.GridH, len(content.Steps)/2, content.Attempts)

    // Rank candidate positions by pixel border continuity
    candidates, err := rankSliderCandidates(content.Image, content.GridW, content.GridH, content.Steps)
    if err != nil {
        trap.Note("rank failed: %v", err)
        trap.Commit("rank_failed")
        return "", fmt.Errorf("slider rank: %w", err)
    }

    maxTries := content.Attempts
    if maxTries > len(candidates) {
        maxTries = len(candidates)
    }

    log.Printf("slider: ranked %d positions, trying top %d", len(candidates), maxTries)

    // Try each candidate
    for i := 0; i < maxTries; i++ {
        c := candidates[i]
        log.Printf("slider: guess %d/%d position=%d score=%d", i+1, maxTries, c.Index, c.Score)

        answer, err := encodeSliderAnswer(c.ActiveSteps)
        if err != nil {
            trap.Note("encodeSliderAnswer failed: %v", err)
            trap.Commit("encode_answer_err")
            return "", err
        }

        // Generate slider cursor (simulates drag from left to position)
        cursor := generateSliderCursor(c.Index, len(candidates))

        checkData := baseParams + fmt.Sprintf(
            "&accelerometer=%s&gyroscope=%s&motion=%s&cursor=%s&taps=%s&connectionRtt=%s&connectionDownlink=%s"+
                "&browser_fp=%s&hash=%s&answer=%s&debug_info=%s",
            neturl.QueryEscape("[]"), neturl.QueryEscape("[]"), neturl.QueryEscape("[]"),
            neturl.QueryEscape(cursor),
            neturl.QueryEscape("[]"), neturl.QueryEscape("[]"), neturl.QueryEscape("[]"),
            browserFp, hash, neturl.QueryEscape(answer),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        )

        checkResp, err := vkReq("captchaNotRobot.check", checkData)
        if err != nil {
            trap.Note("attempt %d/%d transport err: %v", i+1, maxTries, err)
            trap.Commit("check_transport_err")
            return "", fmt.Errorf("slider check: %w", err)
        }

        respObj, ok := checkResp["response"].(map[string]interface{})
        if !ok {
            trap.Note("attempt %d/%d invalid response: %v", i+1, maxTries, checkResp)
            trap.Commit("check_invalid_response")
            return "", fmt.Errorf("slider check: invalid response")
        }

        status, _ := respObj["status"].(string)
        trap.Note("attempt %d/%d position=%d score=%d → status=%s",
            i+1, maxTries, c.Index, c.Score, status)
        switch status {
        case "OK":
            successToken, _ := respObj["success_token"].(string)
            if successToken == "" {
                trap.Note("OK but success_token missing in: %v", respObj)
                trap.Commit("ok_without_token")
                return "", fmt.Errorf("slider: success_token not found")
            }
            log.Printf("slider: solved! position=%d (attempt %d/%d)", c.Index, i+1, maxTries)
            // Commit solved captchas too so the user can actually see
            // what our solver is processing. The reason field marks
            // them "solved_ok"; unsolved entries use other reasons.
            // Without this commit a healthy run produces an empty trap
            // dir, which looks indistinguishable from "the trap isn't
            // wired correctly".
            trap.Note("SOLVED at attempt %d/%d, position=%d", i+1, maxTries, c.Index)
            trap.Commit("solved_ok")
            return successToken, nil
        case "ERROR_LIMIT":
            markCaptchaSaturated()
            trap.Commit("error_limit")
            return "", fmt.Errorf("slider: ERROR_LIMIT")
        default:
            log.Printf("slider: position=%d rejected (status=%s)", c.Index, status)
            time.Sleep(500 * time.Millisecond)
        }
    }

    trap.Commit("all_guesses_rejected")
    return "", fmt.Errorf("slider: all %d guesses rejected", maxTries)
}

// extractSliderSettings extracts slider captcha_settings from settings API response.
func extractSliderSettings(settingsResp map[string]interface{}) string {
    if settingsResp == nil {
        return ""
    }
    respObj, ok := settingsResp["response"].(map[string]interface{})
    if !ok {
        return ""
    }

    // Try to find captcha_settings for slider type
    raw := respObj["captcha_settings"]
    if raw == nil {
        return ""
    }

    // captcha_settings can be array or map
    switch v := raw.(type) {
    case []interface{}:
        for _, item := range v {
            m, ok := item.(map[string]interface{})
            if !ok {
                continue
            }
            t, _ := m["type"].(string)
            if t == sliderCaptchaType {
                return normalizeSettings(m["settings"])
            }
        }
    case map[string]interface{}:
        if s, ok := v[sliderCaptchaType]; ok {
            return normalizeSettings(s)
        }
    case string:
        // Try JSON parse
        trimmed := strings.TrimSpace(v)
        if trimmed == "" {
            return ""
        }
        var items []interface{}
        if err := json.Unmarshal([]byte(trimmed), &items); err == nil {
            return extractSliderSettings(map[string]interface{}{
                "response": map[string]interface{}{"captcha_settings": items},
            })
        }
    }
    return ""
}

func normalizeSettings(raw interface{}) string {
    switch v := raw.(type) {
    case nil:
        return ""
    case string:
        return v
    default:
        data, err := json.Marshal(v)
        if err != nil {
            return ""
        }
        return string(data)
    }
}

// parseSliderContent parses the getContent API response.
func parseSliderContent(resp map[string]interface{}) (*sliderCaptchaContent, error) {
    respObj, ok := resp["response"].(map[string]interface{})
    if !ok {
        return nil, fmt.Errorf("invalid response: %v", resp)
    }

    status, _ := respObj["status"].(string)
    if status != "OK" {
        return nil, fmt.Errorf("status: %s", status)
    }

    ext, _ := respObj["extension"].(string)
    ext = strings.ToLower(ext)
    if ext != "jpeg" && ext != "jpg" {
        return nil, fmt.Errorf("unsupported image format: %s", ext)
    }

    rawImage, _ := respObj["image"].(string)
    if rawImage == "" {
        return nil, fmt.Errorf("image missing")
    }

    rawSteps, ok := respObj["steps"].([]interface{})
    if !ok {
        return nil, fmt.Errorf("steps missing")
    }

    steps, err := parseIntSlice(rawSteps)
    if err != nil {
        return nil, err
    }

    gridW, gridH, swaps, attempts, err := parseSliderSteps(steps)
    if err != nil {
        return nil, err
    }

    img, err := decodeSliderImage(rawImage)
    if err != nil {
        return nil, err
    }

    return &sliderCaptchaContent{
        Image:    img,
        GridW:    gridW,
        GridH:    gridH,
        Steps:    swaps,
        Attempts: attempts,
    }, nil
}

func parseIntSlice(raw []interface{}) ([]int, error) {
    values := make([]int, 0, len(raw))
    for _, item := range raw {
        switch v := item.(type) {
        case float64:
            values = append(values, int(v))
        case int:
            values = append(values, v)
        case string:
            n, err := strconv.Atoi(strings.TrimSpace(v))
            if err != nil {
                return nil, fmt.Errorf("invalid numeric: %v", item)
            }
            values = append(values, n)
        default:
            return nil, fmt.Errorf("invalid numeric: %v", item)
        }
    }
    return values, nil
}

// parseSliderSteps decodes VK's `steps` array. Two formats observed:
//
//   square:   [size, swap_pairs..., attempts?]            // tile grid = size×size
//   rect:     [width, height, swap_pairs..., attempts?]   // tile grid = width×height
//
// VK started serving the rectangular variant (3×7 word-strip layouts:
// ШАПОЧКИ / КОРРУПЦИЯ / СКЕПТИЦИЗМ etc.) where the old square parser
// produces tile-counts that don't contain the swap indices and the
// renderer scrambles the image instead of unscrambling. We try
// square first (backward-compatible: pre-existing 3×3, 4×4, etc.
// captchas keep parsing the same way), then rect, then bail with the
// raw payload logged so a third format can be added without
// guesswork.
func parseSliderSteps(steps []int) (gridW int, gridH int, swaps []int, attempts int, err error) {
    if len(steps) < 3 {
        return 0, 0, nil, 0, fmt.Errorf("steps too short: %d", len(steps))
    }
    log.Printf("slider: raw steps payload: %v", steps)

    if w, h, sw, at, ok := decodeSliderStepsSquare(steps); ok {
        log.Printf("slider: parsed as %dx%d (square format), %d candidates, %d attempts",
            w, h, len(sw)/2, at)
        return w, h, sw, at, nil
    }
    if w, h, sw, at, ok := decodeSliderStepsRect(steps); ok {
        log.Printf("slider: parsed as %dx%d (rect format), %d candidates, %d attempts",
            w, h, len(sw)/2, at)
        return w, h, sw, at, nil
    }
    return 0, 0, nil, 0, fmt.Errorf("unrecognised steps payload %v", steps)
}

func decodeSliderStepsSquare(steps []int) (w, h int, swaps []int, attempts int, ok bool) {
    size := steps[0]
    if size <= 0 {
        return 0, 0, nil, 0, false
    }
    tileCount := size * size
    rest := append([]int(nil), steps[1:]...)
    attempts = defaultSliderAttempts
    if len(rest)%2 != 0 {
        attempts = rest[len(rest)-1]
        rest = rest[:len(rest)-1]
    }
    if attempts <= 0 {
        attempts = defaultSliderAttempts
    }
    if len(rest) == 0 || len(rest)%2 != 0 {
        return 0, 0, nil, 0, false
    }
    for _, v := range rest {
        if v < 0 || v >= tileCount {
            return 0, 0, nil, 0, false
        }
    }
    return size, size, rest, attempts, true
}

func decodeSliderStepsRect(steps []int) (w, h int, swaps []int, attempts int, ok bool) {
    if len(steps) < 4 {
        return 0, 0, nil, 0, false
    }
    width, height := steps[0], steps[1]
    if width <= 0 || height <= 0 {
        return 0, 0, nil, 0, false
    }
    tileCount := width * height
    rest := append([]int(nil), steps[2:]...)
    attempts = defaultSliderAttempts
    if len(rest)%2 != 0 {
        attempts = rest[len(rest)-1]
        rest = rest[:len(rest)-1]
    }
    if attempts <= 0 {
        attempts = defaultSliderAttempts
    }
    if len(rest) == 0 || len(rest)%2 != 0 {
        return 0, 0, nil, 0, false
    }
    for _, v := range rest {
        if v < 0 || v >= tileCount {
            return 0, 0, nil, 0, false
        }
    }
    return width, height, rest, attempts, true
}

func decodeSliderImage(rawImage string) (image.Image, error) {
    decoded, err := base64.StdEncoding.DecodeString(rawImage)
    if err != nil {
        return nil, fmt.Errorf("base64 decode: %w", err)
    }
    img, _, err := image.Decode(bytes.NewReader(decoded))
    if err != nil {
        return nil, fmt.Errorf("image decode: %w", err)
    }
    return img, nil
}

func encodeSliderAnswer(activeSteps []int) (string, error) {
    payload := struct {
        Value []int `json:"value"`
    }{Value: activeSteps}
    data, err := json.Marshal(payload)
    if err != nil {
        return "", err
    }
    return base64.StdEncoding.EncodeToString(data), nil
}

// rankSliderCandidates analyzes each candidate permutation and ranks by
// pixel border continuity (lower score = better match = more likely correct).
func rankSliderCandidates(img image.Image, gridW, gridH int, swaps []int) ([]sliderCandidate, error) {
    candidateCount := len(swaps) / 2
    if candidateCount == 0 {
        return nil, fmt.Errorf("no candidates")
    }

    candidates := make([]sliderCandidate, 0, candidateCount)
    for idx := 1; idx <= candidateCount; idx++ {
        activeSteps := buildSliderActiveSteps(swaps, idx)
        mapping, err := buildSliderTileMapping(gridW, gridH, activeSteps)
        if err != nil {
            return nil, err
        }

        rendered, err := renderSliderCandidate(img, gridW, gridH, mapping)
        if err != nil {
            return nil, err
        }

        score := scoreRenderedSliderImage(rendered, gridW, gridH)
        candidates = append(candidates, sliderCandidate{
            Index:       idx,
            ActiveSteps: activeSteps,
            Score:       score,
        })
    }

    sort.SliceStable(candidates, func(i, j int) bool {
        if candidates[i].Score == candidates[j].Score {
            return candidates[i].Index < candidates[j].Index
        }
        return candidates[i].Score < candidates[j].Score
    })

    return candidates, nil
}

func buildSliderActiveSteps(swaps []int, candidateIndex int) []int {
    if candidateIndex <= 0 {
        return []int{}
    }
    end := candidateIndex * 2
    if end > len(swaps) {
        end = len(swaps)
    }
    return append([]int(nil), swaps[:end]...)
}

func buildSliderTileMapping(gridW, gridH int, activeSteps []int) ([]int, error) {
    tileCount := gridW * gridH
    if tileCount <= 0 {
        return nil, fmt.Errorf("invalid tile count")
    }
    if len(activeSteps)%2 != 0 {
        return nil, fmt.Errorf("invalid steps length: %d", len(activeSteps))
    }

    mapping := make([]int, tileCount)
    for i := range mapping {
        mapping[i] = i
    }
    for idx := 0; idx < len(activeSteps); idx += 2 {
        l, r := activeSteps[idx], activeSteps[idx+1]
        if l < 0 || r < 0 || l >= tileCount || r >= tileCount {
            return nil, fmt.Errorf("step out of range: %d,%d", l, r)
        }
        mapping[l], mapping[r] = mapping[r], mapping[l]
    }
    return mapping, nil
}

func renderSliderCandidate(img image.Image, gridW, gridH int, mapping []int) (*image.RGBA, error) {
    tileCount := gridW * gridH
    if len(mapping) != tileCount {
        return nil, fmt.Errorf("mapping length %d != %d", len(mapping), tileCount)
    }

    bounds := img.Bounds()
    rendered := image.NewRGBA(bounds)
    for dstIdx, srcIdx := range mapping {
        srcRect := sliderTileRect(bounds, gridW, gridH, srcIdx)
        dstRect := sliderTileRect(bounds, gridW, gridH, dstIdx)
        copyTile(rendered, dstRect, img, srcRect)
    }
    return rendered, nil
}

func scoreRenderedSliderImage(img image.Image, gridW, gridH int) int64 {
    bounds := img.Bounds()
    var score int64

    // Horizontal borders (left tile right edge vs right tile left edge)
    for row := 0; row < gridH; row++ {
        for col := 0; col < gridW-1; col++ {
            leftRect := sliderTileRect(bounds, gridW, gridH, row*gridW+col)
            rightRect := sliderTileRect(bounds, gridW, gridH, row*gridW+col+1)
            height := leftRect.Dy()
            if h := rightRect.Dy(); h < height {
                height = h
            }
            for y := 0; y < height; y++ {
                score += pixelDiff(
                    img.At(leftRect.Max.X-1, leftRect.Min.Y+y),
                    img.At(rightRect.Min.X, rightRect.Min.Y+y),
                )
            }
        }
    }

    // Vertical borders (top tile bottom edge vs bottom tile top edge)
    for row := 0; row < gridH-1; row++ {
        for col := 0; col < gridW; col++ {
            topRect := sliderTileRect(bounds, gridW, gridH, row*gridW+col)
            bottomRect := sliderTileRect(bounds, gridW, gridH, (row+1)*gridW+col)
            width := topRect.Dx()
            if w := bottomRect.Dx(); w < width {
                width = w
            }
            for x := 0; x < width; x++ {
                score += pixelDiff(
                    img.At(topRect.Min.X+x, topRect.Max.Y-1),
                    img.At(bottomRect.Min.X+x, bottomRect.Min.Y),
                )
            }
        }
    }

    return score
}

func sliderTileRect(bounds image.Rectangle, gridW, gridH, index int) image.Rectangle {
    row := index / gridW
    col := index % gridW
    x0 := bounds.Min.X + col*bounds.Dx()/gridW
    x1 := bounds.Min.X + (col+1)*bounds.Dx()/gridW
    y0 := bounds.Min.Y + row*bounds.Dy()/gridH
    y1 := bounds.Min.Y + (row+1)*bounds.Dy()/gridH
    return image.Rect(x0, y0, x1, y1)
}

func copyTile(dst *image.RGBA, dstRect image.Rectangle, src image.Image, srcRect image.Rectangle) {
    dw, dh := dstRect.Dx(), dstRect.Dy()
    sw, sh := srcRect.Dx(), srcRect.Dy()
    for y := 0; y < dh; y++ {
        sy := srcRect.Min.Y + y*sh/dh
        for x := 0; x < dw; x++ {
            sx := srcRect.Min.X + x*sw/dw
            dst.Set(dstRect.Min.X+x, dstRect.Min.Y+y, src.At(sx, sy))
        }
    }
}

func pixelDiff(a, b color.Color) int64 {
    ar, ag, ab, _ := a.RGBA()
    br, bg, bb, _ := b.RGBA()
    return absDiff(ar, br) + absDiff(ag, bg) + absDiff(ab, bb)
}

func absDiff(a, b uint32) int64 {
    if a > b {
        return int64(a - b)
    }
    return int64(b - a)
}

func generateSliderCursor(candidateIndex, candidateCount int) string {
    if candidateCount <= 0 {
        return "[]"
    }
    type point struct {
        X int   `json:"x"`
        Y int   `json:"y"`
        T int64 `json:"t"`
    }
    startX := 140
    endX := startX + 620*candidateIndex/candidateCount
    startY := 430
    startTime := time.Now().Add(-220 * time.Millisecond).UnixMilli()

    points := make([]point, 12)
    for i := 0; i < 12; i++ {
        points[i] = point{
            X: startX + (endX-startX)*i/11,
            Y: startY + (i%3 - 1),
            T: startTime + int64(i*18),
        }
    }
    data, _ := json.Marshal(points)
    return string(data)
}
