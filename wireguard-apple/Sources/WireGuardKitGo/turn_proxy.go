package main

/*
#include <stdlib.h>

typedef void(*proxy_logger_fn_t)(void *context, int level, const char *msg);

static inline void call_proxy_logger(proxy_logger_fn_t fn, void *ctx, int level, const char *msg) {
    if (fn != NULL) {
        fn(ctx, level, msg);
    }
}
*/
import "C" 

import (
    "bytes"
    "context"
    "crypto/tls"
    "encoding/json"
    "fmt"
    "io"
    "log"
    "math/rand"
    "net"
    "net/http"
	neturl "net/url"
    "sync"
    "sync/atomic"
    "time"
    "unsafe"
    "strings"

    "github.com/cbeuw/connutil"
    "github.com/google/uuid"
    "github.com/pion/dtls/v3"
    "github.com/pion/dtls/v3/pkg/crypto/selfsign"
    "github.com/pion/logging"
    "github.com/pion/turn/v5"
)

var proxyLoggerFunc C.proxy_logger_fn_t
var proxyLoggerCtx unsafe.Pointer
var proxyCancel context.CancelFunc

// Session registry — every live DTLS/TURN session registers its
// cancel func so ProxyForceReconnect() can tear them all down at once
// (e.g. when iOS wakes the device after sleep and we want fresh
// allocations before WireGuard resumes pumping packets).
var (
	sessionMu       sync.Mutex
	sessionCancels  = map[uint64]context.CancelFunc{}
	sessionIDSource uint64
)

func registerSession(cancel context.CancelFunc) func() {
	id := atomic.AddUint64(&sessionIDSource, 1)
	sessionMu.Lock()
	sessionCancels[id] = cancel
	sessionMu.Unlock()
	return func() {
		sessionMu.Lock()
		delete(sessionCancels, id)
		sessionMu.Unlock()
	}
}

//export ProxyForceReconnect
func ProxyForceReconnect() {
	sessionMu.Lock()
	cancels := make([]context.CancelFunc, 0, len(sessionCancels))
	for _, c := range sessionCancels {
		cancels = append(cancels, c)
	}
	sessionMu.Unlock()
	for _, c := range cancels {
		c()
	}
	log.Printf("ProxyForceReconnect: cancelled %d live session(s)", len(cancels))
}


//export ProxySetLogger
func ProxySetLogger(context unsafe.Pointer, loggerFn C.proxy_logger_fn_t) {
    proxyLoggerCtx = context
    proxyLoggerFunc = loggerFn
}

var proxyReady = make(chan struct{}, 1)

//export ProxyWaitReady
func ProxyWaitReady(timeoutMs C.int) C.int {
    select {
    case <-proxyReady:
        return 1
    case <-time.After(time.Duration(timeoutMs) * time.Millisecond):
        return 0
    }
}

type ProxyLogger int

func (l ProxyLogger) Write(p []byte) (n int, err error) {
    if proxyLoggerFunc == nil {
        return len(p), nil
    }

    cleanMsg := bytes.TrimRight(p, "\n")
    cMsg := C.CString(string(cleanMsg))
    defer C.free(unsafe.Pointer(cMsg))

    C.call_proxy_logger(proxyLoggerFunc, proxyLoggerCtx, C.int(l), cMsg)

    return len(p), nil
}

func init() {
    log.SetFlags(0)
    log.SetOutput(ProxyLogger(0))
}

type getCredsFunc func(context.Context, string) (string, string, string, error)

// sharedAuthClient is the package-level HTTP client used by getCreds
// for the 8-RT VK auth + identity-registration pipeline. Sharing one
// client across every getCreds invocation amortises TLS handshakes
// (~300-500 ms each) over the connection pool — previously each
// getCreds built a fresh http.Client whose defer CloseIdleConnections
// destroyed the idle pool the moment the function returned, so every
// one of 4×N=200 round trips paid full handshake cost. The captcha
// solver uses its own client (newCaptchaClient) because it needs a
// per-attempt cookie jar.
var sharedAuthClient = &http.Client{
	Timeout: 20 * time.Second,
	Transport: &http.Transport{
		// customDial layers system DNS → DoH (1.1.1.1) → hardcoded
		// VK fallback IPs. Russian mobile carriers regularly
		// NXDOMAIN login.vk.com / api.vk.com, so without this
		// fallback the very first get_anonym_token POST dies on
		// lookup before any captcha logic engages. See
		// dns_resolver.go.
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

func dtlsFunc(ctx context.Context, conn net.PacketConn, peer *net.UDPAddr) (net.Conn, error) {
    certificate, err := selfsign.GenerateSelfSigned()
    if err != nil {
        return nil, err
    }
    config := &dtls.Config{
        Certificates:          []tls.Certificate{certificate},
        InsecureSkipVerify:    true,
        ExtendedMasterSecret:  dtls.RequireExtendedMasterSecret,
        CipherSuites:          []dtls.CipherSuiteID{dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
        ConnectionIDGenerator: dtls.OnlySendCIDGenerator(),
    }
    ctx1, cancel := context.WithTimeout(ctx, 30*time.Second)
    defer cancel()
    dtlsConn, err := dtls.Client(conn, peer, config)
    if err != nil {
        return nil, err
    }

    if err := dtlsConn.HandshakeContext(ctx1); err != nil {
        return nil, err
    }
    return dtlsConn, nil
}

func oneDtlsConnection(ctx context.Context, peer *net.UDPAddr, listenConn net.PacketConn, connchan chan<- net.PacketConn, okchan chan<- struct{}, c1 chan<- error, streamID int) {
    var err error = nil
    defer func() { c1 <- err }()
    sessionStart := time.Now()

    // Data-plane byte counters for this DTLS session. The two directions:
    //   wgToDtls:   bytes read from listenConn (WG ciphertext at :9000)
    //               and written into dtlsConn (towards the TURN relay).
    //   dtlsToWg:   bytes read from dtlsConn (decrypted DTLS payload
    //               coming back from the relay) and written into
    //               listenConn (towards the WG client).
    // A periodic logger below prints both totals and 10s deltas so we
    // can tell whether user traffic is actually flowing through the
    // tunnel or whether it's just WG control-plane keepalives.
    var wgToDtls, dtlsToWg atomic.Uint64

    defer func() {
        log.Printf("DTLS session lifetime=%s wg→dtls=%dB dtls→wg=%dB exit=%v",
            time.Since(sessionStart).Round(time.Millisecond),
            wgToDtls.Load(), dtlsToWg.Load(), err)
    }()
    dtlsctx, dtlscancel := context.WithCancel(ctx)
    defer dtlscancel()
    unregister := registerSession(dtlscancel)
    defer unregister()
    var conn1, conn2 net.PacketConn
    conn1, conn2 = connutil.AsyncPacketPipe()
    go func() {
        for {
            select {
            case <-dtlsctx.Done():
                return
            case connchan <- conn2:
            }
        }
    }()
    dtlsConn, err1 := dtlsFunc(dtlsctx, conn1, peer)
    if err1 != nil {
        err = fmt.Errorf("failed to connect DTLS: %s", err1)
        return
    }
    defer func() {
        if closeErr := dtlsConn.Close(); closeErr != nil {
            err = fmt.Errorf("failed to close DTLS connection: %s", closeErr)
            return
        }
        log.Printf("Closed DTLS connection\n")
    }()
    log.Printf("Established DTLS connection!\n")

    // Stream-Aggregation preamble: if enabled, write the 17-byte
    // [sessionID, streamID] header BEFORE WireGuard packets start
    // flowing through dtlsConn. The receiver-side aggregator
    // (kiper292/vk-turn-proxy fork on the WG server's box) reads
    // this once per stream and fuses every stream sharing the same
    // session ID into a single endpoint for WG, stopping the WG
    // server from endpoint-thrashing when N parallel TURN
    // allocations deliver packets from N distinct VK relay ports.
    // Without the flag set (default), nothing is written and the
    // stream looks exactly like our pre-aggregation transport.
    if streamAggIsEnabled() {
        sid, ok := currentStreamAggSession()
        if ok {
            preamble := make([]byte, 17)
            copy(preamble[:16], sid[:])
            preamble[16] = byte(streamID)
            if _, werr := dtlsConn.Write(preamble); werr != nil {
                log.Printf("stream-agg: preamble write failed on stream %d: %s", streamID, werr)
                err = fmt.Errorf("stream-agg preamble: %s", werr)
                return
            }
            log.Printf("stream-agg: stream %d preamble sent (sessionID=%x)", streamID, sid[:4])
        }
    }

    // NOTE: do NOT signal proxyReady here. Signalling it the moment
    // the FIRST DTLS session establishes causes Swift to call
    // adapter.start() and iOS to bring up utun with the WG config's
    // AllowedIPs=0.0.0.0/0 routing. If the user has nValue>1, the
    // remaining N-1 sessions still need to fetch fresh VK creds —
    // and that means the manual-captcha WebView in the app tries to
    // load id.vk.ru AFTER utun is up, so the captcha sheet ends up
    // routed through the half-built tunnel and never loads. The
    // proxyReady signal is now sent from StartProxy once all N
    // sessions have established their DTLS+TURN allocations.
    go func() {
        for {
            select {
            case <-dtlsctx.Done():
                return
            case okchan <- struct{}{}:
            }
        }
    }()

    // Application-level keepalive over DTLS.
    //
    // WireGuard's PersistentKeepalive=25 only fires when WG itself is
    // running. When iOS throttles or briefly suspends the Network
    // Extension, WG's goroutine can miss its tick and the DTLS path
    // goes silent — the VK TURN relay then drops the channel binding
    // as 'idle' and the next real packet finds a dead path.
    //
    // We send a tiny sentinel packet over the DTLS conn every 5s so
    // the TURN ChannelData is refreshed regardless of WG state.
    //
    // Sentinel: 0xFF 0xFF 0xFF 0xFF — invalid first byte for any
    // WireGuard message type (valid: 0x01-0x04) and below WG's 32-byte
    // minimum, so server-side vk-turn-proxy can drop it cheaply before
    // forwarding to wg-quick@wg0. See companion patch in
    // truvvor/vk-turn-proxy server/.
    go func() {
        keepalive := []byte{0xFF, 0xFF, 0xFF, 0xFF}
        ticker := time.NewTicker(5 * time.Second)
        defer ticker.Stop()
        for {
            select {
            case <-dtlsctx.Done():
                return
            case <-ticker.C:
                if _, werr := dtlsConn.Write(keepalive); werr != nil {
                    log.Printf("keepalive write failed: %s", werr)
                    return
                }
            }
        }
    }()

    wg := sync.WaitGroup{}
    wg.Add(2)
    context.AfterFunc(dtlsctx, func() {
        listenConn.SetDeadline(time.Now())
        dtlsConn.SetDeadline(time.Now())
    })

    // Watchdog: if no inbound bytes from dtlsConn for >60s, force a
    // restart. With WG's PersistentKeepalive=25 we should be seeing
    // traffic every few seconds; a long silence means the TURN
    // allocation died or the network changed under us.
    var lastRxNanos atomic.Int64
    lastRxNanos.Store(time.Now().UnixNano())
    go func() {
        ticker := time.NewTicker(15 * time.Second)
        defer ticker.Stop()
        for {
            select {
            case <-dtlsctx.Done():
                return
            case now := <-ticker.C:
                last := time.Unix(0, lastRxNanos.Load())
                if now.Sub(last) > 60*time.Second {
                    log.Printf("Watchdog: no inbound DTLS traffic for %s — forcing restart", now.Sub(last).Round(time.Second))
                    dtlscancel()
                    return
                }
            }
        }
    }()

    var addr atomic.Value

    // Note: byte counters keep accumulating into wgToDtls / dtlsToWg
    // and surface in the per-session lifetime log on exit. The
    // periodic 10s dump was useful while we were proving that user
    // traffic actually flows through the tunnel, but now it's just
    // line noise.

    go func() {
        defer wg.Done()
        defer dtlscancel()
        buf := make([]byte, 1600)
        for {
            select {
            case <-dtlsctx.Done():
                return
            default:
            }
            n, addr1, err1 := listenConn.ReadFrom(buf)
            if err1 != nil {
                log.Printf("Failed: %s", err1)
                return
            }

            addr.Store(addr1)

            _, err1 = dtlsConn.Write(buf[:n])
            if err1 != nil {
                log.Printf("Failed: %s", err1)
                return
            }
            wgToDtls.Add(uint64(n))
        }
    }()

    go func() {
        defer wg.Done()
        defer dtlscancel()
        buf := make([]byte, 1600)
        for {
            select {
            case <-dtlsctx.Done():
                return
            default:
            }
            n, err1 := dtlsConn.Read(buf)
            if err1 != nil {
                log.Printf("Failed: %s", err1)
                return
            }
            lastRxNanos.Store(time.Now().UnixNano())
            addr1, ok := addr.Load().(net.Addr)
            if !ok {
                log.Printf("Failed: no listener ip")
                return
            }

            _, err1 = listenConn.WriteTo(buf[:n], addr1)
            if err1 != nil {
                log.Printf("Failed: %s", err1)
                return
            }
            dtlsToWg.Add(uint64(n))
        }
    }()

    wg.Wait()
    listenConn.SetDeadline(time.Time{})
    dtlsConn.SetDeadline(time.Time{})
}

type connectedUDPConn struct {
	*net.UDPConn
}

func (c *connectedUDPConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	return c.Write(p)
}

type turnParams struct {
	host     string
	port     string
	link     string
	udp      bool
	getCreds getCredsFunc
}

func oneTurnConnection(ctx context.Context, turnParams *turnParams, peer *net.UDPAddr, conn2 net.PacketConn, c chan<- error) {
	var err error = nil
	defer func() { c <- err }()
	sessionStart := time.Now()

	// Data-plane byte counters on the TURN side. The two directions:
	//   conn2ToRelay: bytes read from conn2 (decrypted DTLS output that
	//                 represents the WG packet) and written into
	//                 relayConn (towards the WG server via the TURN
	//                 server's relay).
	//   relayToConn2: bytes coming back from the relay and pushed into
	//                 conn2 (which DTLS will re-encrypt for the client).
	// Periodic logger below mirrors the DTLS-side counters so a missing
	// data path can be pinpointed to either the DTLS or TURN layer.
	var conn2ToRelay, relayToConn2 atomic.Uint64

	defer func() {
		log.Printf("TURN session lifetime=%s conn2→relay=%dB relay→conn2=%dB exit=%v",
			time.Since(sessionStart).Round(time.Millisecond),
			conn2ToRelay.Load(), relayToConn2.Load(), err)
	}()
	user, pass, url, err1 := turnParams.getCreds(ctx, turnParams.link)
	if err1 != nil {
		err = fmt.Errorf("failed to get TURN credentials: %s", err1)
		return
	}
	urlhost, urlport, err1 := net.SplitHostPort(url)
	if err1 != nil {
		err = fmt.Errorf("failed to parse TURN server address: %s", err1)
		return
	}
	if turnParams.host != "" {
		urlhost = turnParams.host
	}
	if turnParams.port != "" {
		urlport = turnParams.port
	}
	var turnServerAddr string
	turnServerAddr = net.JoinHostPort(urlhost, urlport)
	turnServerUdpAddr, err1 := net.ResolveUDPAddr("udp", turnServerAddr)
	if err1 != nil {
		err = fmt.Errorf("failed to resolve TURN server address: %s", err1)
		return
	}
	turnServerAddr = turnServerUdpAddr.String()
	fmt.Println(turnServerUdpAddr.IP)
	// Dial TURN Server
	var cfg *turn.ClientConfig
	var turnConn net.PacketConn
	var d net.Dialer
	ctx1, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if turnParams.udp {
		conn, err2 := net.DialUDP("udp", nil, turnServerUdpAddr) // nolint: noctx
		if err2 != nil {
			err = fmt.Errorf("failed to connect to TURN server: %s", err2)
			return
		}
		defer func() {
			if err1 = conn.Close(); err1 != nil {
				err = fmt.Errorf("failed to close TURN server connection: %s", err1)
				return
			}
		}()
		// Same buffer concern as listenConn, but on the wire side: a
		// page-load burst arrives at the device from the relay over a
		// 30–100 ms RTT path, and any backlog the kernel can't queue
		// gets dropped silently — TCP then retransmits and stalls.
		tuneUDPBuffers("turnConn", conn)
		turnConn = &connectedUDPConn{conn}
	} else {
		conn, err2 := d.DialContext(ctx1, "tcp", turnServerAddr) // nolint: noctx
		if err2 != nil {
			err = fmt.Errorf("failed to connect to TURN server: %s", err2)
			return
		}
		defer func() {
			if err1 = conn.Close(); err1 != nil {
				err = fmt.Errorf("failed to close TURN server connection: %s", err1)
				return
			}
		}()
		turnConn = turn.NewSTUNConn(conn)
	}
	var addrFamily turn.RequestedAddressFamily
	if peer.IP.To4() != nil {
		addrFamily = turn.RequestedAddressFamilyIPv4
	} else {
		addrFamily = turn.RequestedAddressFamilyIPv6
	}
	// Start a new TURN Client and wrap our net.Conn in a STUNConn
	// This allows us to simulate datagram based communication over a net.Conn
	cfg = &turn.ClientConfig{
		STUNServerAddr:         turnServerAddr,
		TURNServerAddr:         turnServerAddr,
		Conn:                   turnConn,
		Username:               user,
		Password:               pass,
		RequestedAddressFamily: addrFamily,
		LoggerFactory:          logging.NewDefaultLoggerFactory(),
	}

	client, err1 := turn.NewClient(cfg)
	if err1 != nil {
		err = fmt.Errorf("failed to create TURN client: %s", err1)
		return
	}
	defer client.Close()

	// Start listening on the conn provided.
	err1 = client.Listen()
	if err1 != nil {
		err = fmt.Errorf("failed to listen: %s", err1)
		return
	}

	// Allocate a relay socket on the TURN server. On success, it
	// will return a net.PacketConn which represents the remote
	// socket.
	relayConn, err1 := client.Allocate()
	if err1 != nil {
		err = fmt.Errorf("failed to allocate: %s", err1)
		return
	}
	defer func() {
		if err1 := relayConn.Close(); err1 != nil {
			err = fmt.Errorf("failed to close TURN allocated connection: %s", err1)
		}
	}()

	// The relayConn's local address is actually the transport
	// address assigned on the TURN server.
	log.Printf("relayed-address=%s", relayConn.LocalAddr().String())

	wg := sync.WaitGroup{}
	wg.Add(2)
	turnctx, turncancel := context.WithCancel(context.Background())
	unregister := registerSession(turncancel)
	defer unregister()
	context.AfterFunc(turnctx, func() {
		if err := relayConn.SetDeadline(time.Now()); err != nil {
			log.Printf("Failed to set relay deadline: %s", err)
		}
		if err := conn2.SetDeadline(time.Now()); err != nil {
			log.Printf("Failed to set upstream deadline: %s", err)
		}
	})
	var addr atomic.Value
	// Start read-loop on conn2 (output of DTLS)
	go func() {
		defer wg.Done()
		defer turncancel()
		buf := make([]byte, 1600)
		for {
			select {
			case <-turnctx.Done():
				return
			default:
			}
			n, addr1, err1 := conn2.ReadFrom(buf)
			if err1 != nil {
				log.Printf("Failed: %s", err1)
				return
			}

			addr.Store(addr1) // store peer

			_, err1 = relayConn.WriteTo(buf[:n], peer)
			if err1 != nil {
				log.Printf("Failed: %s", err1)
				return
			}
			conn2ToRelay.Add(uint64(n))
		}
	}()

	// Start read-loop on relayConn
	go func() {
		defer wg.Done()
		defer turncancel()
		buf := make([]byte, 1600)
		for {
			select {
			case <-turnctx.Done():
				return
			default:
			}
			n, _, err1 := relayConn.ReadFrom(buf)
			if err1 != nil {
				log.Printf("Failed: %s", err1)
				return
			}
			addr1, ok := addr.Load().(net.Addr)
			if !ok {
				log.Printf("Failed: no listener ip")
				return
			}

			_, err1 = conn2.WriteTo(buf[:n], addr1)
			if err1 != nil {
				log.Printf("Failed: %s", err1)
				return
			}
			relayToConn2.Add(uint64(n))
		}
	}()

	// Byte counters are folded into the per-session lifetime log on
	// exit; the periodic 10s dump that proved data was flowing
	// during the throughput investigation is no longer interesting.

	wg.Wait()
	if err := relayConn.SetDeadline(time.Time{}); err != nil {
		log.Printf("Failed to clear relay deadline: %s", err)
	}
	if err := conn2.SetDeadline(time.Time{}); err != nil {
		log.Printf("Failed to clear upstream deadline: %s", err)
	}
}

// reconnectBackoff produces a capped exponential backoff with jitter.
// Caller uses it like:
//   wait := reconnectBackoff(prev, success)
//   time.Sleep(wait)
// On success it returns 0 (caller resets state and continues immediately).
func reconnectBackoff(prev time.Duration, success bool) time.Duration {
	if success {
		return 0
	}
	if prev <= 0 {
		prev = 500 * time.Millisecond
	} else {
		prev *= 2
	}
	const maxBackoff = 30 * time.Second
	if prev > maxBackoff {
		prev = maxBackoff
	}
	// Add jitter +/- 25% so reconnects don't synchronise across N parallel streams.
	jitter := time.Duration(rand.Int63n(int64(prev / 2))) - prev/4
	return prev + jitter
}

func oneDtlsConnectionLoop(ctx context.Context, peer *net.UDPAddr, listenConnChan <-chan net.PacketConn, connchan chan<- net.PacketConn, okchan chan<- struct{}, streamID int) {
	var backoff time.Duration
	for {
		select {
		case <-ctx.Done():
			return
		case listenConn := <-listenConnChan:
			c := make(chan error)
			go oneDtlsConnection(ctx, peer, listenConn, connchan, okchan, c, streamID)
			err := <-c
			if err != nil {
				log.Printf("%s", err)
				backoff = reconnectBackoff(backoff, false)
				if backoff > 0 {
					log.Printf("DTLS reconnect in %s", backoff.Round(time.Millisecond))
					select {
					case <-ctx.Done():
						return
					case <-time.After(backoff):
					}
				}
			} else {
				backoff = reconnectBackoff(backoff, true)
			}
		}
	}
}

func oneTurnConnectionLoop(ctx context.Context, turnParams *turnParams, peer *net.UDPAddr, connchan <-chan net.PacketConn, t <-chan time.Time) {
	var backoff time.Duration
	for {
		select {
		case <-ctx.Done():
			return
		case conn2 := <-connchan:
			select {
			case <-t:
				c := make(chan error)
				go oneTurnConnection(ctx, turnParams, peer, conn2, c)
				err := <-c
				if err != nil {
					log.Printf("%s", err)
					backoff = reconnectBackoff(backoff, false)
					if backoff > 0 {
						log.Printf("TURN reconnect in %s", backoff.Round(time.Millisecond))
						select {
						case <-ctx.Done():
							return
						case <-time.After(backoff):
						}
					}
				} else {
					backoff = reconnectBackoff(backoff, true)
				}
			default:
			}
		}
	}
}

type turnCred struct {
	user, pass, addr string
	acquiredAt       time.Time
}

// credMaxAge is how long a TURN cred stays usable in the pool. VK
// rotates TURN allocations roughly every minute, after which Allocate
// returns 437 (allocation mismatch). Recycling a 90 s-old cred during
// a reconnect storm just kicks off a brand-new dead TURN session —
// pion fails fast, the loop reconnects, getCreds returns the same
// stale cred, and round we go. Capping at 45 s gives a comfortable
// margin under VK's actual rotation window while still letting the
// burst-recycle path (fresh creds added in the last ~5 s) work.
const credMaxAge = 45 * time.Second

// Max concurrent captcha solves against VK. Fully-parallel solves at
// N=30 trigger VK's anti-bot rate-limit (`ERROR_LIMIT` on
// captcha.isNotRobot, `status: ERROR` on slider getContent) and the
// per-IP TURN allocation cap (error 486). Five concurrent solves keeps
// the captcha pipeline well under VK's threshold while still scaling
// throughput roughly 5× over fully-serial (which was the d917a0e
// motivation in the first place).
const maxConcurrentCaptchaSolves = 5

func poolCreds(f getCredsFunc, poolSize int) getCredsFunc {
	var mu sync.Mutex
	var pool []turnCred
	var cTime time.Time
	var idx int

	// Bounded-concurrency gate for captcha solves. Buffered channel
	// acts as a semaphore: at most cap(solveSlot) goroutines hold a
	// slot at a time, the rest block on send until a slot is released.
	solveSlot := make(chan struct{}, maxConcurrentCaptchaSolves)

	return func(ctx context.Context, link string) (string, string, string, error) {
		mu.Lock()

		if !cTime.IsZero() && time.Since(cTime) > 10*time.Minute {
			pool = nil
			cTime = time.Time{}
		}

		// Prune creds older than credMaxAge. Without this both the
		// cache-hit fast path and the saturation short-circuit would
		// keep handing out dead identities to oneTurnConnection,
		// which then 437s on Allocate, dies, reconnects, and burns
		// another solve attempt. The 45 s budget lines up with VK's
		// TURN rotation window so any cred in the pool was either
		// just acquired or is in its useful lifetime.
		if len(pool) > 0 {
			fresh := pool[:0]
			for _, c := range pool {
				if time.Since(c.acquiredAt) <= credMaxAge {
					fresh = append(fresh, c)
				}
			}
			pool = fresh
		}

		// Cache-hit fast path: pool already at capacity, hand out a
		// rotating cached cred and bail. This path never touches the
		// solve semaphore — only cold solves are throttled.
		if len(pool) >= poolSize {
			c := pool[idx%len(pool)]
			idx++
			cTime = time.Now()
			mu.Unlock()
			return c.user, c.pass, c.addr, nil
		}

		// Saturation short-circuit. Reconnect loops (oneDtls/oneTurn
		// ConnectionLoop) call getCreds on every retry, and while the
		// pool is below poolSize each call would otherwise spin up
		// another solveVkCaptcha → ERROR_LIMIT → recycle cycle. With
		// N=50 sessions all hitting VK's rate-limit simultaneously
		// this snowballs into 100+ doomed captcha attempts per minute
		// and a fresh TURN allocation per attempt — each of which VK
		// closes within ~50 s. Detect the burning state and short-
		// circuit straight to a recycled cred. The cooldown in
		// directSaturated/tunnelSaturated will auto-clear the streak
		// after captchaCooldown so this is not permanent — once VK's
		// rate-limit window expires, real solves resume.
		if len(pool) > 0 {
			egressIsTunnel := captchaTunnelEgress.Load()
			// "currentSat" is the egress this attempt would use by
			// default. "otherSat" is the egress solveVkCaptcha can
			// escape to via the force-direct path (cellularDial).
			// That escape only exists for tunnel → direct, not the
			// other way around, so when we're already on direct the
			// short-circuit just looks at directSaturated.
			currentSat := directSaturated()
			otherSat := tunnelSaturated()
			if egressIsTunnel {
				currentSat, otherSat = tunnelSaturated(), directSaturated()
			}
			if currentSat && (otherSat || !egressIsTunnel) {
				c := pool[idx%len(pool)]
				idx++
				cTime = time.Now()
				mu.Unlock()
				return c.user, c.pass, c.addr, nil
			}
		}

		// Cache-miss slow path: release the mutex, jitter, take a
		// solve slot, then call f(ctx, link). The mutex is dropped
		// first so we don't serialise on it while waiting for a slot.
		// The jitter runs BEFORE slot acquisition so it overlaps the
		// queue wait instead of holding a slot — previously a 5-slot
		// pipeline burned 0.75-3 s per slot on jitter alone, halving
		// effective throughput. Now the slot only covers the actual
		// PoW + HTTP work. ctx-aware at every step so a Disconnect
		// during the wait bails fast.
		mu.Unlock()

		// 1.5-2.5 s pre-slot wait: combined anti-bot pacing (used to
		// live inside solveVkCaptcha as a fixed 1.5-2.5 s sleep while
		// the slot was held) and entry desync (used to be a 0-750 ms
		// post-slot jitter). Both purposes preserved, the slot is
		// freed earlier.
		select {
		case <-time.After(time.Duration(1500+rand.Intn(1000)) * time.Millisecond):
		case <-ctx.Done():
			return "", "", "", ctx.Err()
		}

		select {
		case solveSlot <- struct{}{}:
		case <-ctx.Done():
			return "", "", "", ctx.Err()
		}
		u, p, a, err := f(ctx, link)
		<-solveSlot

		mu.Lock()
		defer mu.Unlock()

		if err == nil {
			pool = append(pool, turnCred{u, p, a, time.Now()})
			cTime = time.Now()
			log.Printf("Successfully registered User Identity %d/%d", len(pool), poolSize)
			idx++
			return u, p, a, nil
		}

		log.Printf("Failed to get unique TURN identity: %v", err)
		if len(pool) > 0 {
			log.Printf("Falling back to reusing a previous identity...")
			c := pool[idx%len(pool)]
			idx++
			cTime = time.Now()
			return c.user, c.pass, c.addr, nil
		}
		return "", "", "", err
	}
}

//export StartProxy
func StartProxy(cLink *C.char, cPeerAddr *C.char, cLocalAddr *C.char, cN C.int, cUDP C.int) {
    select { case <-proxyReady: default: }

    link := C.GoString(cLink)
    peerAddrStr := C.GoString(cPeerAddr)
    localAddrStr := C.GoString(cLocalAddr)
    
    // host/port: empty by default so we use what VK API returned in
    // turn_server.urls[0]. Override only if you know the TURN endpoint
    // shouldn't track what VK responds with (e.g. pinning a stable IP).
    host := ""
    port := ""
    n := int(cN)
    // udp transport to TURN. true=plain UDP (faster, fragile under loss),
    // false=TCP STUNConn (survives short cellular blips at the cost of HoL).
    udp := cUDP != 0
    log.Printf("StartProxy: peer=%s n=%d udp=%v", peerAddrStr, n, udp)

    ctx, cancel := context.WithCancel(context.Background())
    proxyCancel = cancel
    defer cancel()

    // Periodic Go runtime memstats. Pair with the Swift-side
    // os_proc_available_memory logger to understand when the
    // extension is approaching iOS's kill threshold.
    startMemstatsLogger(ctx)

    peer, err := net.ResolveUDPAddr("udp", peerAddrStr)
    if err != nil {
        log.Printf("Resolve UDP error: %v", err)
        return
    }

    parts := strings.Split(link, "join/")
    link = parts[len(parts)-1]

    if idx := strings.IndexAny(link, "/?#"); idx != -1 {
        link = link[:idx]
    }

	params := &turnParams{
		host:     host,
		port:     port,
		link:     link,
		udp:      udp,
		getCreds: poolCreds(getCredsRouted, n),
	}

    listenConnChan := make(chan net.PacketConn)
	listenConn, err := net.ListenPacket("udp", localAddrStr)
	if err != nil {
		log.Printf("Failed to listen: %s", err)
		return
	}
	// Bump the WG↔proxy UDP socket buffers. Default iOS UDP recv buffer
	// is ~196 KB; a single page load can burst 50–100 1.2 KB packets at
	// once, overflowing the kernel queue before our read goroutine
	// drains it. The kernel may cap the request below 4 MB depending on
	// kern.ipc.maxsockbuf — log what we actually got.
	tuneUDPBuffers("listenConn", listenConn)

	context.AfterFunc(ctx, func() {
		if closeErr := listenConn.Close(); closeErr != nil {
			log.Printf("Failed to close local connection: %s", closeErr)
		}
	})

	// Per-session fan-out of the shared listenConn. Without this, all
	// N oneDtlsConnection goroutines call ReadFrom on the same UDP
	// socket, the kernel wakes only one of them, and the other N-1
	// sessions sit idle — silently defeating nValue>1. The dispatcher
	// reads once and round-robins each WG packet to one of N
	// fanoutPacketConn channels; each session reads from its own.
	// Writes still go straight back to the real listenConn so replies
	// from any session reach the WG client.
	fanouts := make([]*fanoutPacketConn, n)
	for i := range fanouts {
		fanouts[i] = newFanoutPacketConn(i, listenConn)
	}
	startFanoutDispatcher(ctx, listenConn, fanouts)
	log.Printf("fanout: dispatcher up with %d virtual conn(s)", n)

	// Each oneDtlsConnectionLoop wants a chan that endlessly redelivers
	// its private listen-side conn. Spawn one such chan per fanout.
	makeFanoutChan := func(f net.PacketConn) chan net.PacketConn {
		ch := make(chan net.PacketConn)
		go func() {
			for {
				select {
				case <-ctx.Done():
					return
				case ch <- f:
				}
			}
		}()
		return ch
	}

	// listenConnChan kept for the type signature only — the original
	// goroutine that fed the shared listenConn is replaced by the
	// per-fanout chans below.
	_ = listenConnChan

    wg1 := sync.WaitGroup{}
	t := time.Tick(200 * time.Millisecond)

	// Re-roll the Stream-Aggregation session ID once per StartProxy.
	// Each of the N DTLS sessions below will then prepend the same
	// session ID + its own stream index after handshake, letting the
	// receiver-side aggregator fuse them. No-op when the feature is
	// off (default).
	if streamAggIsEnabled() {
		sid := freshStreamAggSession()
		log.Printf("stream-agg: enabled, sessionID=%x (N=%d)", sid[:4], n)
	}

	// Phased bring-up driven by adaptive captcha-egress budget.
	//
	// VK rate-limits captcha.isNotRobot per source IP. We have two
	// budgets available:
	//
	//   "direct" — the user's mobile IP. Used until ERROR_LIMIT lands
	//              on a captcha solve.
	//   "tunnel" — the WG server's egress IP. Once WG handshake
	//              completes, this extension's outbound HTTP routes
	//              through utun automatically (includeAllNetworks=true).
	//
	// Sequence:
	//
	//   Phase A (direct):
	//     Spawn sessions one at a time with a small stagger, keeping
	//     them all on the user's mobile IP. Stop as soon as either
	//       (a) we've spawned N, or
	//       (b) a captcha solve returns ERROR_LIMIT (captchaDirectSat
	//           trips).
	//     This drains the direct egress's rate-limit budget — exactly
	//     what the user asked for ("столько тоннелей сколько можно
	//     поднять со своего родного айпи").
	//
	//   Bridge:
	//     Wait for any one of the spawned sessions to reach DTLS
	//     ready, fire proxyReady so Swift starts the WG adapter,
	//     then wait ~2 s for WG handshake to complete through that
	//     session. Flip captchaTunnelEgress so subsequent solves
	//     are attributed to the tunnel pool.
	//
	//   Phase B (tunnel) — only if Phase A stopped early on direct
	//     saturation AND we still have sessions to spawn:
	//     Continue spawning sessions, also one at a time. Their
	//     captcha HTTP now goes through utun → WG server → api.vk.ru,
	//     so VK sees the WG server's egress IP — a fresh per-IP
	//     rate-limit budget. Stop when N reached or
	//     captchaTunnelSat trips.
	//
	// Manual-captcha mode keeps the single-phase "all N before WG"
	// barrier: each WebView is presented one-at-a-time anyway, and
	// the UI flow assumes the captcha sheet can still reach id.vk.ru
	// outside the tunnel (includeAllNetworks=false in that mode).
	resetCaptchaStats()
	captchaSessionsTarget.Store(int64(n))

	sessionReady := make(chan int, n)
	spawnSession := func(i int) {
		fanoutChan := makeFanoutChan(fanouts[i])
		cChan := make(chan net.PacketConn)
		sessionOk := make(chan struct{})

		wg1.Go(func() {
			oneDtlsConnectionLoop(ctx, peer, fanoutChan, cChan, sessionOk, i)
		})
		wg1.Go(func() {
			oneTurnConnectionLoop(ctx, params, peer, cChan, t)
		})
		go func() {
			select {
			case <-sessionOk:
				// Make this lane visible to the fanout dispatcher.
				// Until now the dispatcher was skipping it because
				// nothing was draining its incoming channel.
				fanouts[i].active.Store(true)
				captchaSessionsReady.Add(1)
				sessionReady <- i
			case <-ctx.Done():
			}
		}()
	}

	if manualCaptchaForcedMode() {
		// Manual mode: spawn all N upfront and wait for every one
		// before bringing up WG (legacy behaviour the WebView UI
		// flow depends on).
		for i := 0; i < n; i++ {
			spawnSession(i)
		}
		for k := 0; k < n; k++ {
			select {
			case idx := <-sessionReady:
				log.Printf("StartProxy: session %d ready (%d/%d, manual)", idx+1, k+1, n)
			case <-ctx.Done():
				wg1.Wait()
				return
			}
		}
		select {
		case proxyReady <- struct{}{}:
		default:
		}
		log.Printf("Proxy started on %s with %d parallel TURN session(s) (manual mode)", localAddrStr, n)
		wg1.Wait()
		return
	}

	// Start the sessionReady drain + proxyReady-signaller BEFORE the
	// Phase A spawn loop. iOS' startTunnel completion handler has to
	// fire within ~15-20 s or the OS gives up and tears the tunnel
	// down. Phase A's 400 ms stagger × N=50 = 20 s of spawning, so if
	// we wait for "phase A done" before consuming the first
	// sessionReady, iOS pulls the plug before WG ever starts. With
	// this goroutine reading concurrently, the very first DTLS-ready
	// session (≈5 s in) triggers proxyReady immediately and Swift's
	// adapter.start fires without waiting on the rest of the fleet.
	go func() {
		firstSignalled := false
		for {
			select {
			case idx := <-sessionReady:
				log.Printf("StartProxy: session %d ready", idx+1)
				if !firstSignalled {
					firstSignalled = true
					log.Printf("StartProxy: first session ready, signaling proxyReady")
					select {
					case proxyReady <- struct{}{}:
					default:
					}
					// Flip tunnel egress 2 s after the first DTLS
					// session is up — WG handshake completes in that
					// window and from then on the extension's HTTP
					// auto-routes through utun.
					go func() {
						select {
						case <-time.After(2 * time.Second):
							captchaTunnelEgress.Store(true)
							log.Printf("StartProxy: tunnel egress engaged")
						case <-ctx.Done():
						}
					}()
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	// Phase A: spawn direct sessions until N reached or direct egress
	// hits ERROR_LIMIT. The 1.5-2.5 s pre-slot jitter inside poolCreds
	// (see F3) now does the anti-bot pacing that the stagger used to
	// do; the stagger only exists to give the saturation check inside
	// this loop enough granularity to fire BEFORE the whole fleet has
	// kicked off solveVkCaptcha. 100 ms × 50 = 5 s for all N to enter
	// the slot queue, vs the old 20 s — saves ~15 s of bring-up time
	// when direct doesn't saturate, while still letting Phase A→B
	// transition fire within 100 ms of an ERROR_LIMIT landing.
	phaseAStagger := 100 * time.Millisecond
	phaseACount := 0
	for phaseACount < n {
		if directSaturated() {
			log.Printf("StartProxy: direct egress saturated after %d sessions, transitioning to tunnel egress",
				phaseACount)
			break
		}
		spawnSession(phaseACount)
		phaseACount++
		select {
		case <-time.After(phaseAStagger):
		case <-ctx.Done():
			wg1.Wait()
			return
		}
	}
	log.Printf("StartProxy: phase A done, spawned=%d/%d direct, saturated=%v",
		phaseACount, n, directSaturated())

	if phaseACount >= n {
		// Phase A spawned all N — no Phase B needed. proxyReady was
		// already fired by the drain goroutine above; nothing else
		// to do here.
		log.Printf("Proxy started on %s with %d parallel TURN session(s) (all direct)", localAddrStr, n)
		wg1.Wait()
		return
	}

	// Phase B: still need sessions, direct saturated. Spawn the rest
	// through the tunnel egress. captchaTunnelEgress has either
	// already flipped (if first session was ready before saturation)
	// or will flip via the drain goroutine after the next ready.
	wg1.Go(func() {
		log.Printf("StartProxy: spawning phase B (target=%d, already=%d)", n, phaseACount)

		// Per-session stagger 200 ms — twice Phase A because the WG
		// server's egress is the only IP for everyone else's traffic
		// too, so saturating it has wider blast radius. The 1.5-2.5 s
		// pre-slot jitter (F3) handles anti-bot pacing; the stagger
		// only governs how quickly the loop notices tunnel
		// saturation. 200 ms × 40 ≈ 8 s phase B warm-up vs old 32 s.
		phaseBStagger := 200 * time.Millisecond
		for i := phaseACount; i < n; i++ {
			if ctx.Err() != nil {
				return
			}
			if tunnelSaturated() {
				log.Printf("StartProxy: tunnel egress also rate-limited; stopping at %d/%d sessions",
					i, n)
				return
			}
			spawnSession(i)
			select {
			case <-time.After(phaseBStagger):
			case <-ctx.Done():
				return
			}
		}
	})

    log.Printf("Proxy started on %s with %d parallel TURN session(s) requested (phased)", localAddrStr, n)
    wg1.Wait()
}

//export StopProxy
func StopProxy() {
    if proxyCancel != nil {
        proxyCancel()
        proxyCancel = nil
        log.Println("Proxy gracefully stopped")
    }
}
