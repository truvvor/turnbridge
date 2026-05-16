// turn_min.go — hand-rolled minimal TURN client (RFC 5766).
//
// Replaces github.com/pion/turn/v5 in the data path. pion's client
// maintains rich permission/channel state, multi-peer dispatch, RFC
// 6062 TCP-allocation support, and a handful of background goroutines
// per Client. For our use-case — one peer per allocation (the WG
// client), UDP-or-STUN-over-TCP transport, one bound channel for that
// one peer — that's a lot of dead weight to carry per session and the
// per-session struct + maps were a meaningful slice of the ~2 MB/
// session steady-state we measured in the memory audit.
//
// What's here:
//   - Allocate with long-term auth (two-pass nonce challenge per
//     RFC 5389 §10.2 + RFC 5766 §6.2)
//   - ChannelBind for the single peer
//   - Refresh on a half-lifetime ticker, cancel via context
//   - ChannelData frame encode/decode in the hot path
//   - net.PacketConn surface matching pion's allocation.Conn
//
// What's NOT here:
//   - CreatePermission — superseded by ChannelBind which also installs
//     the permission (RFC 5766 §11.2)
//   - Send/Data indications — we always use the bound channel
//   - Multi-peer allocations (we have exactly one peer)
//   - Fingerprint / short-term auth
//   - TURN-TCP (RFC 6062)

package main

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pion/stun/v3"
)

// TURN attribute types beyond what pion/stun exports as named
// constants. Values from RFC 5766 §14.
const (
	attrChannelNumber          stun.AttrType = 0x000C
	attrLifetime               stun.AttrType = 0x000D
	attrXORPeerAddress         stun.AttrType = 0x0012
	attrXORRelayedAddress      stun.AttrType = 0x0016
	attrRequestedAddressFamily stun.AttrType = 0x0017
	attrRequestedTransport     stun.AttrType = 0x0019
)

// Channel numbers must fall in 0x4000-0x4FFE (RFC 5766 §11). We only
// bind one channel per allocation, so a fixed value is fine.
const fixedChannelNumber uint16 = 0x4000

// RFC 5766 §6.2 — lifetime SHOULD default to 600s. We ask for that
// and refresh at half-life.
const allocLifetimeSec uint32 = 600

// RFC 5766 §14.7 — REQUESTED-TRANSPORT for UDP relay.
const transportUDP byte = 17

// Address-family attribute values (RFC 6156 §4.1.1).
const (
	addrFamilyIPv4 byte = 0x01
	addrFamilyIPv6 byte = 0x02
)

// txRetryDelays is the RFC 5389 §7.2.1 retransmit schedule, slightly
// shortened: 500ms, 1s, 2s, 4s. We don't need the full 7-retry
// 39.5s ladder because failed allocations get retried at a higher
// layer (oneTurnConnectionLoop) and we'd rather fail fast and let
// the session recycle on a fresh socket.
var txRetryDelays = []time.Duration{
	500 * time.Millisecond,
	1 * time.Second,
	2 * time.Second,
	4 * time.Second,
}

// minimalTURNAlloc represents a single live TURN allocation. It
// satisfies net.PacketConn so it can drop into the same slot as
// pion's relayConn in oneTurnConnection.
type minimalTURNAlloc struct {
	conn   net.PacketConn // transport (connectedUDPConn or *turn.STUNConn equivalent)
	server net.Addr       // destination for WriteTo on UDP; ignored by STUNConn

	user, pass string
	realm      []byte
	nonce      atomic.Value // []byte; updated whenever a 438 lands

	peer            *net.UDPAddr
	relayedAddr     *net.UDPAddr
	currentLifetime time.Duration

	// Transactions are serialised: only Allocate / ChannelBind /
	// Refresh run, and only one at a time (Refresh waits for the
	// previous to finish before firing). One pending slot is enough.
	pendingMu sync.Mutex
	pendingTx [stun.TransactionIDSize]byte
	pendingCh chan *stun.Message

	// Data path. The read loop demuxes inbound frames: ChannelData
	// goes onto inboundData; everything else (STUN responses /
	// indications) is steered to pendingCh by transaction-ID match.
	inboundData chan []byte

	closed    chan struct{}
	closeOnce sync.Once

	// SetReadDeadline: past-time wakeup mirrors the idiom in
	// fanoutPacketConn / pipeConn — set deadline = now to interrupt
	// the in-flight ReadFrom with os.ErrDeadlineExceeded.
	deadlineMu sync.Mutex
	wakeup     chan struct{}
	timer      *time.Timer
}

// LocalAddr returns the relayed transport address — the address peers
// dial to reach us through the TURN server. oneTurnConnection only
// reads this for the "relayed-address=" log line.
func (a *minimalTURNAlloc) LocalAddr() net.Addr {
	return a.relayedAddr
}

// ReadFrom blocks until the next data frame arrives from the bound
// peer. The returned addr is always the bound peer — we never accept
// data from any other source because we never CreatePermission'd /
// ChannelBind'd any other peer.
func (a *minimalTURNAlloc) ReadFrom(buf []byte) (int, net.Addr, error) {
	select {
	case data, ok := <-a.inboundData:
		if !ok {
			return 0, nil, net.ErrClosed
		}
		n := copy(buf, data)
		return n, a.peer, nil
	case <-a.closed:
		return 0, nil, net.ErrClosed
	case <-a.wakeup:
		return 0, nil, os.ErrDeadlineExceeded
	}
}

// WriteTo wraps buf in a ChannelData frame and sends it through the
// transport. The addr argument is ignored — we always send to the
// bound peer via the bound channel. This matches the contract that
// oneTurnConnection relies on (it calls WriteTo with the same peer
// every time).
func (a *minimalTURNAlloc) WriteTo(buf []byte, _ net.Addr) (int, error) {
	select {
	case <-a.closed:
		return 0, net.ErrClosed
	default:
	}

	frame := encodeChannelData(fixedChannelNumber, buf)
	_, err := a.conn.WriteTo(frame, a.server)
	if err != nil {
		return 0, err
	}
	return len(buf), nil
}

func (a *minimalTURNAlloc) Close() error {
	a.closeOnce.Do(func() {
		// Best-effort delete on the server side: Refresh with
		// lifetime=0 explicitly tears down the allocation per
		// RFC 5766 §7. If it fails (network gone, server already
		// expired us) it doesn't matter — the allocation would
		// time out within ~10 min anyway.
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		_ = a.refresh(ctx, 0)
		cancel()
		close(a.closed)
	})
	return nil
}

func (a *minimalTURNAlloc) SetDeadline(t time.Time) error {
	return a.SetReadDeadline(t)
}

func (a *minimalTURNAlloc) SetReadDeadline(t time.Time) error {
	a.deadlineMu.Lock()
	defer a.deadlineMu.Unlock()

	if a.timer != nil {
		a.timer.Stop()
		a.timer = nil
	}
	if t.IsZero() {
		return nil
	}
	d := time.Until(t)
	if d <= 0 {
		select {
		case a.wakeup <- struct{}{}:
		default:
		}
		return nil
	}
	a.timer = time.AfterFunc(d, func() {
		select {
		case a.wakeup <- struct{}{}:
		default:
		}
	})
	return nil
}

// SetWriteDeadline is a no-op. Our WriteTo doesn't block (channel-data
// goes straight to the underlying conn, which is either UDP — drops on
// overflow — or TCP via STUNConn, where the kernel buffers).
func (a *minimalTURNAlloc) SetWriteDeadline(t time.Time) error {
	return nil
}

// minimalTURNAllocate dials a fresh TURN allocation on conn, binds a
// channel for peer, and starts the read+refresh goroutines. The
// caller's ctx is used only for the allocate handshake; subsequent
// lifetime is bounded by Close.
func minimalTURNAllocate(
	ctx context.Context,
	conn net.PacketConn,
	server net.Addr,
	user, pass string,
	peer *net.UDPAddr,
) (*minimalTURNAlloc, error) {
	alloc := &minimalTURNAlloc{
		conn:        conn,
		server:      server,
		user:        user,
		pass:        pass,
		peer:        peer,
		inboundData: make(chan []byte, 64),
		closed:      make(chan struct{}),
		wakeup:      make(chan struct{}, 1),
	}
	alloc.nonce.Store([]byte(nil))

	// Spawn the read demultiplexer before any handshake so allocate
	// responses can reach pendingCh.
	go alloc.readLoop()

	// On error, leave conn lifecycle to the caller — they hold the
	// defer that closes it. Just signal our internal closed channel so
	// the just-spawned readLoop unwinds.
	if err := alloc.allocate(ctx); err != nil {
		alloc.closeOnce.Do(func() { close(alloc.closed) })
		return nil, fmt.Errorf("allocate: %w", err)
	}
	if err := alloc.channelBind(ctx); err != nil {
		alloc.closeOnce.Do(func() { close(alloc.closed) })
		return nil, fmt.Errorf("channelBind: %w", err)
	}
	go alloc.refreshLoop()
	return alloc, nil
}

// allocate runs the full RFC 5389 §10.2 long-term-auth two-pass
// handshake: first request is anonymous and expected to get back a
// 401 with REALM and NONCE; second pass adds USERNAME/REALM/NONCE/
// MESSAGE-INTEGRITY and gets back XOR-RELAYED-ADDRESS.
func (a *minimalTURNAlloc) allocate(ctx context.Context) error {
	family := addrFamilyIPv4
	if a.peer.IP.To4() == nil {
		family = addrFamilyIPv6
	}

	build := func(withAuth bool) (*stun.Message, error) {
		m := stun.New()
		m.SetType(stun.NewType(stun.MethodAllocate, stun.ClassRequest))
		if err := m.NewTransactionID(); err != nil {
			return nil, err
		}
		// WriteHeader stamps the STUN magic cookie 0x2112A442 into
		// m.Raw[4:8]. Without this, MessageIntegrity.AddTo (called
		// later by addAuth) computes the HMAC over m.Raw with
		// cookie=0 — but the wire bytes go out with the real cookie
		// (Encode writes it), so the server's recomputed HMAC over
		// the received bytes doesn't match → 401. SetType wrote
		// [0:2] and NewTransactionID wrote [8:20], but nothing else
		// touches [4:8] until Encode, which runs too late. This was
		// the 1.3.9 ship-blocker.
		m.WriteHeader()
		m.Add(attrRequestedTransport, []byte{transportUDP, 0, 0, 0})
		m.Add(attrRequestedAddressFamily, []byte{family, 0, 0, 0})
		if withAuth {
			if err := a.addAuth(m); err != nil {
				return nil, err
			}
		}
		m.Encode()
		return m, nil
	}

	// First attempt — anonymous. RFC 5389 spells out that the server
	// MUST 401 this with REALM/NONCE for long-term-credential mode.
	first, err := build(false)
	if err != nil {
		return err
	}
	resp, err := a.do(ctx, first)
	if err != nil {
		return err
	}
	if resp.Type.Class == stun.ClassSuccessResponse {
		// Server happens to accept unauthenticated allocate (rare).
		return a.parseAllocSuccess(resp)
	}
	if err := a.learnAuth(resp); err != nil {
		return fmt.Errorf("learn auth: %w", err)
	}

	// Second attempt — authenticated.
	second, err := build(true)
	if err != nil {
		return err
	}
	resp, err = a.do(ctx, second)
	if err != nil {
		return err
	}
	if resp.Type.Class != stun.ClassSuccessResponse {
		// On 438 Stale Nonce, server may have rotated the nonce
		// between the 401 and our second request. Pick up the new
		// nonce and retry once.
		if isStaleNonce(resp) {
			if err := a.learnAuth(resp); err != nil {
				return err
			}
			retry, err := build(true)
			if err != nil {
				return err
			}
			resp, err = a.do(ctx, retry)
			if err != nil {
				return err
			}
			if resp.Type.Class != stun.ClassSuccessResponse {
				return errorFrom(resp)
			}
		} else {
			return errorFrom(resp)
		}
	}
	return a.parseAllocSuccess(resp)
}

func (a *minimalTURNAlloc) parseAllocSuccess(m *stun.Message) error {
	var relayed stun.XORMappedAddress
	if err := relayed.GetFromAs(m, attrXORRelayedAddress); err != nil {
		return fmt.Errorf("XOR-RELAYED-ADDRESS: %w", err)
	}
	a.relayedAddr = &net.UDPAddr{IP: relayed.IP, Port: relayed.Port}

	lifetime := allocLifetimeSec
	if raw, err := m.Get(attrLifetime); err == nil && len(raw) == 4 {
		lifetime = binary.BigEndian.Uint32(raw)
	}
	a.currentLifetime = time.Duration(lifetime) * time.Second
	return nil
}

// channelBind binds fixedChannelNumber to a.peer. Per RFC 5766 §11.2,
// this also installs a permission for the peer's IP, so we don't need
// a separate CreatePermission.
func (a *minimalTURNAlloc) channelBind(ctx context.Context) error {
	build := func() (*stun.Message, error) {
		m := stun.New()
		m.SetType(stun.NewType(stun.MethodChannelBind, stun.ClassRequest))
		if err := m.NewTransactionID(); err != nil {
			return nil, err
		}
		m.WriteHeader() // stamp magic cookie — see allocate()
		var chBuf [4]byte
		binary.BigEndian.PutUint16(chBuf[0:2], fixedChannelNumber)
		m.Add(attrChannelNumber, chBuf[:])
		xor := stun.XORMappedAddress{IP: a.peer.IP, Port: a.peer.Port}
		if err := xor.AddToAs(m, attrXORPeerAddress); err != nil {
			return nil, err
		}
		if err := a.addAuth(m); err != nil {
			return nil, err
		}
		m.Encode()
		return m, nil
	}
	for attempt := 0; attempt < 2; attempt++ {
		req, err := build()
		if err != nil {
			return err
		}
		resp, err := a.do(ctx, req)
		if err != nil {
			return err
		}
		if resp.Type.Class == stun.ClassSuccessResponse {
			return nil
		}
		if isStaleNonce(resp) && attempt == 0 {
			if err := a.learnAuth(resp); err != nil {
				return err
			}
			continue
		}
		return errorFrom(resp)
	}
	return errors.New("channel bind: out of retries")
}

// refresh sends a Refresh request with the given lifetime (or 0 to
// destroy the allocation). On 438 Stale Nonce it re-learns and
// retries once.
func (a *minimalTURNAlloc) refresh(ctx context.Context, lifetimeSec uint32) error {
	build := func() (*stun.Message, error) {
		m := stun.New()
		m.SetType(stun.NewType(stun.MethodRefresh, stun.ClassRequest))
		if err := m.NewTransactionID(); err != nil {
			return nil, err
		}
		m.WriteHeader() // stamp magic cookie — see allocate()
		var lifeBuf [4]byte
		binary.BigEndian.PutUint32(lifeBuf[:], lifetimeSec)
		m.Add(attrLifetime, lifeBuf[:])
		if err := a.addAuth(m); err != nil {
			return nil, err
		}
		m.Encode()
		return m, nil
	}
	for attempt := 0; attempt < 2; attempt++ {
		req, err := build()
		if err != nil {
			return err
		}
		resp, err := a.do(ctx, req)
		if err != nil {
			return err
		}
		if resp.Type.Class == stun.ClassSuccessResponse {
			return nil
		}
		if isStaleNonce(resp) && attempt == 0 {
			if err := a.learnAuth(resp); err != nil {
				return err
			}
			continue
		}
		return errorFrom(resp)
	}
	return errors.New("refresh: out of retries")
}

func (a *minimalTURNAlloc) refreshLoop() {
	half := a.currentLifetime / 2
	if half < 30*time.Second {
		half = 30 * time.Second
	}
	t := time.NewTicker(half)
	defer t.Stop()
	for {
		select {
		case <-a.closed:
			return
		case <-t.C:
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			err := a.refresh(ctx, allocLifetimeSec)
			cancel()
			if err != nil {
				log.Printf("turn-min: refresh failed: %s", err)
				return
			}
		}
	}
}

// addAuth stamps USERNAME, REALM, NONCE and MESSAGE-INTEGRITY onto m.
// All three text attrs MUST be present for the integrity check to
// validate per RFC 5389 §15.4.
func (a *minimalTURNAlloc) addAuth(m *stun.Message) error {
	nonce, _ := a.nonce.Load().([]byte)
	if nonce == nil || a.realm == nil {
		return errors.New("auth not yet learned")
	}
	if err := stun.NewUsername(a.user).AddTo(m); err != nil {
		return err
	}
	if err := stun.Realm(a.realm).AddTo(m); err != nil {
		return err
	}
	if err := stun.Nonce(nonce).AddTo(m); err != nil {
		return err
	}
	return stun.NewLongTermIntegrity(a.user, string(a.realm), a.pass).AddTo(m)
}

// learnAuth pulls REALM and NONCE from a 401 / 438 error response.
func (a *minimalTURNAlloc) learnAuth(m *stun.Message) error {
	var realm stun.Realm
	if err := realm.GetFrom(m); err != nil {
		return fmt.Errorf("REALM: %w", err)
	}
	a.realm = []byte(realm)
	var nonce stun.Nonce
	if err := nonce.GetFrom(m); err != nil {
		return fmt.Errorf("NONCE: %w", err)
	}
	a.nonce.Store([]byte(nonce))
	return nil
}

// do sends m and returns the matching response. It serialises on
// pendingMu so we never have more than one in-flight transaction —
// the existing call sites are sequential (allocate → channelBind →
// periodic refresh) so this is the natural shape.
func (a *minimalTURNAlloc) do(ctx context.Context, m *stun.Message) (*stun.Message, error) {
	a.pendingMu.Lock()
	a.pendingTx = m.TransactionID
	ch := make(chan *stun.Message, 1)
	a.pendingCh = ch
	a.pendingMu.Unlock()

	defer func() {
		a.pendingMu.Lock()
		a.pendingCh = nil
		a.pendingMu.Unlock()
	}()

	// Retransmit ladder. UDP transport may lose the request or its
	// response; TCP transport doesn't need the retries but they're
	// harmless because the server demuxes by transaction ID.
	for _, delay := range txRetryDelays {
		if _, err := a.conn.WriteTo(m.Raw, a.server); err != nil {
			return nil, err
		}
		select {
		case resp := <-ch:
			return resp, nil
		case <-time.After(delay):
			continue
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-a.closed:
			return nil, net.ErrClosed
		}
	}
	return nil, errors.New("transaction timeout")
}

// readLoop is the one and only goroutine that pulls from the
// underlying transport. It demuxes between STUN frames (which feed
// pendingCh) and ChannelData (which feeds inboundData).
func (a *minimalTURNAlloc) readLoop() {
	buf := borrowReadBuf()
	defer returnReadBuf(buf)
	for {
		n, _, err := a.conn.ReadFrom(buf)
		if err != nil {
			// Surface the close downstream so a blocked ReadFrom
			// returns net.ErrClosed instead of hanging.
			a.closeOnce.Do(func() { close(a.closed) })
			return
		}
		if n < 4 {
			continue
		}
		if isChannelData(buf[:n]) {
			payload, ok := decodeChannelData(buf[:n])
			if !ok {
				continue
			}
			// Copy because buf gets reused on the next loop iteration.
			cp := make([]byte, len(payload))
			copy(cp, payload)
			select {
			case a.inboundData <- cp:
			case <-a.closed:
				return
			default:
				// Drop on consumer back-pressure. Matches udp_fanout
				// and packet_pipe behavior under UDP semantics —
				// better than blocking the read loop, which would
				// freeze the allocation entirely.
			}
			continue
		}
		// STUN frame — could be a response (matches pending tx ID)
		// or an indication (Data indication if peer-sent us data via
		// a path that didn't use channel binding). Indications are
		// ignored: the peer ChannelBound, so all real traffic comes
		// in via ChannelData.
		msg := &stun.Message{Raw: append([]byte(nil), buf[:n]...)}
		if err := msg.Decode(); err != nil {
			continue
		}
		a.pendingMu.Lock()
		ch := a.pendingCh
		expected := a.pendingTx
		a.pendingMu.Unlock()
		if ch != nil && msg.TransactionID == expected {
			select {
			case ch <- msg:
			default:
				// Slot already filled — duplicate retransmit reply,
				// safe to drop.
			}
		}
	}
}

// encodeChannelData wraps payload in a ChannelData frame per
// RFC 5766 §11.5. The 4-byte header is followed by payload and (for
// TCP/TLS transports) zero-padded to a 4-byte boundary. UDP doesn't
// require padding but accepts it, so we always pad — the few bytes
// of waste aren't worth a branch.
func encodeChannelData(channel uint16, payload []byte) []byte {
	padLen := (4 - (len(payload) & 3)) & 3
	frame := make([]byte, 4+len(payload)+padLen)
	binary.BigEndian.PutUint16(frame[0:2], channel)
	binary.BigEndian.PutUint16(frame[2:4], uint16(len(payload)))
	copy(frame[4:], payload)
	return frame
}

// decodeChannelData returns the unframed payload (no padding) and
// true if the frame is well-formed. We assume the caller has already
// run isChannelData to disambiguate from STUN.
func decodeChannelData(frame []byte) ([]byte, bool) {
	if len(frame) < 4 {
		return nil, false
	}
	dataLen := int(binary.BigEndian.Uint16(frame[2:4]))
	if 4+dataLen > len(frame) {
		return nil, false
	}
	return frame[4 : 4+dataLen], true
}

// isChannelData distinguishes ChannelData from STUN. STUN's first two
// bits are zero (so first byte < 0x40); valid channel numbers start
// at 0x4000.
func isChannelData(b []byte) bool {
	if len(b) < 4 {
		return false
	}
	ch := binary.BigEndian.Uint16(b[0:2])
	return ch >= 0x4000 && ch <= 0x4FFE
}

func isStaleNonce(m *stun.Message) bool {
	var ec stun.ErrorCodeAttribute
	if err := ec.GetFrom(m); err != nil {
		return false
	}
	return ec.Code == 438
}

func errorFrom(m *stun.Message) error {
	var ec stun.ErrorCodeAttribute
	if err := ec.GetFrom(m); err != nil {
		return fmt.Errorf("turn server returned non-success without ERROR-CODE")
	}
	return fmt.Errorf("turn server error %d: %s", ec.Code, ec.Reason)
}
