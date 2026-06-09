// packet_pipe.go — bounded in-memory net.PacketConn pair.
//
// Replaces github.com/pion/transport/v4/connutil.AsyncPacketPipe in
// turn_proxy.go. The pion version is backed by an unbounded
// bytes.Buffer whose capacity ratchets up to the high-water mark on
// any burst and never shrinks — that's how steady-state RSS grew
// past the iOS budget at N=40 under reconnect storms. The bounded
// pipe below caps in-flight queue depth at boundedPipeDepth packets
// per direction and drops on overflow (UDP semantics, no
// backpressure), so worst-case memory per session is exactly
// 2 × depth × ~MTU bytes.
//
// Also exports readBufPool, a sync.Pool of *[1600]byte used by the
// four read-loop scratches in oneDtlsConnection /
// oneTurnConnection. Each loop borrows on entry, returns on exit.
// Under reconnect churn (sessions dying and respawning at high
// rate) this trims the GC pressure of repeatedly allocating ~1.6 KB
// per new goroutine.

package main

import (
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// boundedPipeDepth caps how many packets can sit in either direction
// of the pipe at one time. DTLS handshake bursts are ~5-10 packets;
// post-handshake traffic drains fast, so 16 leaves comfortable
// headroom without committing many MB per session.
const boundedPipeDepth = 16

type pipePacket struct {
	data []byte
	addr net.Addr
}

// pipePair owns the two channels that connect a pair of pipeConns,
// plus the shared close state. Closing either pipeConn closes the
// pair — there's no way to half-close a UDP-like connection, and
// pion's connutil behaved the same way.
type pipePair struct {
	a2b       chan pipePacket
	b2a       chan pipePacket
	closeOnce sync.Once
	closed    chan struct{}
	dropped   atomic.Uint64
}

type pipeConn struct {
	pair *pipePair
	rx   chan pipePacket // packets coming IN (= peer's tx)
	tx   chan pipePacket // packets going OUT (= peer's rx)

	deadlineMu    sync.Mutex
	wakeup        chan struct{}
	deadlineTimer *time.Timer
}

// boundedPacketPipe returns a connected pair of net.PacketConn.
// Each direction has its own channel of depth=boundedPipeDepth.
// WriteTo to one appears on the other's ReadFrom. Bounded — overflow
// drops the new packet with a counter increment rather than blocking.
func boundedPacketPipe() (net.PacketConn, net.PacketConn) {
	pair := &pipePair{
		a2b:    make(chan pipePacket, boundedPipeDepth),
		b2a:    make(chan pipePacket, boundedPipeDepth),
		closed: make(chan struct{}),
	}
	a := &pipeConn{
		pair:   pair,
		rx:     pair.b2a,
		tx:     pair.a2b,
		wakeup: make(chan struct{}),
	}
	b := &pipeConn{
		pair:   pair,
		rx:     pair.a2b,
		tx:     pair.b2a,
		wakeup: make(chan struct{}),
	}
	return a, b
}

func (p *pipeConn) ReadFrom(buf []byte) (int, net.Addr, error) {
	select {
	case pkt, ok := <-p.rx:
		if !ok {
			return 0, nil, net.ErrClosed
		}
		n := copy(buf, pkt.data)
		return n, pkt.addr, nil
	case <-p.pair.closed:
		return 0, nil, net.ErrClosed
	case <-p.wakeup:
		return 0, nil, os.ErrDeadlineExceeded
	}
}

func (p *pipeConn) WriteTo(buf []byte, addr net.Addr) (int, error) {
	select {
	case <-p.pair.closed:
		return 0, net.ErrClosed
	default:
	}
	// Copy because the caller is allowed to reuse buf after WriteTo
	// returns (pion does this with its own scratch buffer).
	data := append([]byte(nil), buf...)
	select {
	case p.tx <- pipePacket{data: data, addr: addr}:
		return len(buf), nil
	case <-p.pair.closed:
		return 0, net.ErrClosed
	default:
		// Drop on overflow. Mirrors udp_fanout.go's dispatcher
		// behaviour and matches UDP's "no flow control" semantics.
		// Lying about success (returning len(buf), nil) is the
		// standard idiom — net.PacketConn callers don't have a
		// way to react to "your packet was buffered, not sent"
		// anyway.
		p.pair.dropped.Add(1)
		return len(buf), nil
	}
}

func (p *pipeConn) Close() error {
	p.pair.closeOnce.Do(func() { close(p.pair.closed) })
	return nil
}

// LocalAddr returns a sentinel because pion-dtls reads it just to log
// it; the value doesn't have to be meaningful for the pipe to work.
func (p *pipeConn) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4zero, Port: 0}
}

func (p *pipeConn) SetDeadline(t time.Time) error {
	if err := p.SetReadDeadline(t); err != nil {
		return err
	}
	return p.SetWriteDeadline(t)
}

// SetReadDeadline mirrors fanoutPacketConn: the pion idiom is
// "Set to a past time" = "interrupt the in-flight read with
// os.ErrDeadlineExceeded". We don't bother implementing a real
// future-deadline behaviour because oneTurnConnection /
// oneDtlsConnection only ever call this with time.Now() from
// context.AfterFunc when ctx is being cancelled.
func (p *pipeConn) SetReadDeadline(t time.Time) error {
	p.deadlineMu.Lock()
	defer p.deadlineMu.Unlock()

	if p.deadlineTimer != nil {
		p.deadlineTimer.Stop()
		p.deadlineTimer = nil
	}

	if t.IsZero() {
		return nil
	}
	d := time.Until(t)
	if d <= 0 {
		select {
		case p.wakeup <- struct{}{}:
		default:
		}
		return nil
	}
	p.deadlineTimer = time.AfterFunc(d, func() {
		select {
		case p.wakeup <- struct{}{}:
		default:
		}
	})
	return nil
}

// SetWriteDeadline is a no-op: WriteTo never blocks (drops on
// overflow via the select-default branch), so a deadline can't
// be missed.
func (p *pipeConn) SetWriteDeadline(t time.Time) error {
	return nil
}

// readBufPool amortises the 1600-byte read scratches used by every
// per-session read-loop goroutine in oneDtlsConnection and
// oneTurnConnection. Without it, each goroutine startup allocates
// a fresh slice — under a reconnect storm (N=40 sessions cycling
// every ~30 s on cred-rotation) that's ~160 allocations per cycle
// of 1.6 KB each = 256 KB of churn per minute just on scratches.
// With the pool, freshly-spawned goroutines reuse a recently-freed
// scratch instead.
var readBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 1600)
		return &b
	},
}

// borrowReadBuf returns a 1600-byte slice from the pool. The caller
// must return it via returnReadBuf when done; the buf MUST NOT be
// retained or shared after that.
func borrowReadBuf() []byte {
	return *readBufPool.Get().(*[]byte)
}

func returnReadBuf(buf []byte) {
	// Only return slices that haven't been re-sliced down; this keeps
	// the pool entries at the expected 1600-byte capacity. The check
	// also rejects nil and non-pool-sourced buffers that callers
	// might accidentally pass in.
	if cap(buf) != 1600 {
		return
	}
	buf = buf[:cap(buf)]
	readBufPool.Put(&buf)
}
