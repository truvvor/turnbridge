// SPDX-License-Identifier: MIT
//
// UDP fan-out so N parallel TURN allocations actually share the WG
// upstream traffic instead of all sleeping on the same listenConn.
//
// Background: StartProxy creates ONE net.PacketConn for 127.0.0.1:9000
// (the WG client's UDP endpoint) and previously handed the same
// PacketConn to every oneDtlsConnection goroutine. When WG sends a
// packet, the kernel wakes ONE waiting goroutine — usually the same
// one consistently due to scheduling — so the other N-1 sessions sit
// idle. Setting nValue=3 in the profile then doesn't actually
// triple throughput, which silently defeats the whole reason to
// run multiple TURN allocations.
//
// Fix: a dispatcher goroutine reads from the real listenConn and
// round-robins each packet into one of N fanoutPacketConn channels.
// Each fanoutPacketConn satisfies net.PacketConn, so it drops in
// where listenConn used to be passed without changing the
// oneDtlsConnection signature. WriteTo delegates straight back to
// the real socket — replies from all N sessions go out the same
// shared port to the same WG client address.
//
// WG itself is robust to per-packet reordering up to a 32-packet
// replay window (RFC 7539 + WireGuard whitepaper §5.3), so a 3-way
// round-robin is safe. Round-robin is per-packet rather than per-flow
// because there's only ever one flow on this socket (one WG client
// instance).

package main

import (
	"context"
	"errors"
	"log"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// fanoutQueueDepth is the per-virtual-conn buffer size. Each slot
// holds a fanoutPacket (slice header + ~1500 B payload), so at
// N=40 and 256-deep queues worst-case the dispatcher could be
// holding 40 × 256 × 1.5 KB ≈ 15 MB of in-flight WG packets — a
// lot of headroom for a system that's already inside a ~100 MB
// extension budget. 64 still absorbs a fast page-load burst
// (~50-100 packets in a few ms) without dropping, and caps worst-
// case at ~4 MB. If the consumer is slower than that the drop
// counter trips earlier, which is the right signal anyway —
// hiding it behind a deeper queue just delays the inevitable.
const fanoutQueueDepth = 64

type fanoutPacket struct {
	data []byte
	addr net.Addr
}

// fanoutPacketConn is the per-DTLS-session view of the shared
// listenConn. Reads come from a private channel filled by the
// dispatcher; writes go straight to the underlying socket.
type fanoutPacketConn struct {
	id       int
	real     net.PacketConn
	incoming chan fanoutPacket

	closeOnce sync.Once
	closed    chan struct{}

	// deadline state: SetReadDeadline(past time) is the standard
	// "interrupt the in-flight read" idiom used by oneDtlsConnection's
	// context.AfterFunc cleanup. We mirror that with a wakeup channel
	// that ReadFrom selects on.
	deadlineMu    sync.Mutex
	wakeup        chan struct{}
	deadlineTimer *time.Timer

	dropped atomic.Uint64 // packets the dispatcher tried to enqueue but the channel was full

	// active=false ⇒ dispatcher skips this lane. Used during phased
	// bring-up: wave-2 fanouts exist before their DTLS sessions are
	// up; without this gate the dispatcher round-robins WG packets
	// into channels nobody is draining, the buffer fills, and packets
	// get dropped instead of being delivered to the wave-1 lanes that
	// are actually live. Flipped to true the instant the matching
	// oneDtlsConnection signals sessionOk.
	active atomic.Bool
}

func newFanoutPacketConn(id int, real net.PacketConn) *fanoutPacketConn {
	return &fanoutPacketConn{
		id:       id,
		real:     real,
		incoming: make(chan fanoutPacket, fanoutQueueDepth),
		closed:   make(chan struct{}),
		wakeup:   make(chan struct{}),
	}
}

func (f *fanoutPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	select {
	case pkt, ok := <-f.incoming:
		if !ok {
			return 0, nil, net.ErrClosed
		}
		n := copy(p, pkt.data)
		return n, pkt.addr, nil
	case <-f.closed:
		return 0, nil, net.ErrClosed
	case <-f.wakeup:
		return 0, nil, os.ErrDeadlineExceeded
	}
}

func (f *fanoutPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	return f.real.WriteTo(p, addr)
}

func (f *fanoutPacketConn) Close() error {
	f.closeOnce.Do(func() { close(f.closed) })
	return nil
}

func (f *fanoutPacketConn) LocalAddr() net.Addr { return f.real.LocalAddr() }

func (f *fanoutPacketConn) SetDeadline(t time.Time) error {
	if err := f.SetReadDeadline(t); err != nil {
		return err
	}
	return f.SetWriteDeadline(t)
}

func (f *fanoutPacketConn) SetReadDeadline(t time.Time) error {
	f.deadlineMu.Lock()
	defer f.deadlineMu.Unlock()

	if f.deadlineTimer != nil {
		f.deadlineTimer.Stop()
		f.deadlineTimer = nil
	}

	// Empty time → clear deadline. Replace wakeup so future ReadFrom
	// calls don't immediately fail.
	if t.IsZero() {
		select {
		case <-f.wakeup:
			// Was closed; create a fresh one so subsequent reads don't fail.
			f.wakeup = make(chan struct{})
		default:
		}
		return nil
	}

	wait := time.Until(t)
	if wait <= 0 {
		// Already past — interrupt any current ReadFrom immediately.
		select {
		case <-f.wakeup:
			// Already closed, nothing to do.
		default:
			close(f.wakeup)
		}
		return nil
	}

	// Future deadline — arm a timer to close wakeup at the right moment.
	f.deadlineTimer = time.AfterFunc(wait, func() {
		f.deadlineMu.Lock()
		defer f.deadlineMu.Unlock()
		select {
		case <-f.wakeup:
		default:
			close(f.wakeup)
		}
	})
	return nil
}

func (f *fanoutPacketConn) SetWriteDeadline(t time.Time) error {
	// The real listenConn's deadline is shared across all fanouts, so
	// honoring it here would break the other sessions. We don't use
	// write deadlines anywhere in oneDtlsConnection's actual data
	// path, so this is safe to ignore.
	return nil
}

// startFanoutDispatcher spawns one goroutine that drains the shared
// listenConn and distributes packets round-robin into the N fanouts.
// On listenConn close it tears down all fanouts.
func startFanoutDispatcher(ctx context.Context, listenConn net.PacketConn, fanouts []*fanoutPacketConn) {
	go func() {
		defer func() {
			for _, f := range fanouts {
				f.Close()
			}
		}()

		buf := make([]byte, 1600)
		var rrIdx uint64
		var dropped uint64

		// Drops are silent under healthy conditions and only surface
		// when a consumer is actually backing up. Periodic dispatcher
		// health log fires every 10s but only emits a line if at
		// least one packet was dropped since the last tick.
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		go func() {
			var prevDrop uint64
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					curDrop := atomic.LoadUint64(&dropped)
					if curDrop == prevDrop {
						continue
					}
					var perFanoutDrop []uint64
					for _, f := range fanouts {
						perFanoutDrop = append(perFanoutDrop, f.dropped.Load())
					}
					log.Printf("fanout: dropped Δ+%d (total=%d) per-session=%v",
						curDrop-prevDrop, curDrop, perFanoutDrop)
					prevDrop = curDrop
				}
			}
		}()

		for {
			n, addr, err := listenConn.ReadFrom(buf)
			if err != nil {
				if errors.Is(err, net.ErrClosed) || errors.Is(err, os.ErrDeadlineExceeded) {
					log.Printf("fanout: dispatcher exiting: %s", err)
					return
				}
				log.Printf("fanout: dispatcher read error: %s", err)
				return
			}

			// Copy because buf is reused next iteration.
			data := make([]byte, n)
			copy(data, buf[:n])

			// Pick an ACTIVE fanout. We use SHORTEST-QUEUE-FIRST with a
			// round-robin tiebreak. Pure round-robin distributes WG
			// packets evenly across N sessions, but the throughput of a
			// VK TURN allocation is voice-grade (~250 kbps - 2 Mbps) and
			// some allocations are noticeably slower than others — a
			// recycled cred about to expire, a relay on a hot path, a
			// session whose DTLS handshake just retried. Pure RR keeps
			// shoving packets into those slow lanes until their 256-deep
			// buffer fills, then drops; meanwhile fast lanes idle.
			// Shortest-queue-first naturally puts most packets on the
			// fastest lanes (their queues are short because they drain
			// quickly) and starves the slow ones. WG's own
			// retransmit/ack machinery handles any out-of-order arrival.
			//
			// O(N) per packet is fine: N ≤ 100, ~1k pkts/sec on a
			// 10 Mbps tunnel → 100k cheap ops/sec.
			total := uint64(len(fanouts))
			start := (atomic.AddUint64(&rrIdx, 1) - 1) % total
			var f *fanoutPacketConn
			minLen := fanoutQueueDepth + 1 // anything in-range beats this
			for k := uint64(0); k < total; k++ {
				i := (start + k) % total
				if !fanouts[i].active.Load() {
					continue
				}
				l := len(fanouts[i].incoming)
				if l < minLen {
					minLen = l
					f = fanouts[i]
					if l == 0 {
						break // an empty queue is unbeatable
					}
				}
			}
			if f == nil {
				// No active lanes — the bootstrap fleet hasn't come
				// up yet, or all sessions died. Drop and account.
				atomic.AddUint64(&dropped, 1)
				continue
			}

			select {
			case f.incoming <- fanoutPacket{data: data, addr: addr}:
			case <-ctx.Done():
				return
			default:
				// Consumer is too slow — drop this packet and account
				// for it. Better than blocking the dispatcher (which
				// would also stall the other N-1 fanouts) or growing
				// the channel unbounded.
				f.dropped.Add(1)
				atomic.AddUint64(&dropped, 1)
			}
		}
	}()
}
