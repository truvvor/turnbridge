// SPDX-License-Identifier: MIT
//
// UDP socket-buffer tuning helper for the two real wire sockets in
// turn_proxy.go (listenConn on 127.0.0.1:9000 and turnConn to VK's
// relay). Default iOS UDP RCVBUF/SNDBUF is in the ~196 KB ballpark,
// which is fine for the audio/video calling that VK's TURN servers
// were originally built for but too small for the bursty packet
// pattern of a web page load tunneled over WG: 50–100 1.2 KB packets
// arrive within a few ms and the kernel drops anything that can't fit
// the queue before the read goroutine drains it.
//
// We try to raise both buffers to 4 MB. The kernel may cap the actual
// size below the request (iOS uses `kern.ipc.maxsockbuf`, typically
// 8 MB), so we log what we actually got via SO_RCVBUF / SO_SNDBUF
// readback so a future "still losing packets" report can be diagnosed.

package main

import (
	"log"
	"net"
	"syscall"
)

const udpBufferTarget = 4 * 1024 * 1024 // 4 MB

// udpBufferTuner is the smallest interface that both
// `net.PacketConn` (listenConn) and `*net.UDPConn` (turnConn) satisfy
// for setting socket buffer sizes.
type udpBufferTuner interface {
	SetReadBuffer(bytes int) error
	SetWriteBuffer(bytes int) error
}

// tuneUDPBuffers requests larger socket buffers and logs the result.
// On Darwin the actual buffer size is 2x the value you ask for (the
// kernel accounts for control overhead), so the SO_RCVBUF/SO_SNDBUF
// readback can look bigger than `udpBufferTarget` — that's fine.
func tuneUDPBuffers(label string, conn interface{}) {
	t, ok := conn.(udpBufferTuner)
	if !ok {
		log.Printf("%s: cannot tune UDP buffers (unsupported type %T)", label, conn)
		return
	}
	if err := t.SetReadBuffer(udpBufferTarget); err != nil {
		log.Printf("%s: SetReadBuffer(%d) failed: %v", label, udpBufferTarget, err)
	}
	if err := t.SetWriteBuffer(udpBufferTarget); err != nil {
		log.Printf("%s: SetWriteBuffer(%d) failed: %v", label, udpBufferTarget, err)
	}

	// Read back the kernel-accepted values via SyscallConn so we know
	// whether the request was honoured or silently capped.
	rcv, snd := readbackBuffers(conn)
	log.Printf("%s: UDP buffers tuned: SO_RCVBUF=%d SO_SNDBUF=%d (target=%d)",
		label, rcv, snd, udpBufferTarget)
}

func readbackBuffers(conn interface{}) (rcv, snd int) {
	type syscallable interface {
		SyscallConn() (syscall.RawConn, error)
	}
	sc, ok := conn.(syscallable)
	if !ok {
		return 0, 0
	}
	raw, err := sc.SyscallConn()
	if err != nil {
		return 0, 0
	}
	_ = raw.Control(func(fd uintptr) {
		if v, err := syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUF); err == nil {
			rcv = v
		}
		if v, err := syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_SNDBUF); err == nil {
			snd = v
		}
	})
	return rcv, snd
}

// Type-assertion guard: net.PacketConn returned by net.ListenPacket
// for the "udp" network is concretely *net.UDPConn, which satisfies
// both udpBufferTuner and the SyscallConn interface. Compile-time
// sanity check so we don't drift.
var (
	_ udpBufferTuner = (*net.UDPConn)(nil)
)
