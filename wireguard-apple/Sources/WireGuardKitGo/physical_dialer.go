// SPDX-License-Identifier: MIT
//
// physical_dialer.go — escape hatch from the utun default route.
//
// Once WireGuard comes up inside the NE extension, utun becomes the
// default route in the extension's process. From that moment, every
// HTTP request the captcha solver issues exits through utun → WG
// server → VK. That's the "tunnel egress" — VK sees a single shared
// source IP from all our sessions, and VK's per-IP captcha rate-limit
// chokes it within a minute. Worse: there is no way to flip the
// default route back to cellular dynamically; iOS exposes no API for
// that inside an NE extension.
//
// Workaround: pin individual sockets to a specific physical interface
// using Darwin's IP_BOUND_IF / IPV6_BOUND_IF setsockopts. The kernel
// then routes those sockets through the named NIC (en0 / pdp_ip0)
// regardless of what the default route says. utun is bypassed.
//
// cellularDial is a drop-in replacement for customDial that does
// exactly this. It enumerates non-loopback non-tunnel interfaces,
// prefers Wi-Fi (en0), falls back to cellular (pdp_ip0), and falls
// back to customDial if no usable physical interface is found.

package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// Darwin socket-option constants. The Go standard library doesn't
// re-export these, but they're stable in <netinet/in.h>:
//   IP_BOUND_IF        = 25  (binds an IPv4 socket to an interface index)
//   IPV6_BOUND_IF      = 125 (same for IPv6)
const (
	darwinIPBoundIf   = 25
	darwinIPv6BoundIf = 125
)

// Cached physical-interface index, refreshed on a TTL. Enumerating
// interfaces is cheap but not free, and cellularDial may be called
// many times per second under heavy retry. 30 s is generous since
// iOS interface indices don't change without a Network Path change
// event (which the watchdog already handles separately).
var (
	physIfaceMu       sync.Mutex
	physIfaceIndex    atomic.Int32 // 0 means "no usable interface"
	physIfaceCachedAt time.Time
)

const physIfaceTTL = 30 * time.Second

func physicalInterfaceIndex() int {
	physIfaceMu.Lock()
	defer physIfaceMu.Unlock()

	if !physIfaceCachedAt.IsZero() && time.Since(physIfaceCachedAt) < physIfaceTTL {
		return int(physIfaceIndex.Load())
	}

	idx := lookupPhysicalInterface()
	physIfaceIndex.Store(int32(idx))
	physIfaceCachedAt = time.Now()
	return idx
}

// lookupPhysicalInterface returns the index of a non-loopback, non-
// tunnel, non-bridge interface that has at least one routable IPv4
// address. Wi-Fi (en0..) is preferred; cellular (pdp_ipN) is the
// fallback. Returns 0 if nothing usable is up.
func lookupPhysicalInterface() int {
	ifaces, err := net.Interfaces()
	if err != nil {
		log.Printf("physical_dialer: net.Interfaces failed: %v", err)
		return 0
	}

	var wifi, cellular int
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		name := iface.Name
		if strings.HasPrefix(name, "utun") || strings.HasPrefix(name, "ipsec") {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil || len(addrs) == 0 {
			continue
		}
		hasUsableIP := false
		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip4 := ipnet.IP.To4()
			if ip4 == nil {
				continue
			}
			if ip4.IsLinkLocalUnicast() || ip4.IsLoopback() || ip4.IsUnspecified() {
				continue
			}
			hasUsableIP = true
			break
		}
		if !hasUsableIP {
			continue
		}
		switch {
		case strings.HasPrefix(name, "en"):
			if wifi == 0 {
				wifi = iface.Index
			}
		case strings.HasPrefix(name, "pdp_ip"):
			if cellular == 0 {
				cellular = iface.Index
			}
		}
	}
	if wifi != 0 {
		return wifi
	}
	return cellular
}

// pinnedDialer returns a net.Dialer whose sockets are bound to the
// given interface index via IP_BOUND_IF / IPV6_BOUND_IF. Each Dial
// call sets the option in the socket Control hook before connect.
func pinnedDialer(ifIndex int, timeout time.Duration) *net.Dialer {
	return &net.Dialer{
		Timeout: timeout,
		Control: func(network, address string, c syscall.RawConn) error {
			var bindErr error
			ctrlErr := c.Control(func(fd uintptr) {
				if strings.HasSuffix(network, "6") {
					bindErr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, darwinIPv6BoundIf, ifIndex)
				} else {
					bindErr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, darwinIPBoundIf, ifIndex)
				}
			})
			if ctrlErr != nil {
				return ctrlErr
			}
			return bindErr
		},
	}
}

// cellularDial is the interface-pinned counterpart of customDial.
// Same DNS resilience (system → DoH → hardcoded fallback IPs), but
// every connect() is issued from a socket bound to a physical
// interface, so the kernel routes through cellular / Wi-Fi instead
// of utun. If no physical interface is up we transparently fall back
// to customDial; the caller (solveVkCaptcha) has already gated on
// physicalInterfaceIndex() > 0 anyway, but the fallback is cheap
// safety.
func cellularDial(ctx context.Context, network, address string) (net.Conn, error) {
	ifIndex := physicalInterfaceIndex()
	if ifIndex == 0 {
		log.Printf("cellularDial: no usable physical interface, falling back to default route")
		return customDial(ctx, network, address)
	}

	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}

	d := pinnedDialer(ifIndex, dohDialBudget)

	// Fast path: literal IP needs no resolution.
	if net.ParseIP(host) != nil {
		return d.DialContext(ctx, network, address)
	}

	// Layer 1: system resolver via the pinned dialer.
	sysCtx, cancel := context.WithTimeout(ctx, systemDialBudget)
	conn, sysErr := d.DialContext(sysCtx, network, address)
	cancel()
	if sysErr == nil {
		return conn, nil
	}
	log.Printf("cellularDial: system resolve+dial failed for %s via iface=%d: %v — falling back to DoH",
		host, ifIndex, sysErr)

	// Layer 2: DoH lookup, then dial the returned IPs via the pinned
	// dialer. DoH itself uses dohClient (default route) — once the
	// tunnel is up, DoH responses get cached for 10 minutes so the
	// per-host RTT is amortised.
	if ips, err := resolveViaDoH(ctx, host); err == nil && len(ips) > 0 {
		log.Printf("cellularDial: DoH %s → %v (iface=%d)", host, ips, ifIndex)
		for _, ip := range ips {
			c, derr := d.DialContext(ctx, network, net.JoinHostPort(ip, port))
			if derr == nil {
				return c, nil
			}
			log.Printf("cellularDial: dial %s via iface=%d (DoH) failed: %v", ip, ifIndex, derr)
		}
	} else if err != nil {
		log.Printf("cellularDial: DoH lookup failed for %s: %v", host, err)
	}

	// Layer 3: hardcoded VK fallback IPs.
	if ips, ok := fallbackIPs[strings.ToLower(host)]; ok {
		log.Printf("cellularDial: trying hardcoded fallback IPs for %s via iface=%d: %v",
			host, ifIndex, ips)
		for _, ip := range ips {
			c, derr := d.DialContext(ctx, network, net.JoinHostPort(ip, port))
			if derr == nil {
				return c, nil
			}
			log.Printf("cellularDial: dial %s via iface=%d (fallback) failed: %v", ip, ifIndex, derr)
		}
	}

	return nil, fmt.Errorf("cellularDial: all DNS layers exhausted for %s via iface=%d (sys=%v)",
		host, ifIndex, sysErr)
}
