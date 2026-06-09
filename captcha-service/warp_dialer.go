// warp_dialer.go — bind outbound HTTP sockets to a pre-configured
// WireGuard interface (typically a Cloudflare WARP tunnel set up
// externally via wg-quick) so VK-bound captcha traffic egresses from
// Cloudflare's edge IP space instead of the host's eth0.
//
// Operational model:
//   1. Operator runs wgcf (https://github.com/ViRb3/wgcf) to obtain
//      free WARP credentials, gets a WireGuard config file.
//   2. Operator brings the interface up out-of-band:
//        sudo wg-quick up /etc/wireguard/wgcf.conf
//      with `Table = off` in the [Interface] block so it doesn't
//      install default routes — we don't want WARP eating all
//      outbound traffic from this host, only the captcha-service's
//      VK calls.
//   3. captcha-service runs with WARP_INTERFACE=wgcf in its env.
//      Every outbound HTTP socket aimed at VK gets pinned to that
//      interface via SO_BINDTODEVICE — kernel routes the packet
//      through the WireGuard interface regardless of the host's
//      default route.
//
// Why this approach and not in-process WireGuard:
//   - In-process means importing golang.zx2c4.com/wireguard into a
//     service that runs as non-root → CAP_NET_ADMIN required or
//     fall back to a userspace TUN which needs root anyway. wg-quick
//     handles all that cleanly out of band.
//   - Separation of concerns: WARP setup, key rotation, MTU tuning
//     stays at the network layer where the operator already has
//     tools. captcha-service just consumes an interface name.
//   - Falling back is trivial: unset WARP_INTERFACE and outbound
//     uses the host default route again. No code changes.
//
// SO_BINDTODEVICE requires CAP_NET_RAW or running as root. Our
// Dockerfile drops to non-root user `app`; the operator either grants
// CAP_NET_RAW (--cap-add=NET_RAW in docker run) or runs the container
// with --network=host and a host-level firewall mark instead. The
// README documents both.

package main

import (
	"context"
	"net"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// warpInterface is the name of the WireGuard interface to bind
// outbound captcha sockets to. Empty = WARP off, use default route.
// Read once at startup from WARP_INTERFACE env var.
var warpInterface = os.Getenv("WARP_INTERFACE")

// warpControl is a net.Dialer.Control hook that pins the socket to
// warpInterface before connect(). Idempotent and safe to call from
// multiple goroutines — net.Dialer guarantees serial control invoc
// per socket. Returns nil if WARP isn't configured so it's safe to
// always wire in.
func warpControl(network, address string, c syscall.RawConn) error {
	if warpInterface == "" {
		return nil
	}
	var serr error
	if err := c.Control(func(fd uintptr) {
		serr = unix.BindToDevice(int(fd), warpInterface)
	}); err != nil {
		return err
	}
	return serr
}

// warpDialer wraps an arbitrary upstream DialContext so we can layer
// our SO_BINDTODEVICE control on top while preserving custom DNS
// resolution behavior (e.g. dns_resolver.customDial).
type warpDialer struct {
	upstream func(ctx context.Context, network, address string) (net.Conn, error)
}

func (d *warpDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if d.upstream != nil {
		// The upstream dialer (e.g. customDial) does DNS resolution
		// and may dial-by-IP; we still need to pin to warpInterface
		// after it produces a Conn. SetsockoptString on the live
		// socket isn't reliable cross-platform (kernel may have
		// already started SYN), so instead the upstream dialer must
		// itself install the control hook. Document this contract
		// in callers — see vk_captcha.go.
		return d.upstream(ctx, network, address)
	}
	dialer := &net.Dialer{Control: warpControl}
	return dialer.DialContext(ctx, network, address)
}

// newWARPNetDialer returns a net.Dialer pre-wired with the WARP
// control hook. Use this where a net.Dialer value (not a DialContext
// function) is required — notably tls-client's WithDialer option.
func newWARPNetDialer() net.Dialer {
	return net.Dialer{Control: warpControl}
}

// warpStatus is for the /stats endpoint and startup log.
func warpStatus() string {
	if warpInterface == "" {
		return "off"
	}
	return "on:" + warpInterface
}
