package libv2ray

import (
	"log"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"

	"github.com/xtls/xray-core/transport/internet"
)

// ProtectHandler is implemented by the Kotlin side; gomobile generates a Java interface.
// The App implements Protect(fd) by calling VpnService.protect(fd).
type ProtectHandler interface {
	Protect(fd int32) bool
}

var (
	protectHandler ProtectHandler
	protectCount   int64
	protectFail    int64
	protectOnce    sync.Once
)

// SetProtectHandler sets the App-side protect callback. Must be called before StartLoop.
func SetProtectHandler(h ProtectHandler) {
	protectHandler = h
}

// GetProtectCount returns the number of sockets successfully protected.
func GetProtectCount() int64 {
	return atomic.LoadInt64(&protectCount)
}

// GetProtectFailCount returns the number of protect failures (Protect returned false).
func GetProtectFailCount() int64 {
	return atomic.LoadInt64(&protectFail)
}

// registerProtectController registers a dialer controller with Xray that calls
// protectHandler.Protect(fd) on every outbound socket creation. Registered once (sync.Once).
// Covers TCP/UDP (incl. Hy2 QUIC): both Hy2 socket creation sites go through
// internet.DialSystem -> effectiveSystemDialer.Dial -> UDP branch, where
// lc.Control loops over all Controllers.
func registerProtectController() {
	protectOnce.Do(func() {
		err := internet.RegisterDialerController(
			func(network, address string, c syscall.RawConn) error {
				if protectHandler == nil {
					return nil
				}
				// Skip loopback for cleaner logs.
				if strings.HasPrefix(address, "127.") ||
					strings.HasPrefix(address, "[::1]:") {
					return nil
				}
				var ctrlErr error
				c.Control(func(fd uintptr) {
					ok := protectHandler.Protect(int32(fd))
					if ok {
						atomic.AddInt64(&protectCount, 1)
					} else {
						atomic.AddInt64(&protectFail, 1)
						log.Printf("WeaveProtect: protect(fd=%d) failed for %s %s", fd, network, address)
					}
				})
				return ctrlErr
			})
		if err != nil {
			log.Printf("WeaveProtect: RegisterDialerController failed: %v", err)
		}
	})
}

// ListRegisteredTransports returns the sorted names of Xray's registered transports,
// for the Kotlin startup self-check in XrayCore.initialize() to fail fast on a
// missing transport (e.g. the 1.0.21 "unknown transport protocol: mist" regression).
func ListRegisteredTransports() []string {
	return internet.ListRegisteredTransports()
}
