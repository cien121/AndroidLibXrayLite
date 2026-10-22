package libv2ray

import (
	"log"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"

	"github.com/xtls/xray-core/transport/internet"
)

// ProtectHandler 由 Kotlin 实现，gomobile 生成 Java 接口。
// App 侧在 VpnService 中实现 Protect(fd)，调用 VpnService.protect(fd)。
type ProtectHandler interface {
	Protect(fd int32) bool
}

var (
	protectHandler ProtectHandler
	protectCount   int64
	protectFail    int64
	protectOnce    sync.Once
)

// SetProtectHandler 设置 App 侧的 protect 回调，必须在 StartLoop 之前调用。
func SetProtectHandler(h ProtectHandler) {
	protectHandler = h
}

// GetProtectCount 返回已成功 protect 的 socket 计数。
func GetProtectCount() int64 {
	return atomic.LoadInt64(&protectCount)
}

// GetProtectFailCount 返回 protect 失败的计数（protect 返回 false）。
func GetProtectFailCount() int64 {
	return atomic.LoadInt64(&protectFail)
}

// registerProtectController 向 Xray 注册 dialer controller，在每个出站 socket
// 创建时调用 protectHandler.Protect(fd)。只注册一次（sync.Once）。
// 覆盖 TCP/UDP（含 Hy2 QUIC）——Hy2 的两处建 socket 都走
// internet.DialSystem → effectiveSystemDialer.Dial → UDP 分支，
// lc.Control 里循环调用全部 Controllers。
func registerProtectController() {
	protectOnce.Do(func() {
		err := internet.RegisterDialerController(
			func(network, address string, c syscall.RawConn) error {
				if protectHandler == nil {
					return nil
				}
				// loopback 跳过，日志更干净
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

// ListRegisteredTransports 返回 Xray 已注册的 transport 名（排序），
// 供 Kotlin 在 XrayCore.initialize() 做启动自检，fail-fast 发现漏注册
//（如 1.0.21 的 "unknown transport protocol: mist"）。
func ListRegisteredTransports() []string {
	return internet.ListRegisteredTransports()
}
