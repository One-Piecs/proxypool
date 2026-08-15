package healthcheck

import (
	"testing"

	"github.com/One-Piecs/proxypool/pkg/proxy"
)

func TestFindOrCreateDelayStat(t *testing.T) {
	// 清理全局统计（避免其它测试残留）
	statsLock.Lock()
	ProxyStats = ProxyStats[:0]
	statsLock.Unlock()

	p := &proxy.Shadowsocks{
		Base:     proxy.Base{Name: "t1", Server: "1.2.3.4", Port: 8388, Type: "ss"},
		Password: "pw",
		Cipher:   "aes-256-gcm",
	}

	// 首次调用：创建并返回非 nil
	ps := findOrCreateDelayStat(p, 123)
	if ps == nil {
		t.Fatal("findOrCreateDelayStat returned nil (bug: nil sent to channel)")
	}
	if ps.Delay != 123 {
		t.Fatalf("Delay = %d, want 123", ps.Delay)
	}
	if len(ProxyStats) != 1 {
		t.Fatalf("ProxyStats len = %d, want 1", len(ProxyStats))
	}

	// 再次调用：命中已有记录并更新
	ps2 := findOrCreateDelayStat(p, 456)
	if ps2 == nil {
		t.Fatal("second call returned nil")
	}
	if ps2.Delay != 456 {
		t.Fatalf("Delay = %d, want 456 (updated)", ps2.Delay)
	}
	if len(ProxyStats) != 1 {
		t.Fatalf("ProxyStats len = %d, want 1 (no duplicate)", len(ProxyStats))
	}
}

// TestCleanBadProxiesEmptyList 回归验证 done 通道不被二次关闭：
// 空列表不提交任务，StopWait 立即返回并 close(done)，
// 旧实现还保留 defer close(done) 导致函数返回时二次关闭 panic。
func TestCleanBadProxiesEmptyList(t *testing.T) {
	result := CleanBadProxiesWithWorkpool(nil)
	if result == nil || len(result) != 0 {
		t.Fatalf("expected empty result, got len=%d", len(result))
	}
}
