package log

import (
	"io"
	"testing"

	log "github.com/sirupsen/logrus"
)

// TestDefaultLoggerDiscarded 验证 logrus 默认 logger 输出已丢弃：
// mihomo 等第三方库直接写默认 logger，若不丢弃会在健康检查/测速时
// 把内部错误（如 vision 握手失败）刷到应用日志。
func TestDefaultLoggerDiscarded(t *testing.T) {
	if out := log.StandardLogger().Out; out != io.Discard {
		t.Fatalf("default logrus logger output = %v, want io.Discard", out)
	}
}

// TestAppLoggerWorks 验证应用自身日志仍可正常输出（使用独立实例）
func TestAppLoggerWorks(t *testing.T) {
	// 不应 panic
	Infoln("app log works")
	Warnln("app warn works")
	Errorln("app error works")
}
