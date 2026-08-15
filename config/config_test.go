package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestParseCache(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	writeCfg := func(port string) {
		if err := os.WriteFile(path, []byte("port: \""+port+"\"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		// 确保 mtime 严格变化（APFS 纳秒精度下本可省略，双保险）
		_ = os.Chtimes(path, time.Now(), time.Now().Add(2*time.Second))
	}

	writeCfg("12345")
	if err := Parse(path); err != nil {
		t.Fatalf("first parse: %v", err)
	}
	if Config().Port != "12345" {
		t.Fatalf("port = %q, want 12345", Config().Port)
	}

	// 未变化：应命中缓存（不重新解析）
	if err := Parse(path); err != nil {
		t.Fatalf("cached parse: %v", err)
	}
	if Config().Port != "12345" {
		t.Fatalf("port = %q, want 12345 (cached)", Config().Port)
	}

	// 文件变化：应重新解析
	writeCfg("99999")
	if err := Parse(path); err != nil {
		t.Fatalf("re-parse: %v", err)
	}
	if Config().Port != "99999" {
		t.Fatalf("port = %q, want 99999 (re-parsed)", Config().Port)
	}
}

func TestParseInvalidPath(t *testing.T) {
	if err := Parse(filepath.Join(t.TempDir(), "nonexistent.yaml")); err == nil {
		t.Fatal("expected error for nonexistent config file")
	}
}
