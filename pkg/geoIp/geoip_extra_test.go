package geoIp

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadEmojiMap(t *testing.T) {
	em, err := loadEmojiMap()
	if err != nil {
		t.Fatalf("loadEmojiMap failed: %v", err)
	}
	if len(em) == 0 {
		t.Fatal("emojiMap is empty")
	}
	if em["CN"] == "" || em["JP"] == "" || em["US"] == "" {
		t.Fatalf("missing common country emojis: CN=%q JP=%q US=%q", em["CN"], em["JP"], em["US"])
	}
}

func TestWriteFileAtomic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "test.txt")
	if err := writeFileAtomic(path, []byte("hello")); err != nil {
		t.Fatalf("writeFileAtomic failed: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back failed: %v", err)
	}
	if string(data) != "hello" {
		t.Fatalf("content mismatch: %q", data)
	}
	// 不应残留临时文件
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Fatalf("tmp file should not exist, err=%v", err)
	}
}

func TestFindWithoutDB(t *testing.T) {
	// DB 未加载时应返回错误而不是 panic
	old := countryDB.Load()
	countryDB.Store(nil)
	defer func() {
		if old != nil {
			countryDB.Store(old)
		}
	}()

	ip, country, err := GeoIpDB.Find("1.2.3.4")
	if err == nil {
		t.Fatalf("expected error when db not loaded, got ip=%s country=%s", ip, country)
	}
}

func TestFindInvalidInput(t *testing.T) {
	// 非法输入(非 IP 非域名)应返回错误
	_, _, err := GeoIpDB.Find("not-an-ip-or-domain!!")
	if err == nil {
		t.Fatal("expected error for invalid input")
	}
}

func TestIsCDNKeywordsPrecompiled(t *testing.T) {
	// 校验大写关键词表覆盖原实现的关键词
	originals := []string{
		"CDN", "Content Delivery", "Edge", "Anycast", "Cache",
		"Akamai", "Incap", "Stackpath", "Bunny", "Zscaler", "Cloudflare", "Fastly",
		"Microsoft", "Azure", "Amazon", "Google", "Edgio", "Edgecast", "Limelight",
		"CacheFly", "CDNetworks", "ArvanCloud", "Tencent", "Alibaba",
	}
	upperSet := make(map[string]bool, len(cdnKeywordsUpper))
	for _, kw := range cdnKeywordsUpper {
		upperSet[kw] = true
	}
	for _, orig := range originals {
		if !upperSet[strings.ToUpper(orig)] {
			t.Errorf("keyword %q missing from precompiled list", orig)
		}
	}
}
