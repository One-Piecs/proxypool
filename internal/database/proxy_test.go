package database

import (
	"testing"

	"github.com/One-Piecs/proxypool/pkg/proxy"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// TestGetAllProxiesRestoresName 验证从数据库加载时恢复上次爬取保存的 name/country，
// 避免启动窗口期（首轮爬取完成前）/proxies 接口输出空名称。
func TestGetAllProxiesRestoresName(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AutoMigrate(&Proxy{}); err != nil {
		t.Fatal(err)
	}

	// 保存全局 DB 并在测试后恢复
	oldDB := DB
	DB = db
	defer func() { DB = oldDB }()

	p := Proxy{
		Base: proxy.Base{
			Name: "🇯🇵 JP_01", Country: "🇯🇵 JP",
			Server: "1.2.3.4", Port: 8388, Type: "ss", Useable: true,
		},
		Link: "ss://YWVzLTI1Ni1nY206cGFzc0AxLjIuMy40OjgzODg=",
	}
	if err := db.Create(&p).Error; err != nil {
		t.Fatal(err)
	}

	pl := GetAllProxies()
	if len(pl) != 1 {
		t.Fatalf("len = %d, want 1", len(pl))
	}
	base := pl[0].BaseInfo()
	if base.Name != "🇯🇵 JP_01" {
		t.Errorf("name = %q, want restored '🇯🇵 JP_01'", base.Name)
	}
	if base.Country != "🇯🇵 JP" {
		t.Errorf("country = %q, want restored '🇯🇵 JP'", base.Country)
	}
	if base.Useable {
		t.Error("useable should be false after load")
	}
	if base.Port != 8388 || base.Server != "1.2.3.4" {
		t.Errorf("parsed base mismatch: %+v", base)
	}
}
