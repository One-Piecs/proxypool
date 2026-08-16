package database

import (
	"testing"

	"github.com/One-Piecs/proxypool/pkg/healthcheck"
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

// TestSpeedPersistence 验证测速结果持久化与恢复
func TestSpeedPersistence(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AutoMigrate(&Proxy{}); err != nil {
		t.Fatal(err)
	}
	oldDB := DB
	DB = db
	defer func() { DB = oldDB }()

	p := Proxy{
		Identifier: "1.2.3.4:8388pass", // 与 SaveProxyList 写入的唯一标识一致
		Base: proxy.Base{
			Name: "🇯🇵 JP_01", Country: "🇯🇵 JP",
			Server: "1.2.3.4", Port: 8388, Type: "ss", Useable: true,
		},
		Link: "ss://YWVzLTI1Ni1nY206cGFzc0AxLjIuMy40OjgzODg=",
	}
	if err := db.Create(&p).Error; err != nil {
		t.Fatal(err)
	}

	// 模拟测速后保存速度
	pl := GetAllProxies()
	if len(pl) != 1 {
		t.Fatalf("len = %d, want 1", len(pl))
	}
	healthcheck.AppendStat(healthcheck.Stat{Id: pl[0].Identifier(), Speed: 25.5})
	SaveProxiesSpeed(pl)

	// 验证 DB 中已保存
	var saved Proxy
	if err := db.Where("identifier = ?", pl[0].Identifier()).First(&saved).Error; err != nil {
		t.Fatal(err)
	}
	if saved.Speed != 25.5 {
		t.Errorf("saved speed = %v, want 25.5", saved.Speed)
	}

	// 模拟重启: 清空统计后重新加载, 速度应恢复
	healthcheck.ProxyStats = healthcheck.ProxyStats[:0]
	pl2 := GetAllProxies()
	if len(pl2) != 1 {
		t.Fatalf("reload len = %d, want 1", len(pl2))
	}
	if ps, ok := healthcheck.FindStat(pl2[0]); !ok || ps.Speed != 25.5 {
		t.Errorf("speed not restored after reload: %+v", ps)
	}
}
