package geoIp

import (
	"testing"
)

func TestGeoIP_Find(t *testing.T) {
	// InitGeoIpDB 需要本地的 assets/Country.mmdb，缺失时会尝试联网下载；
	// CI 或离线环境下下载失败会 panic，这里捕获并跳过，避免测试不稳定。
	defer func() {
		if r := recover(); r != nil {
			t.Skipf("GeoIP DB init failed, skip test: %v", r)
		}
	}()
	_ = InitGeoIpDB()

	ips := []string{
		"120.233.151.145",
		"103.142.141.201",
		"172.105.232.147",
	}

	for _, ip := range ips {
		t.Log(GeoIpDB.Find(ip))
	}
}
