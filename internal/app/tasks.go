package app

import (
	"runtime"
	"sync"

	"github.com/One-Piecs/proxypool/config"
	"github.com/One-Piecs/proxypool/internal/cache"
	"github.com/One-Piecs/proxypool/log"
	"github.com/One-Piecs/proxypool/pkg/geoIp"
	"github.com/One-Piecs/proxypool/pkg/healthcheck"
	"github.com/One-Piecs/proxypool/pkg/provider"
	"github.com/One-Piecs/proxypool/pkg/proxy"
)

// taskGuard 互斥执行重负载任务：正在运行时新触发直接跳过，
// 避免 cron 定时任务与 API 手动触发并发抓取/测速相互干扰。
var taskGuard sync.Mutex

// RunExclusive 串行执行任务；已有任务在运行则跳过。返回是否实际执行。
func RunExclusive(name string, fn func()) bool {
	if !taskGuard.TryLock() {
		log.Warnln("Task [%s] skipped: another task is running", name)
		return false
	}
	defer taskGuard.Unlock()

	log.Infoln("Task [%s] started", name)
	defer log.Infoln("Task [%s] done", name)
	fn()
	// 大批代理对象释放后主动触发一次 GC，及时归还内存
	runtime.GC()
	return true
}

// CrawlTask 完整抓取任务（cron 与 API 共用）
func CrawlTask() {
	RunExclusive("crawl", func() {
		if err := InitConfigAndGetters(""); err != nil {
			log.Errorln("[task] config parse error: %s", err)
		}
		CrawlGo()
		Getters = nil
	})
}

// SpeedTestTask 全量测速任务
func SpeedTestTask() {
	RunExclusive("speedtest", func() {
		// 每次触发都重读配置（带 mtime 缓存，未变化零开销）：
		// 保证动态修改 config.yaml（如开启 speedtest）后能生效
		if err := config.Parse(""); err != nil {
			log.Errorln("[task] config parse error: %s", err)
		}
		pl := cache.GetProxies("proxies")
		SpeedTest(pl)
		RefreshProviderCache(pl)
	})
}

// ActiveSpeedTestTask 活跃节点高频测速任务
func ActiveSpeedTestTask() {
	RunExclusive("active-speedtest", func() {
		if err := config.Parse(""); err != nil {
			log.Errorln("[task] config parse error: %s", err)
		}
		plAll := cache.GetProxies("proxies")
		pl := healthcheck.ProxyStats.ReqCountThan(config.Config().ActiveFrequency, plAll, true)
		if len(pl) > int(config.Config().ActiveMaxNumber) {
			pl = healthcheck.ProxyStats.SortProxiesBySpeed(pl)[:config.Config().ActiveMaxNumber]
		}
		log.Infoln("Active proxies count: %d", len(pl))
		SpeedTest(pl)
		RefreshProviderCache(plAll)
	})
}

// BestNodeTask 抓取最佳节点
func BestNodeTask() {
	RunExclusive("best-node", func() {
		if err := config.Parse(""); err != nil {
			log.Errorln("[task] config parse error: %s", err)
			return
		}
		CrawlBestNode()
	})
}

// GeoIPTask 更新 GeoIP 数据库
func GeoIPTask() {
	RunExclusive("geoip-update", func() {
		geoIp.UpdateGeoIP()
	})
}

// RefreshProviderCache 更新各客户端静态订阅文本缓存
func RefreshProviderCache(pl proxy.ProxyList) {
	cache.SetString("clashproxies", provider.Clash{Base: provider.Base{Proxies: &pl}}.Provide())
	cache.SetString("surgeproxies", provider.Surge{Base: provider.Base{Proxies: &pl}}.Provide())
	cache.SetString("loonproxies", provider.Loon{Base: provider.Base{Proxies: &pl}}.Provide())
}
