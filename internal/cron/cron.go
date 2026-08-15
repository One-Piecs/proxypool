package cron

import (
	"runtime"
	"time"

	"github.com/One-Piecs/proxypool/config"
	"github.com/One-Piecs/proxypool/internal/app"
	"github.com/One-Piecs/proxypool/internal/cache"
	"github.com/One-Piecs/proxypool/log"
	"github.com/One-Piecs/proxypool/pkg/cdn"
	"github.com/One-Piecs/proxypool/pkg/geoIp"
	"github.com/One-Piecs/proxypool/pkg/healthcheck"
	"github.com/One-Piecs/proxypool/pkg/provider"
	"github.com/One-Piecs/proxypool/pkg/proxy"
	"github.com/go-co-op/gocron/v2"
)

// runtimeGC 在重负载任务结束后触发一次 GC，及时释放大批代理对象占用的内存
func runtimeGC() {
	runtime.GC()
}

// Cron 启动所有定时任务并阻塞当前 goroutine。
// 使用 go-co-op/gocron/v2 替代已停更的 github.com/jasonlvhit/gocron。
func Cron() {
	s, err := gocron.NewScheduler(gocron.WithLocation(time.Local))
	if err != nil {
		log.Errorln("[cron.go] create scheduler error: %s", err)
		return
	}

	cfg := config.Config()
	mustSchedule(s, time.Duration(cfg.CrawlInterval)*time.Minute, crawlTask)
	mustSchedule(s, time.Duration(cfg.SpeedTestInterval)*time.Minute, speedTestTask)
	mustSchedule(s, time.Duration(cfg.ActiveInterval)*time.Minute, frequentSpeedTestTask)
	mustSchedule(s, time.Duration(cfg.SubBestNodeInterval)*time.Minute, CrawlBestNodeTask)
	mustScheduleDaily(s, 4, 30, geoIp.UpdateGeoIP)
	mustScheduleDaily(s, 4, 35, geoIp.UpdateGeoIpASNDB)
	mustScheduleDaily(s, 4, 40, cdn.GlobalManager.Update)

	s.Start()
	// 阻塞主调用方，行为与原 gocron.Start() 一致
	select {}
}

// mustSchedule 按固定间隔注册任务，注册失败时记录日志（不中断其它任务）。
func mustSchedule(s gocron.Scheduler, interval time.Duration, fn any) {
	if _, err := s.NewJob(
		gocron.DurationJob(interval),
		gocron.NewTask(fn),
	); err != nil {
		log.Errorln("[cron.go] schedule task error: %s", err)
	}
}

// mustScheduleDaily 注册每天固定时间执行一次的任务。
func mustScheduleDaily(s gocron.Scheduler, hour, minute uint, fn any) {
	if _, err := s.NewJob(
		gocron.DailyJob(1, gocron.NewAtTimes(gocron.NewAtTime(hour, minute, 0))),
		gocron.NewTask(fn),
	); err != nil {
		log.Errorln("[cron.go] schedule daily task error: %s", err)
	}
}

func crawlTask() {
	err := app.InitConfigAndGetters("")
	if err != nil {
		log.Errorln("[cron.go] config parse error: %s", err)
	}
	app.CrawlGo()
	app.Getters = nil
	runtimeGC()
}

func speedTestTask() {
	log.Infoln("Doing speed test task...")
	err := config.Parse("")
	if err != nil {
		log.Errorln("[cron.go] config parse error: %s", err)
	}
	pl := cache.GetProxies("proxies")

	app.SpeedTest(pl)
	refreshProviderCache(pl)
	runtimeGC()
}

func frequentSpeedTestTask() {
	log.Infoln("Doing speed test task for active proxies...")
	err := config.Parse("")
	if err != nil {
		log.Errorln("[cron.go] config parse error: %s", err)
	}
	pl_all := cache.GetProxies("proxies")
	pl := healthcheck.ProxyStats.ReqCountThan(config.Config().ActiveFrequency, pl_all, true)
	if len(pl) > int(config.Config().ActiveMaxNumber) {
		pl = healthcheck.ProxyStats.SortProxiesBySpeed(pl)[:config.Config().ActiveMaxNumber]
	}
	log.Infoln("Active proxies count: %d", len(pl))

	app.SpeedTest(pl)
	refreshProviderCache(pl_all)
	runtimeGC()
}

func CrawlBestNodeTask() {
	log.Infoln("Doing CrawlBestNodeTask ...")
	err := config.Parse("")
	if err != nil {
		log.Errorln("[cron.go] config parse error: %s", err)
		return
	}
	app.CrawlBestNode()
	runtimeGC()
}

// refreshProviderCache 更新各客户端的静态订阅文本缓存
func refreshProviderCache(pl proxy.ProxyList) {
	cache.SetString("clashproxies", provider.Clash{
		Base: provider.Base{
			Proxies: &pl,
		},
	}.Provide()) // update static string provider
	cache.SetString("surgeproxies", provider.Surge{
		Base: provider.Base{
			Proxies: &pl,
		},
	}.Provide())
	cache.SetString("loonproxies", provider.Loon{
		Base: provider.Base{
			Proxies: &pl,
		},
	}.Provide())
}
