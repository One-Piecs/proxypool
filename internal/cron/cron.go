package cron

import (
	"time"

	"github.com/One-Piecs/proxypool/config"
	"github.com/One-Piecs/proxypool/internal/app"
	"github.com/One-Piecs/proxypool/log"
	"github.com/One-Piecs/proxypool/pkg/cdn"
	"github.com/One-Piecs/proxypool/pkg/geoIp"
	"github.com/go-co-op/gocron/v2"
)

// Cron 启动所有定时任务并阻塞当前 goroutine。
// 任务实现统一收敛在 internal/app（带互斥防并发），此处仅负责调度。
func Cron() {
	s, err := gocron.NewScheduler(gocron.WithLocation(time.Local))
	if err != nil {
		log.Errorln("[cron.go] create scheduler error: %s", err)
		return
	}

	cfg := config.Config()
	mustSchedule(s, time.Duration(cfg.CrawlInterval)*time.Minute, app.CrawlTask)
	mustSchedule(s, time.Duration(cfg.SpeedTestInterval)*time.Minute, app.SpeedTestTask)
	mustSchedule(s, time.Duration(cfg.ActiveInterval)*time.Minute, app.ActiveSpeedTestTask)
	mustSchedule(s, time.Duration(cfg.SubBestNodeInterval)*time.Minute, app.BestNodeTask)
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
