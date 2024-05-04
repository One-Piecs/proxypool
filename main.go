package main

import (
	"flag"
	_ "net/http/pprof"
	"os"

	"github.com/google/gops/agent"

	"github.com/One-Piecs/proxypool/pkg/geoIp"

	"github.com/One-Piecs/proxypool/api"
	"github.com/One-Piecs/proxypool/internal/app"
	"github.com/One-Piecs/proxypool/internal/cron"
	"github.com/One-Piecs/proxypool/internal/database"
	"github.com/One-Piecs/proxypool/log"
)

var (
	configFilePath = ""
	debugMode      = false
	version        string
)

func main() {
	// go func() {
	//	http.ListenAndServe("0.0.0.0:6060", nil)
	// }()
	api.SetVersion(version)

	flag.StringVar(&configFilePath, "c", "", "path to config file: config.yaml")
	flag.BoolVar(&debugMode, "d", false, "debug output")
	flag.Parse()

	log.SetLevel(log.INFO)
	if debugMode {
		log.SetLevel(log.DEBUG)
	}

	if err := agent.Listen(agent.Options{Addr: "0.0.0.0:8848", ShutdownCleanup: true}); err != nil {
		log.Errorln(err.Error())
	}

	if configFilePath == "" {
		configFilePath = os.Getenv("CONFIG_FILE")
	}
	if configFilePath == "" {
		configFilePath = "config.yaml"
	}
	err := app.InitConfigAndGetters(configFilePath)
	if err != nil {
		log.Errorln("Configuration init error: %s", err.Error())
		panic(err)
	}

	database.InitTables()
	// init GeoIp db reader and map between emoji's and countries
	// return: struct geoIp (dbreader, emojimap)
	err = geoIp.InitGeoIpDB()
	if err != nil {
		os.Exit(1)
	}
	log.Infoln("Do the first crawl...")
	go app.CrawlGo()            // 抓取主程序
	go cron.Cron()              // 定时运行
	go cron.CrawlBestNodeTask() // 抓取最佳节点
	api.Run()                   // Web Serve
}
