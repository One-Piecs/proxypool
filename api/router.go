package api

import (
	"html/template"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"time"

	"github.com/One-Piecs/proxypool/log"
	"github.com/One-Piecs/proxypool/pkg/geoIp"
	"github.com/One-Piecs/proxypool/pkg/provider"

	"github.com/One-Piecs/proxypool/internal/app"
	// "github.com/One-Piecs/proxypool/internal/bindata"
	"github.com/arl/statsviz"

	"github.com/One-Piecs/proxypool/config"
	appcache "github.com/One-Piecs/proxypool/internal/cache"
	"github.com/gin-contrib/cache"
	"github.com/gin-contrib/cache/persistence"
	"github.com/gin-contrib/pprof"
	"github.com/gin-gonic/gin"
	_ "github.com/heroku/x/hmetrics/onload"
)

var (
	version string
	router  *gin.Engine
)

func SetVersion(v string) {
	version = v
}

func setupRouter() {
	gin.SetMode(gin.ReleaseMode)
	router = gin.New()              // 没有任何中间件的路由
	temp, err := loadHTMLTemplate() // 加载html模板，模板源存放于html.go中的类似_assetsHtmlSurgeHtml的变量
	if err != nil {
		panic(err)
	}
	router.SetHTMLTemplate(temp) // 应用模板

	store := persistence.NewInMemoryStore(time.Minute)
	router.Use(gin.Recovery(), cache.SiteCache(store, time.Minute)) // 加上处理panic的中间件，防止遇到panic退出程序

	// router.Use(gin.Recovery())
	pprof.Register(router)
	router.GET("/debug/statsviz/*filepath", func(context *gin.Context) {
		if context.Param("filepath") == "/ws" {
			statsviz.Ws(context.Writer, context.Request)
			return
		}
		statsviz.IndexAtRoot("/debug/statsviz").ServeHTTP(context.Writer, context.Request)
	})

	// router.StaticFS("/static", http.FS(config.StaticFS))

	router.GET("/static/index.js", func(c *gin.Context) {
		c.Header("Content-Type", "text/javascript")
		data, _ := config.StaticFS.ReadFile("assets/static/index.js")
		c.String(200, string(data))
	})

	router.GET("/", func(c *gin.Context) {
		c.HTML(http.StatusOK, "index.html", gin.H{
			"domain":                      config.Config.Domain,
			"getters_count":               appcache.GettersCount,
			"all_proxies_count":           appcache.AllProxiesCount,
			"ss_proxies_count":            appcache.SSProxiesCount,
			"ssr_proxies_count":           appcache.SSRProxiesCount,
			"vmess_proxies_count":         appcache.VmessProxiesCount,
			"trojan_proxies_count":        appcache.TrojanProxiesCount,
			"useful_proxies_count":        appcache.UsefullProxiesCount,
			"useful_ss_proxies_count":     appcache.UsefullSSProxiesCount,
			"useful_ssr_proxies_count":    appcache.UsefullSSRProxiesCount,
			"useful_vmess_proxies_count":  appcache.UsefullVmessProxiesCount,
			"useful_trojan_proxies_count": appcache.UsefullTrojanProxiesCount,
			"last_crawl_time":             appcache.LastCrawlTime,
			"is_speed_test":               appcache.IsSpeedTest,
			"version":                     version,
			"geo_ip_db_version":           geoIp.GeoIpDBCurVersion,
		})
	})

	router.GET("/clash", func(c *gin.Context) {
		c.HTML(http.StatusOK, "clash.html", gin.H{
			"domain": config.Config.Domain,
			"port":   config.Config.Port,
		})
	})

	router.GET("/surge", func(c *gin.Context) {
		c.HTML(http.StatusOK, "surge.html", gin.H{
			"domain": config.Config.Domain,
		})
	})

	router.GET("/shadowrocket", func(c *gin.Context) {
		c.HTML(http.StatusOK, "shadowrocket.html", gin.H{
			"domain": config.Config.Domain,
		})
	})

	router.GET("/clash/config", func(c *gin.Context) {
		c.HTML(http.StatusOK, "clash-config.yaml", gin.H{
			"domain": config.Config.Domain,
		})
	})
	router.GET("/clash/localconfig", func(c *gin.Context) {
		c.HTML(http.StatusOK, "clash-config-local.yaml", gin.H{
			"port": config.Config.Port,
		})
	})

	router.GET("/surge/config", func(c *gin.Context) {
		c.HTML(http.StatusOK, "surge.conf", gin.H{
			"domain": config.Config.Domain,
		})
	})

	router.GET("/clash/proxies", func(c *gin.Context) {
		proxyTypes := c.DefaultQuery("type", "")
		proxyCountry := c.DefaultQuery("c", "")
		proxyNotCountry := c.DefaultQuery("nc", "")
		proxySpeed := c.DefaultQuery("speed", "")
		proxyFilter := c.DefaultQuery("filter", "")
		text := ""
		if proxyTypes == "" && proxyCountry == "" && proxyNotCountry == "" && proxySpeed == "" && proxyFilter == "" {
			text = appcache.GetString("clashproxies") // A string. To show speed in this if condition, this must be updated after speedtest
			if text == "" {
				proxies := appcache.GetProxies("proxies")
				clash := provider.Clash{
					Base: provider.Base{
						Proxies: &proxies,
					},
				}
				text = clash.Provide() // 根据Query筛选节点
				appcache.SetString("clashproxies", text)
			}
		} else if proxyTypes == "all" {
			proxies := appcache.GetProxies("allproxies")
			clash := provider.Clash{
				Base: provider.Base{
					Proxies:    &proxies,
					Types:      proxyTypes,
					Country:    proxyCountry,
					NotCountry: proxyNotCountry,
					Speed:      proxySpeed,
					Filter:     proxyFilter,
				},
			}
			text = clash.Provide() // 根据Query筛选节点
		} else {
			proxies := appcache.GetProxies("proxies")
			clash := provider.Clash{
				Base: provider.Base{
					Proxies:    &proxies,
					Types:      proxyTypes,
					Country:    proxyCountry,
					NotCountry: proxyNotCountry,
					Speed:      proxySpeed,
					Filter:     proxyFilter,
				},
			}
			text = clash.Provide() // 根据Query筛选节点
		}
		c.String(200, text)
	})
	router.GET("/surge/proxies", func(c *gin.Context) {
		proxyTypes := c.DefaultQuery("type", "")
		proxyCountry := c.DefaultQuery("c", "")
		proxyNotCountry := c.DefaultQuery("nc", "")
		proxySpeed := c.DefaultQuery("speed", "")
		proxyFilter := c.DefaultQuery("filter", "")
		text := ""
		if proxyTypes == "" && proxyCountry == "" && proxyNotCountry == "" && proxySpeed == "" && proxyFilter == "" {
			text = appcache.GetString("surgeproxies") // A string. To show speed in this if condition, this must be updated after speedtest
			if text == "" {
				proxies := appcache.GetProxies("proxies")
				surge := provider.Surge{
					Base: provider.Base{
						Proxies: &proxies,
					},
				}
				text = surge.Provide()
				appcache.SetString("surgeproxies", text)
			}
		} else if proxyTypes == "all" {
			proxies := appcache.GetProxies("allproxies")
			surge := provider.Surge{
				Base: provider.Base{
					Proxies:    &proxies,
					Types:      proxyTypes,
					Country:    proxyCountry,
					NotCountry: proxyNotCountry,
					Speed:      proxySpeed,
					Filter:     proxyFilter,
				},
			}
			text = surge.Provide()
		} else {
			proxies := appcache.GetProxies("proxies")
			surge := provider.Surge{
				Base: provider.Base{
					Proxies:    &proxies,
					Types:      proxyTypes,
					Country:    proxyCountry,
					NotCountry: proxyNotCountry,
					Speed:      proxySpeed,
					Filter:     proxyFilter,
				},
			}
			text = surge.Provide()
		}
		c.String(200, text)
	})

	router.GET("/loon/proxies", func(c *gin.Context) {
		proxyTypes := c.DefaultQuery("type", "")
		proxyCountry := c.DefaultQuery("c", "")
		proxyNotCountry := c.DefaultQuery("nc", "")
		proxySpeed := c.DefaultQuery("speed", "")
		proxyFilter := c.DefaultQuery("filter", "")
		text := ""
		if proxyTypes == "" && proxyCountry == "" && proxyNotCountry == "" && proxySpeed == "" && proxyFilter == "" {
			text = appcache.GetString("loonproxies") // A string. To show speed in this if condition, this must be updated after speedtest
			if text == "" {
				proxies := appcache.GetProxies("proxies")
				loon := provider.Loon{
					Base: provider.Base{
						Proxies: &proxies,
					},
				}
				text = loon.Provide() // 根据Query筛选节点
				appcache.SetString("loonproxies", text)
			}
		} else if proxyTypes == "all" {
			proxies := appcache.GetProxies("allproxies")
			loon := provider.Loon{
				Base: provider.Base{
					Proxies:    &proxies,
					Types:      proxyTypes,
					Country:    proxyCountry,
					NotCountry: proxyNotCountry,
					Speed:      proxySpeed,
					Filter:     proxyFilter,
				},
			}
			text = loon.Provide() // 根据Query筛选节点
		} else {
			proxies := appcache.GetProxies("proxies")
			loon := provider.Loon{
				Base: provider.Base{
					Proxies:    &proxies,
					Types:      proxyTypes,
					Country:    proxyCountry,
					NotCountry: proxyNotCountry,
					Speed:      proxySpeed,
					Filter:     proxyFilter,
				},
			}
			text = loon.Provide() // 根据Query筛选节点
		}
		c.String(200, text)
	})

	router.GET("/ss/sub", func(c *gin.Context) {
		proxies := appcache.GetProxies("proxies")
		ssSub := provider.SSSub{
			Base: provider.Base{
				Proxies: &proxies,
				Types:   "ss",
			},
		}
		c.String(200, ssSub.Provide())
	})
	router.GET("/ssr/sub", func(c *gin.Context) {
		proxies := appcache.GetProxies("proxies")
		ssrSub := provider.SSRSub{
			Base: provider.Base{
				Proxies: &proxies,
				Types:   "ssr",
			},
		}
		c.String(200, ssrSub.Provide())
	})
	router.GET("/vmess/sub", func(c *gin.Context) {
		proxies := appcache.GetProxies("proxies")
		vmessSub := provider.VmessSub{
			Base: provider.Base{
				Proxies: &proxies,
				Types:   "vmess",
			},
		}
		c.String(200, vmessSub.Provide())
	})
	router.GET("/sip002/sub", func(c *gin.Context) {
		proxies := appcache.GetProxies("proxies")
		sip002Sub := provider.SIP002Sub{
			Base: provider.Base{
				Proxies: &proxies,
				Types:   "ss",
			},
		}
		c.String(200, sip002Sub.Provide())
	})
	router.GET("/trojan/sub", func(c *gin.Context) {
		proxies := appcache.GetProxies("proxies")
		trojanSub := provider.TrojanSub{
			Base: provider.Base{
				Proxies: &proxies,
				Types:   "trojan",
			},
		}
		c.String(200, trojanSub.Provide())
	})
	router.GET("/link/:id", func(c *gin.Context) {
		idx := c.Param("id")
		proxies := appcache.GetProxies("allproxies")
		id, err := strconv.Atoi(idx)
		if err != nil {
			c.String(500, err.Error())
		}
		if id >= proxies.Len() || id < 0 {
			c.String(500, "id out of range")
		}
		c.String(200, proxies[id].Link())
	})

	router.GET("/task/crawl", func(c *gin.Context) {
		go func() {
			err := app.InitConfigAndGetters("")
			if err != nil {
				log.Errorln("config parse error: %s", err)
			}
			app.CrawlGo()
			app.Getters = nil
			runtime.GC()
		}()
		c.String(200, "ok")
	})

	router.GET("/task/speedtest", func(c *gin.Context) {
		go func() {
			log.Infoln("Doing speed test task...")
			err := config.Parse("")
			if err != nil {
				log.Errorln("config parse error: %s", err)
			}
			pl := appcache.GetProxies("proxies")

			app.SpeedTest(pl)
			appcache.SetString("clashproxies", provider.Clash{
				Base: provider.Base{
					Proxies: &pl,
				},
			}.Provide()) // update static string provider
			appcache.SetString("surgeproxies", provider.Surge{
				Base: provider.Base{
					Proxies: &pl,
				},
			}.Provide())
			appcache.SetString("loonproxies", provider.Loon{
				Base: provider.Base{
					Proxies: &pl,
				},
			}.Provide())
			runtime.GC()
		}()
		c.String(200, "ok")
	})

	router.GET("/task/updateGeoIP", func(c *gin.Context) {
		go func() {
			log.Infoln("Reloading GeoIP...")
			// geoIp.ReInitGeoIpDB()
			geoIp.UpdateGeoIP()
			runtime.GC()
		}()
		c.String(200, "ok")
	})

	router.GET("/bestProxyIp/:format", func(c *gin.Context) {
		format := c.Param("format")
		country := c.Query("c")
		if country == "" {
			country = "JP"
		}
		text, err := app.SubNiceProxyIp2(format, country)
		if err != nil {
			c.String(500, err.Error())
			return
		}
		c.String(200, text)
	})

	router.GET("/bestIpKr/:format", func(c *gin.Context) {
		format := c.Param("format")
		text, err := app.SubNiceProxyIp2(format, "KR")
		if err != nil {
			c.String(500, err.Error())
			return
		}
		c.String(200, text)
	})
}

func Run() {
	setupRouter()
	servePort := config.Config.Port
	envp := os.Getenv("PORT") // environment port for heroku app
	if envp != "" {
		servePort = envp
	}
	// Run on this server
	var err error
	if config.Config.TLSEnable {
		err = router.RunTLS(":"+servePort, config.Config.CertFile, config.Config.KeyFile)
	} else {
		err = router.Run(":" + servePort)
	}

	if err != nil {
		log.Errorln("router: Web server starting failed. Make sure your port %s has not been used. \n%s", servePort, err.Error())
	} else {
		log.Infoln("Proxypool is serving on port: %s", servePort)
	}
}

// 返回页面templates
func loadHTMLTemplate() (t *template.Template, err error) {
	t, err = template.New("").ParseFS(config.HtmlFs, "assets/html/*")
	return
}
