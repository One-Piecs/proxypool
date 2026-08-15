package database

import (
	"sync"
	"time"

	"github.com/gammazero/workerpool"

	"github.com/One-Piecs/proxypool/log"
	"github.com/One-Piecs/proxypool/pkg/proxy"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// 设置数据库字段，表名为默认为type名的复数。相比于原作者，不使用软删除特性
type Proxy struct {
	ID        uint `gorm:"primarykey"`
	CreatedAt time.Time
	UpdatedAt time.Time
	proxy.Base
	Link       string
	Identifier string `gorm:"unique"`
}

func InitTables() {
	if DB == nil {
		err := connect()
		if err != nil {
			return
		}
	}
	// Warnln: 自动迁移仅仅会创建表，缺少列和索引，并且不会改变现有列的类型或删除未使用的列以保护数据。
	// 如更改表的Column请于数据库中操作
	err := DB.AutoMigrate(&Proxy{})
	if err != nil {
		log.Errorln("\n\t\t[db/proxy.go] database migration failed")
		panic(err)
	}
}

// SaveProxyList 批量保存可用代理列表。
// 使用 clause.OnConflict 在唯一索引冲突时更新 useable/name/country，
// 替代原先逐条 Create+Update 的循环，显著减少 SQL 往返。
func SaveProxyList(pl proxy.ProxyList) {
	if DB == nil || pl.Len() == 0 {
		return
	}

	_ = DB.Transaction(func(tx *gorm.DB) error {
		// Set All Usable to false
		if err := tx.Model(&Proxy{}).Where("useable = ?", true).Update("useable", false).Error; err != nil {
			log.Warnln("database: Reset useable to false failed: %s", err.Error())
		}

		// 批量 Create or Update proxies
		records := make([]Proxy, 0, pl.Len())
		for i := 0; i < pl.Len(); i++ {
			p := Proxy{
				Base:       *pl[i].BaseInfo(),
				Link:       pl[i].Link(),
				Identifier: pl[i].Identifier(),
			}
			p.Useable = true
			records = append(records, p)
		}

		// 以 identifier 为唯一键做 upsert：冲突时更新 useable/name/country/link
		if err := tx.Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "identifier"}},
			DoUpdates: clause.AssignmentColumns([]string{"useable", "name", "country", "link", "updated_at"}),
		}).CreateInBatches(records, 500).Error; err != nil {
			log.Warnln("database: Batch upsert failed: %s", err.Error())
		}
		log.Infoln("database: Updated %d proxies", len(records))
		return nil
	})
}

// Get a proxy list consists of all proxies in database
func GetAllProxies() (proxies proxy.ProxyList) {
	proxies = make(proxy.ProxyList, 0)
	if DB == nil {
		return nil
	}

	proxiesDB := make([]Proxy, 0)
	// 同时取回 name/country：解析出来的节点默认 name 为空，
	// 启动加载阶段（首轮爬取完成前）会直接暴露给 /proxies 接口
	DB.Select("link, name, country").Find(&proxiesDB)

	wp := workerpool.New(100)
	m := sync.Mutex{}
	proxies = make(proxy.ProxyList, 0, len(proxiesDB))

	for _, proxyDB := range proxiesDB {
		pDB := proxyDB
		wp.Submit(func() {
			p, err := proxy.ParseProxyFromLink(pDB.Link)
			if err == nil && p != nil {
				p.SetUseable(false)
				// 恢复上次爬取时保存的名称与国家（避免启动窗口期 name 为空）
				if pDB.Name != "" {
					p.SetName(pDB.Name)
				}
				if pDB.Country != "" {
					p.SetCountry(pDB.Country)
				}
				m.Lock()
				proxies = append(proxies, p)
				m.Unlock()
			}
		})
	}
	wp.StopWait()
	return
}

// Clear proxies unusable more than 1 week
func ClearOldItems() {
	if DB == nil {
		return
	}
	lastWeek := time.Now().Add(-time.Hour * 24 * 7)
	// gorm 的 Delete 返回 *gorm.DB，用 .Error 判断执行是否成功
	res := DB.Where("updated_at < ? AND useable = ?", lastWeek, false).Delete(&Proxy{})
	if res.Error != nil {
		log.Warnln("database: Delete old item failed: %s", res.Error.Error())
		return
	}
	if res.RowsAffected > 0 {
		log.Infoln("database: Swept %d old and unusable proxies", res.RowsAffected)
	} else {
		log.Infoln("database: Nothing old to sweep")
	}
}
