# Changelog

本项目的所有重要变更都会记录在此文件中。

格式基于 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.0.0/)，
版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

## [v1.1.20] - 2026-08-16

### 🔒 安全修复

- 升级 `github.com/quic-go/quic-go` v0.59.0 → v0.61.0，修复 CVE-2026-40898（medium）
- 该库由 gin v1.12 的 HTTP/3 支持引入（`quic-go/quic-go/http3`），
  至此 Dependabot 报告的 25 个漏洞全部清除

## [v1.1.19] - 2026-08-16

### 🔧 CI/CD 优化

- **修复镜像构建不触发的严重 bug**：workflow 仅在 `branches: ['main']` 触发，
  但默认分支为 `master`，导致推送到 master 从不构建镜像；现同时监听 `master` + `main`
- 新增 `workflow_dispatch` 手动触发能力
- 新增 `concurrency` 控制：同一 ref 的重复触发自动取消旧任务，避免并发构建浪费
- 新增 `go vet` + `go test` 步骤，在构建前拦截代码质量问题
- 二进制编译改为并行（`make linux-amd64 &` + `make linux-armv8 &`），缩短构建时间
- 新增 `.dockerignore`：排除 `.git`(107MB)、`bin/` 旧产物(277MB)等，
  大幅缩减 Docker 构建上下文上传量
- 新增 `.github/dependabot.yml`：GitHub Actions 每周自动升级并生成可验证的 PR
- `actions/checkout` v4 → v5

### 🧪 测试

- 修复 `pkg/geoIp` 测试在 CI 上 panic 的问题：GeoIP 数据库缺失且联网下载失败时
  优雅 `t.Skip` 跳过，而非 panic 导致整个测试失败

## [v1.1.18] - 2026-08-16

### 🔒 安全修复

修复 Dependabot 报告的影响本分支（`ai`）的 3 个依赖漏洞：

| 依赖 | 变更 | 漏洞 |
| --- | --- | --- |
| golang.org/x/crypto | v0.50.0 → v0.55.0 | 13 个 CVE（7 critical / 2 high / 4 medium），含 CVE-2026-39830/39831/39832/39833/39834/42508/46595 等 |
| golang.org/x/net | v0.53.0 → v0.58.0 | CVE-2026-25680 |
| github.com/antchfx/xpath | v1.3.5 → v1.3.8 | CVE-2026-32287（high） |

说明：
- Dependabot 告警按默认分支（`master`）评估，其中 pgx/v5、go-retryablehttp 相关告警
  仅存在于 `master` 的依赖图，本分支不受影响
- 升级为间接依赖，与 mihomo 等上游要求（x/crypto ≥ v0.33、x/net ≥ v0.35）兼容

## [v1.1.17] - 2026-08-16

### 🚀 新增

- 新增 `progress` 并发安全进度统计助手：批量节点检测时每完成 10% 输出一条日志，
  替代旧实现中每个节点都向 stdout 刷屏的 `fmt.Printf`（并发下输出交错混乱）
- `pkg/healthcheck` 新增线程安全的 `ProxyStats` 访问 API（`FindStat` / `AppendStat` / `IncReqCount`）

### ⬆️ 依赖升级

| 依赖 | 变更 | 说明 |
| --- | --- | --- |
| github.com/gin-gonic/gin | v1.11.0 → v1.12.0 | Web 框架 |
| github.com/metacubex/mihomo | v1.19.20 → v1.19.29 | 核心代理引擎（连带升级大量传递依赖） |
| github.com/sirupsen/logrus | v1.9.4 → v1.10.0 | 日志 |
| gorm.io/gorm | v1.31.1 → v1.31.2 | ORM |
| github.com/arl/statsviz | v0.8.0 → v0.8.1 | 运行时可视化 |
| github.com/gin-contrib/cache | v1.4.1 → v1.4.4 | 页面缓存中间件 |
| github.com/gin-contrib/pprof | v1.5.3 → v1.5.4 | pprof 中间件 |
| github.com/heroku/x | v0.5.3 → v0.6.1 | Heroku 平台集成 |

**替换已停更/归档的依赖：**

- `github.com/ghodss/yaml`（已归档）→ `gopkg.in/yaml.v3`
- `github.com/patrickmn/go-cache`（已归档）→ 内部自研 `cacheStore`（RWMutex 实现，更轻量）
- `github.com/jasonlvhit/gocron`（2018 年停更）→ `github.com/go-co-op/gocron/v2`（活跃维护）
- `github.com/ivpusic/grpool`（停更）→ `gammazero/workerpool`，并删除全部 grpool 死代码
- `golang.org/x/exp/slices` → 标准库 `slices`（Go 1.21+ 已内置）

### 🐛 Bug 修复

- **`ClearOldItems` 清理功能从未生效**：gorm 的 `Delete` 返回 `*gorm.DB` 而非 `error`，
  原判断恒为真，导致超过一周的失效代理从未被清扫；现改为检查 `.Error` 与 `RowsAffected`
- **`SaveProxyList` 事务范围错误**：事务内使用 `DB` 而非 `tx`，操作未真正纳入事务；现已统一使用 `tx`
- **`/link/:id` 错误处理缺少 `return`**：参数非法或越界时仍继续执行，存在 panic 风险
- **测速结果记录逻辑恒真**：`err == nil || speed > 0` 等价于 `err == nil`，
  0 速度（白名单外/h2 节点）会被写入统计并污染排序；改为 `err == nil && speed > 0`
- **`NameAddIndex` 格式化错误**：`%+02v` → `%02d`，节点序号命名现在输出正确补零格式
- **`main.go` 格式串 vet 警告**：`log.Errorln(err.Error())` 将错误消息当作格式串，
  含 `%` 的错误消息会被错误解析；改为显式 `"%s"` 占位
- **`Update("useable", "false")` 字符串写入**：重置可用状态时写入字符串 `"false"`（SQLite 中为真值），
  现改为布尔值 `false`，配合清理逻辑生效

### 🔧 性能优化

- **数据库批量写入**：`SaveProxyList` 由逐条 `Create` + `Update` 循环改为
  `CreateInBatches` + `clause.OnConflict` 批量 upsert，SQL 往返次数大幅减少
- **`ReqCountThan` 复杂度 O(n×m) → O(n+m)**：改用 map 索引替代嵌套循环
- **`SortProxiesBySpeed` 冒泡排序 → `sort.SliceStable`**：O(n²) → O(n log n)，
  并预取速度记录避免比较器内线性查找
- **`pkg/healthcheck/util.go` 去重**：5 个几乎相同的 HTTP 代理请求函数合并为
  单一 `doViaProxy` 核心 + 薄封装；读完整响应体以支持连接复用
- **`rand.Shuffle` 简化**：Go 1.20+ 全局随机源自动播种，删除手动
  `rand.New(rand.NewSource(time.Now().UnixNano()))` 的重复构造
- **API 路由去重**：`/clash|/surge|/loon|/v2rayn/proxies` 四个 handler 中重复的
  参数解析/缓存/筛选逻辑收敛为统一的 `serveProxyList` 助手

### 🧵 并发安全修复

- **`ProxyStats` 全局统计竞态**：HTTP 请求（`provider.preFilter`）与爬取任务
  （延迟/测速/中转/ChatGPT 检测）会并发读写 `ProxyStats`，存在数据竞争；
  引入包级 `statsLock`（RWMutex）与线程安全 API，统一所有访问路径
- **各检测函数局部锁替换**：`delaycheck` / `speedcheck` / `relaycheck` /
  `openaicheck` 中的局部 `sync.Mutex` 统一改为包级 `statsLock`，
  修复 `Find` 在锁外、`UpdatePSSpeed`/`UpdatePSCount` 在锁外等竞态
- **非原子进度计数**：`doneCount++` / `fmt.Printf` 进度输出（数据竞争 + 输出乱码）
  替换为 `atomic.Int64` 驱动的 `progress` 助手

### 🧹 清理

- 删除死代码：grpool 版本的 `SpeedTestAll` / `SpeedTestNew` / `RelayCheck`、
  `CleanBadProxiesWithGrpool` 及大段注释代码
- 废弃 API 替换：`ioutil.ReadAll` / `ReadFile` / `WriteFile` → `io.ReadAll` / `os.ReadFile` / `os.WriteFile`
- 移除已替换依赖在 `go.mod` / `go.sum` 中的条目
- 变更规模：28 个文件，+701 / -1270 行（净减约 570 行）
