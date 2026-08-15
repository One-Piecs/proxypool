# Changelog

本项目的所有重要变更都会记录在此文件中。

格式基于 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.0.0/)，
版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

## [v1.1.35] - 2026-08-16

### 🐛 修复 /loon|/surge/proxies 的 vless 输出为空

- v1.1.31 新增 vless 时漏改 `checkLoonSupport` / `checkSurgeSupport`：
  两个校验函数没有 vless 分支，导致 vless 节点被 Loon / Surge 输出排除，
  `/loon/proxies?type=vless`、`/surge/proxies?type=vless` 返回空
- 修复：两个校验函数补充 `case *proxy.Vless: return true`
  （vless 类型自身已有 ToLoon / ToSurge 实现）
- 新增回归测试：`TestVlessSupport` 覆盖 clash/loon/surge/quanx 四个校验函数

## [v1.1.34] - 2026-08-16

### 🐛 静默 mihomo 内部日志噪音

- 健康检查/测速时 mihomo 内部（如 vless vision 握手失败）会把 ERROR 级日志
  （`XTLS Vision server responded unknown UUID`、`vision: not a valid...`）
  刷到应用日志——mihomo 与应用此前共用 logrus **默认 logger**
- 修复：应用改用**独立 logrus 实例**，默认 logger 输出丢弃（`io.Discard`）；
  应用日志不受影响，第三方库内部噪音全部静默
- 这些错误本身是无效/过期节点的正常检测信号（节点会被健康检查过滤），
  但大量节点检测时噪音可观，隔离后日志干净
- 新增回归测试：默认 logger 输出已丢弃、应用日志正常

## [v1.1.33] - 2026-08-16

### 🚀 新增 /loon /quanx 页面与 QuanX 输出

- **新增页面**：`/loon`、`/quanx`（与 /clash /surge 同风格，含节点列表订阅入口）
- **新增 `ToQuanX()`**：ss / ssr / vmess / trojan / vless 五种类型的 QuanX 格式输出
  （`vmess = host:port, method=..., password=..., obfs=wss, ...`）
- **新增 QuanX provider**：`/quanx/proxies` 接口（支持现有全部筛选参数）
- 所有页面导航栏增加 Loon / QuanX 入口（6 个页面同步）
- 新增 ToQuanX 输出单元测试

## [v1.1.32] - 2026-08-16

### 🎨 页面与文档同步 vless

- `/clash` 页面：meta 描述、type 筛选值表格增加 vless
- `/surge`、`/shadowrocket` 页面：meta 描述增加 vless
- `index.html`：订阅表格改用专用 `/vless/sub` 入口（原 clash 筛选链接）
- README 协议描述增加 vless
- **新增 `/vless/sub` 订阅接口**：`VlessSub` provider，base64 编码的 vless:// 链接列表
  （与 vmess/sub 同模式）

## [v1.1.31] - 2026-08-16

### 🚀 新增 vless 协议支持

- **新增 `pkg/proxy/vless.go`**：Vless 类型 + 链接解析/生成
  （`vless://uuid@host:port?...`）、三端输出（Clash/Surge/Loon）、去重标识
- **解析入口接入**：`ParseProxyFromLink` / `ParseProxyFromClashProxy`
  （含 clash 配置 `ws-opts` 嵌套结构兼容）
- **抓取接入**：`GrepLinksFromString` 支持 vless 链接（正则要求 `uuid@host:port` 结构，
  避免把普通文本误抓为链接）
- **健康检查/测速接入**：`ToClashMap` 输出 mihomo 所需键名（`ws-opts`/`servername`/
  `client-fingerprint`/`flow` 等），已验证 mihomo 可解析 ws+tls / tcp / reality+flow 三种变体
- **Clash 支持校验**：`checkClashSupport` 放行 vless（mihomo 原生支持，无加密白名单限制）
- **统计与首页**：`TypeCounts`/缓存变量/首页模板增加 vless 计数与订阅入口
- 新增 5 个单元测试（往返解析、ws 参数、三端输出、链接抓取、clash 配置兼容、mihomo 解析）

## [v1.1.30] - 2026-08-16

### 🐛 修复健康检查 done 通道二次关闭 panic

- `CleanBadProxiesWithWorkpool`：`done` 通道既被 goroutine `close(done)`
  （StopWait 完成后）又被 `defer close(done)` 关闭，健康检查正常完成、
  循环经 done 分支返回时触发 `close of closed channel` panic
- 之前未暴露的原因：v1.1.26 修复前的 nil 指针 bug 先 panic，掩盖了此问题；
  nil 修复后健康检查能完整跑完（9426/9426），二次关闭立即暴露
- 修复：移除 `defer close(done)`，done 仅由 goroutine 单一关闭
- 新增空列表回归测试：空列表不提交任务，StopWait 立即返回并 close(done)，
  旧实现必然二次关闭 panic（无需网络即可复现）

## [v1.1.29] - 2026-08-16

### 🐛 修复测速任务未重读配置（回归）

- v1.1.23 把任务收敛到 `internal/app` 时，`SpeedTestTask` / `ActiveSpeedTestTask`
  丢失了原先 cron 中的 `config.Parse("")` 调用
- 后果：动态修改 `config.yaml`（如开启 `speedtest: true`）后，测速定时器触发时
  读到的仍是启动时的旧配置，开关不生效
- 修复：两个测速任务每次触发先重读配置（mtime 缓存，未变化零开销）

> 注：定时任务的**间隔**在启动时固化（`cron.Cron()` 读取一次），
> 修改 `crawl-interval` / `speedtest-interval` 等需重启进程；
> 开关类配置（如 `speedtest`）随任务触发热加载，或手动 `GET /task/speedtest` 立即生效

## [v1.1.28] - 2026-08-16

### 🐛 修复 /proxies 接口节点名缺失

- **`GetAllProxies` 恢复数据库保存的 name/country**：原先只取 `link` 字段重新解析，
  启动加载阶段（首轮爬取完成前）`cache.SetProxies("proxies", dbProxies)` 里的节点
  全部是空名称，导致 `/loon|surge|clash/proxies` 输出 ` = Shadowsocks,...`（name 缺失）
- **修复 `ParseProxyFromLink` 的 GeoIP 错误泄漏 bug**：GeoIP 查询失败时错误原样返回，
  导致 `GetAllProxies` 的 `if err == nil` 把解析成功的节点全部丢弃；
  现 GeoIP 仅用于补充国家信息（失败用 `🏁 ZZ` 默认值），不再否决节点
- 新增数据库回归测试：验证加载时恢复 name/country、解析字段正确

## [v1.1.27] - 2026-08-16

### ⚡ 站点缓存优化

- **带 `random=true` 的请求（`/bestProxyIp`、`/bestIpKr` 随机打乱节点）跳过缓存**：
  否则 1 分钟内多次调用会返回完全相同的随机排列，失去随机语义
- **缓存 key 改用 `URL.RequestURI()` 重建**（含 query）：不依赖服务端填充的
  `RequestURI` 字段，httptest 等场景也能正确区分不同请求，避免 key 塌缩
- 测试补充：random=true 绕过缓存、无 random 参数仍被缓存、不同路径 key 独立

## [v1.1.26] - 2026-08-16

### 🐛 修复健康检查 nil 指针 panic

- **修复 `CleanBadProxiesWithWorkpool` 的变量遮蔽 bug（严重）**：v1.1.22 重写时把
  `c <- ps` 移到 if/else 外，但 if 语句的 `:=` 声明了遮蔽外层的新 `ps`，
  两个分支赋值的是内层变量，channel 实际发送的是外层 nil 指针，
  接收端 `ps.Delay` 触发 `invalid memory address or nil pointer dereference`，
  首次爬取健康检查阶段即崩溃
- 修复方式：find-or-create 逻辑提取为 `findOrCreateDelayStat`（锁内查找/创建，
  保证返回非 nil），worker 发送其返回值
- 新增回归测试 `TestFindOrCreateDelayStat`：验证首次创建/二次命中更新均返回非 nil

## [v1.1.25] - 2026-08-16

### 🐛 修复订阅源抓取超时

- `CrawlBestNode` 订阅源请求超时 30s → **60s**：v1.1.24 引入共享 resty 客户端时
  设置 30s 超时（原实现无超时会无限挂起），但部分海外订阅源响应较慢，
  30s 偏紧导致 `context deadline exceeded`；60s 在防挂死与容错间取得平衡
- 重试退避 1s/2s → **2s/4s**：超时后给慢源更多恢复时间，避免立即重试再次超时

## [v1.1.24] - 2026-08-16

### ⚡ internal/app 优化

- **5 份重复的 URL 生成器 15 分支 switch 收敛**：`generatorKey(f)` + 两张生成器表
  （6 参 / 7 参），原先每个 SubNice* 函数各内联一份
- **`SubNiceCfProxyIp` / `SubNiceCfProxyIpTop20` / `SubNiceCfProxyIpProvider`
  收敛为薄封装**：共用 `buildNodeOutput`，每个由 ~110 行缩至 ~25 行
- **公共逻辑提取**：`loadProxyInfo`（5 份 copier.Copy）、`writeOutputHeader`（5 份头部）、
  `finishOutput`（4 份 V2rayn base64）、`trackDuration`（5 份 defer 计时）
- **`CrawlBestNode`**：`resty.New()` 每请求创建 → 包级共享客户端（含 TLS 跳过校验/UA/超时）；
  三处手写补端口 → `normalizeAddr`（顺带修复裸 IPv6 无方括号的隐患）；
  两处手写 host:port 拆分 → `splitHostPort`（net.SplitHostPort 正确支持 IPv6）
- **`CfIpProvider` 去重**：4 个相同匿名 struct + fetchCfIpProvider 中重复的 1 份 → 命名类型 `cfIpItem`
- **单次遍历统计类型数量**：新增 `ProxyList.TypeCounts()`，替代 8 次 `TypeLen` 的 O(8n) 扫描
- **`CrawlGo` 末尾复用 `RefreshProviderCache`**，删除内联的三份 provider 刷新
- 删除死代码 `removeDuplicateElement`、`filterIpCountry`
- `internal/app` 净减约 620 行（1696 → 1159 行的核心文件）

## [v1.1.23] - 2026-08-16

### ⚡ API 路由与配置加载优化

- **`config.Parse` 加缓存**：本地文件按 mtime 判断是否变化（保留热更新），
  http(s) 源按 60s TTL 刷新。原先 `/best*` 接口每次请求都重新读文件/网络 + YAML 解析，
  URL 配置源则每次请求都发 HTTP GET；现未变化时零开销
- **修复站点缓存中间件**：gin-contrib/cache 的 `SiteCache` 只读不写（从不填充缓存，
  等价于空操作）；改为自实现中间件——未命中时包装 ResponseWriter 记录 2xx 响应，
  命中时直接回放，HTML 页面/订阅接口获得真实 1 分钟 HTTP 缓存
- **触发类接口排除缓存**：`/task/*`、`/health`、`/link/`、`/debug/*` 跳过响应缓存，
  确保手动触发任务/健康检查/动态链接不被缓存拦截
- **7 个 `/best*` handler 收敛**：统一 `bestIPHandler`（配置加载+错误处理）、
  `parseBestIPParams`（d 默认 JP）、`isTrue`（"true"/"1"）辅助函数，
  每个 handler 由 ~50 行缩至 3-6 行
- **5 个 `/xx/sub` handler 收敛**为 `subHandler` 一行式注册
- **任务统一收敛 `internal/app`**：`CrawlTask`/`SpeedTestTask`/`ActiveSpeedTestTask`/
  `BestNodeTask`/`GeoIPTask` 供 cron 与 API 共用，消除重复逻辑；
  `RunExclusive` 互斥防并发——任务运行中再次触发直接跳过（日志提示），
  避免 cron 与手动触发并发抓取/测速
- `/task/*` handler 不再各自重复 `runtime.GC()`（收敛到 RunExclusive）
- 新增单元测试：`config.Parse` 缓存命中/失效、站点缓存命中/排除

## [v1.1.22] - 2026-08-16

### 🔧 CI/CD

- Docker 构建改为**仅 tag 推送自动触发**；master/main 分支改为手工触发（`workflow_dispatch`）

### ⚡ 健康检查与测速优化

- **消除 JSON 往返转换**：新增 `proxy.ToClashMap()` 直接由结构体构造 mihomo 配置 map，
  替代健康检查/测速/中转检测中每次的 `String()`→`json.Unmarshal`，
  并新增等价性单元测试（与旧行为 JSON 形态完全一致）
- **延迟检测减少无效请求**：每轮重试最多尝试 4 个测试 URL（原 10 个），
  健康代理仍 2 个成功即返回，失效代理判定时间大幅缩短
- **测速服务器列表缓存**：speedtest 静态服务器 XML（~100KB）缓存 1 小时，
  避免每个代理重复下载；取列表/用户接口超时 5s → 15s，慢代理不再下载不完直接失败
- **用户位置获取失败降级**：原先直接判定测速失败，现退化为使用服务器列表前 3 个，
  不再因 config 接口被墙而整批测速失败
- **合并重复测速函数**：`SpeedTestAllWithWorkpool` 与 `SpeedTestNewWithWorkpool`
  收敛为单一实现（newOnly 参数区分）

## [v1.1.21] - 2026-08-16

### ⚡ GeoIP 数据库处理优化

- **本地持久化**：Country.mmdb 下载后落盘 + 版本号写入 `assets/version`，
  重启直接本地加载（秒开），不再每次启动重复下载 40MB 到内存
- **修复版本追踪 bug**：原实现本地文件模式版本号为空，cron 的 `UpdateGeoIP` 永远跳过更新检查；
  现每次启动读取本地版本，每日 cron 与远程比对，有更新才下载
- **修复并发竞态**：`UpdateGeoIP`/`UpdateGeoIpASNDB` 原实现直接替换 `GeoIpDB.db` 并立即
  Close 旧 reader，与进行中的 `Find`/`GetASN` 冲突；改用 `atomic.Pointer` 原子替换 + 延迟关闭
- **下载超时**：原裸 `http.Client{}` 无超时、失败即 panic；现统一 30s/10s 超时客户端，失败返回错误
- **修复 ASN 库下载源**：`git.io` 短链已被 GitHub 停用且不稳定，改用 GitHub Release 直连地址
- **启动不再强制下载 ASN 库**：本地已有则直接加载，仅缺失时才下载
- **ip-api.com fallback 防限流**：加 TTL 缓存（成功 24h / 失败 5min）+ 串行化查询 + 5s 超时，
  避免代理池大量查询触发 429
- **`Find` 微优化**：纯 IP 入参直接解析跳过 DNS 查询；国家名拼接用字符串连接替代 `fmt.Sprintf`
- `IsCDN` 关键词表大写预编译；删除死代码 `ReInitGeoIpDB`/`GeoIpBinary`/`GeoIpVersion`
- 新增 5 个单元测试（emoji 映射 / 原子写文件 / 无库容错 / 非法输入 / 关键词覆盖）

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

## [v1.1.38] - 2026-08-16

### 🚀 补全 vless Reality 与 grpc 传输支持

- **Reality**：解析 `security=reality` 的 `pbk`(public-key) / `sid`(short-id) /
  `spiderX` 参数；`Link()` 生成时 security 标记为 reality 并带回参数；
  Clash 输出 / mihomo 映射输出 `reality-opts:{public-key, short-id}`
- **grpc 传输**：解析 `type=grpc` 的 `serviceName`(兼容 `service_name`)；
  Clash 输出 / mihomo 映射输出 `grpc-opts:{grpc-service-name}`；
  Loon / QuanX 输出 grpc-service-name
- 新增测试：reality 解析/生成往返、grpc 解析/生成往返、
  mihomo 解析 4 种变体（ws+tls / tcp / reality+flow / grpc+tls，reality 公钥运行时生成保证合法）

## [v1.1.37] - 2026-08-16

### 🐛 Surge 不支持 vless，撤销 surge 输出

- Surge 客户端官方仅支持 ss/ssr/vmess/trojan/http/socks5 等，**不支持 vless 协议**；
  v1.1.35 误在 `checkSurgeSupport` 放行 vless，导致 `/surge/proxies` 输出 Surge
  无法使用的 vless 节点
- 修复：移除 `checkSurgeSupport` 的 vless 分支（恢复为不支持），
  `/surge/proxies?type=vless` 返回空为**正确行为**
- 更新回归测试：surge 断言为拒绝 vless，clash/loon/quanx 仍放行

## [v1.1.36] - 2026-08-16

### 🐛 紧急修复：v1.1.33 破坏全部 HTML 页面

- v1.1.33 用正则脚本批量改导航栏时，`src = group(1) + nav_new + group(3)`
  先把文件覆盖成导航栏碎片，又执行了一次正则替换，导致 **6 个页面全部被压成
  9 行坏文件**（index/clash/surge/shadowrocket 在 v1.1.33 被提交为坏版本；
  loon/quanx 因 .gitignore 的 `config/*` 规则从未入库）
- 修复：从 v1.1.32 恢复 4 个页面（保留 vless 相关修改），用**精确字符串替换**
  重新加入 Loon/QuanX 导航，重新生成 loon.html / quanx.html
- 修复 .gitignore：`config/*` 宽泛规则改为明确忽略 yaml/crt/key/ini，
  放行 `config/assets/html/*.html` 与 `static/index.js`（页面模板必须入库），
  补回 `proxypool*`、`data`、mmdb 忽略
- 验证：6 个页面全部 200 渲染、结构完整（doctype/html/nav/footer 齐全）、
  导航含 Loon/QuanX
