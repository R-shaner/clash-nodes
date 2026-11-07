# clash-nodes：每小时自动发现、测试并更新的 Clash 订阅

不需要手动填订阅源。GitHub Actions 每小时跑一次：

```
GitHub 搜索最近有更新的节点仓库 → 挑出疑似订阅文件 → 抓取
  → 解析(ss/vmess/vless/trojan/hysteria2) → 去重
  → TCP 预筛 → mihomo 延迟测试 → 真实下载测速 + 识别出口国家
  → 按速度排序、每国限量 → 生成 clash.yaml
```

失效节点不会进入新的输出，新抓到的有效节点自动加入，客户端刷新订阅即可更新。

## 来源怎么来（多路并行，全自动）

1. **仓库搜索**：`queries.txt` 里的关键词和 `topic:` 查询，限定最近 3 天有推送，每条翻 2 页；跳过 fork、归档、体积过大的仓库（多半是客户端而不是节点库）。
2. **仓库文件**：读文件树，挑出文件名像订阅的文件（clash / v2ray / sub / node …）。
3. **README 挖掘**：读每个仓库的 README，挖出里面的 **Telegram 频道**和**订阅链接**（含 GitHub blob 链接自动转 raw、jsDelivr、github.io、pages.dev 等）。
4. **Telegram 频道**：抓公开预览页 `https://t.me/s/<频道>`，每个频道翻 3 页（约 60 条消息）提取节点；频道消息里出现的订阅链接、其他频道会进入第二轮继续抓。
5. **历史有效来源**：任何来源只要有节点通过延迟测试就记一次有效，连续 6 轮没有就淘汰，保留最多 300 个。这份记录通过 Actions cache 跨轮保存，来源池越用越准、越用越大。
6. **固定来源（可选）**：`sources.txt` 或仓库 Secret `EXTRA_SOURCES`。

自动挖到的链接只跟进公网 https 域名（挡掉 IP、localhost、内网域名），下载超过 8 MB 直接放弃。来源质量参差不齐，所以每个节点都要过 TCP、延迟、下载三关，来源本身也要靠"有产出"才能留下。

## 部署

1. 新建 GitHub 仓库，推上全部文件（含隐藏的 `.github`）。
2. Actions 页签 → `update-nodes` → Run workflow，手动跑第一次，看日志里"来源""发现""延迟测试通过"几行是否正常。
3. 跑完后会多出 `nodes` 分支，里面有 `clash.yaml`、`proxies.yaml`、`status.json`。
4. 客户端订阅：
   - `https://raw.githubusercontent.com/<用户名>/<仓库>/nodes/clash.yaml`
   - 国内直连 raw 常常不通，可改用 jsDelivr：`https://cdn.jsdelivr.net/gh/<用户名>/<仓库>@nodes/clash.yaml`（有缓存延迟），或用 Cloudflare Pages 绑定 `nodes` 分支。

## 客户端要求

必须是 **mihomo / Clash.Meta 内核**（Clash Verge / Verge Rev、Clash Meta for Android、ClashX Meta、Stash 等），因为包含 vless / hysteria2 和 `GEOSITE` 规则。原版 Clash / Clash Premium 不支持。

## 可调参数（环境变量，在 workflow 的 `env:` 里加）

| 变量 | 默认 | 含义 |
|---|---|---|
| `DISCOVER` | 1 | 设为 0 关闭自动发现，只用固定来源和历史来源 |
| `MAX_REPOS` / `FILES_PER_REPO` | 60 / 5 | 每轮检查多少仓库、每仓库取几个文件 |
| `DISCOVER_DAYS` / `SEARCH_PAGES` | 3 / 2 | 只看最近 N 天有推送的仓库 / 每条查询翻几页 |
| `MAX_CHANNELS` / `MAX_LINKS` | 30 / 40 | 每轮最多挖多少个 Telegram 频道 / 跟进多少条订阅链接 |
| `TG_PAGES` | 3 | 每个 Telegram 频道翻几页 |
| `MAX_STATE` / `DEAD_LIMIT` | 300 / 6 | 历史来源池上限 / 连续几轮无产出就淘汰 |
| `MAX_PREFILTER` | 6000 | 进入 TCP 预筛的节点上限 |
| `MAX_DELAY_MS` | 1500 | 延迟超过则丢弃 |
| `SPEED_TOP` | 150 | 延迟最低的前 N 个做测速 |
| `MIN_SPEED` | 0.5 | 最低速度 MB/s |
| `KEEP` / `PER_COUNTRY` | 100 / 15 | 最终节点数上限 / 每国上限 |

## 输出文件

| 文件 | 用途 |
|---|---|
| `clash.yaml` | 完整配置：节点 + 分组（自动选择、故障转移、手动、按国家）+ 分流规则 + DNS |
| `proxies.yaml` | 只有 `proxies:`，可当 proxy-provider 接入你自己的配置 |
| `status.json` | 本轮统计：来源数、有效来源数、解析/去重/通过数、国家分布、耗时 |

## 注意

- "全都能用"：生成时每个节点都实测过能出网并下载成功，但免费节点随时下线，所以配置里带了 `故障转移` 和 `自动选择`；订阅更新间隔建议设 60 分钟。
- 自动发现的来源由陌生人运营，节点可以窥探、篡改非 HTTPS 流量，DNS 和 SNI 也会暴露。不要用来登录银行、支付或重要账号。
- GitHub 搜索偶尔限流，此时本轮只用固定来源和历史有效来源，不影响输出。
- 本地试跑：下载 mihomo 放到项目根目录命名为 `mihomo`，`pip install -r requirements.txt && python main.py`（本地没有 token，搜索限流更严）。
- **仓库可见性**：用公开仓库最省事——客户端能直接取到 `nodes` 分支的订阅，Actions 也不限时长。私有仓库有两个问题：raw 链接客户端取不到（需要登录），免费账号每月只有约 2000 分钟 Actions，而每小时跑一次（每轮估计 5–10 分钟）会超。要私有就得改成每隔几小时跑一次，并把输出部署到 Cloudflare Pages 之类的地方。
- 公开仓库意味着任何人都能找到并使用你的订阅，也会更快被针对性封锁；仓库名别起得太显眼。公开分发订阅在国内存在法律风险。
- 公开仓库 60 天没有任何仓库活动时，GitHub 会自动停掉定时任务，发现不更新了就去 Actions 页重新启用。
