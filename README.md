# YJpdding

使用本机 Chrome 真实访问网页，通过 Rust + libpcap 采集和分析 TLS 流量。提供中文交互菜单、无头/有界面模式、本机桌面/原生/随机/自定义 UA、IPv4/IPv6 连接关联、离线分析以及 AnyTLS 实验性 padding 候选。

部署使用 GitHub Release 预编译内核，**无需安装 Rust、Go、Node.js 或 curl**。静态内核包含 libpcap，不依赖部署系统的 glibc 版本。Chrome/Chromium 仍是运行依赖。

## 安装和启动

```bash
wget -O capture.sh https://raw.githubusercontent.com/coexacx/YJpdding/main/capture.sh
sudo bash capture.sh --install
sudo bash capture.sh
```

建议直接在用于抓包的管理账号下安装和运行，避免切换账号后安装目录不同。内核默认安装到 `${XDG_DATA_HOME:-$HOME/.local/share}/YJpdding/current`。可用 `YJPADDING_INSTALL_DIR` 指定位置。

首次没有内核时，启动菜单直接提供环境检测和一键安装。安装器识别 Linux 发行版、CPU 架构、内存和磁盘；安装缺失的 Chrome、Xvfb、Python3 等运行依赖，然后从 Release 下载匹配架构的内核。下载经 SHA-256 校验后，**先用新内核进行本机 Chrome 实际抓包、JavaScript 执行及临时 AnyTLS 节点互通测试，通过后才切换版本**。失败保留原内核和 `verification/` 下的诊断。旧版本保留在 `releases/`。不安装 Rust 或 Go，不修改已有浏览器用户目录。AnyTLS 测试工具从官方 Release 下载固定版本 v0.0.13，校验归档及内核的固定 SHA-256 后缓存到状态目录，未将第三方二进制重新分发至本仓库。

```bash
bash capture.sh --check                         # 系统和资源检查
bash capture.sh --update                        # 更新运行依赖和内核
bash capture.sh --install --skip-packages       # 已有依赖，只下载内核
YJPADDING_VERSION=v2.2.0 bash capture.sh --install --skip-packages
```

发行资产按架构提供；若某架构尚未发布，安装器会明确失败，不会运行不兼容的内核。安装分支覆盖 Debian/Ubuntu、Fedora/RHEL 系、Arch、openSUSE、Alpine；实际验证的平台和架构见 `docs/validation.md`，不将未验证平台标记为已通过。

## 使用

无参数启动为交互菜单。浏览器运行方式与 UA 策略是两个独立选项。

```bash
sudo bash capture.sh capture https://example.com --duration 20 --rounds 1  # 简单站点快速采集
sudo bash capture.sh capture https://corporate.comcast.com/ --ua desktop --duration 60 --rounds 3
sudo bash capture.sh capture https://example.com --browser headed --ua random
sudo bash capture.sh capture https://example.com --ua native  # 保留无头原始标识作对照
sudo bash capture.sh capture 'https://[::1]:8443/' --insecure --duration 15 --rounds 1
sudo bash capture.sh capture https://example.com --ua custom --user-agent 'MyBrowser/1.0'
sudo bash capture.sh capture https://example.com --protocol natural --cache --rounds 1
sudo bash capture.sh capture https://example.com --keylog --reload-interval 0
sudo bash capture.sh capture https://example.com --browse-interval 0  # 关闭随机站内点击
bash capture.sh verify-padding padding-candidate.txt              # 本机临时节点验证
sudo bash capture.sh self-test                                   # 部署前完整自检
bash capture.sh cleanup                                         # 清理到期抓包
bash capture.sh analyze capture.pcap --session session.json
bash capture.sh analyze old.pcap --server 203.0.113.10:443
bash capture.sh validate padding-candidate.txt
bash capture.sh doctor
bash capture.sh capture --help
```

- **无头**使用实际 Chrome 无头模式。**有界面**使用现有桌面；服务器没有显示器时自动启动本次任务专用的 Xvfb，仍属于有界面 Chrome，但不会创建远程桌面。
- **本机桌面 UA（默认 `--ua desktop`）**从本机 Chrome 内部页面读取实际 UA、平台和 Client Hints，仅将 UA 中的 `HeadlessChrome/` 改为 `Chrome/`，保留实际版本、品牌及系统信息。读取过程不访问外部网站；报告同时保存原生和实际发送的 UA。**原生 UA（`--ua native`）**保留所有原始标识，包括无头模式的 `HeadlessChrome`。**随机 UA**使用实际 Chrome 大版本，随机选择桌面平台并同步 UA Client Hints；不声称改变实际操作系统或浏览器指纹。**自定义 UA**同步 `navigator.userAgent`，不捏造无法从字符串确认的 Client Hints。
- **TCP 模式**明确关闭 QUIC，便于 TLS-over-TCP 分析。**自然模式**保留浏览器协议协商；UDP 分开统计，不按 TCP/TLS record 解释。选择自然模式不保证目标会协商 HTTP/3。
- 默认 `any` 网卡覆盖回环、路由变化、IPv4/IPv6。每次创建独立临时浏览器目录、禁用继承的系统代理，默认关闭缓存；重新访问的最小间隔为 10 秒，并等待主页面导航和加载结束，避免打断慢响应或同步脚本。期间滚动页面以触发懒加载。可设置 `--reload-interval 0` 关闭定时重访；若只采一个页面，同时设置 `--browse-interval 0`。整个任务仍受 `--duration` 限制。
- 默认成功加载后每 5 秒尝试一次站内随机浏览，最多 30 个不同链接。使用真实鼠标事件，自动滚动到链接，并将站内新标签页链接留在当前采集标签页；只选择同源的普通内容链接，排除表单、下载和明显的状态修改地址。允许目标首次重定向到实际站点。识别到 OneTrust 隐私弹窗时仅使用关闭/拒绝控件。使用 `--browse-interval 0` 关闭此功能。
- root 启动时，Chrome 默认降权到 nobody 并保留沙箱；特殊受限环境才显式使用 `--no-sandbox`。抓包需要 root 或适当的网络采集 capability。

## 多轮采样和实际抓包筛选（v2.2.0）

默认 `--rounds 3 --duration 60`：浏览器采集总时长 60 秒，分为三个独立 Chrome 会话，每轮约 20 秒；前两轮训练，最后一轮留作独立复核。可使用 3–5 轮，或 `--rounds 1` 保留单轮快速采集。启动/分析耗时与本机比对另计。`--max-mib` 是每轮暂存抓包上限，默认 256 MiB，三轮最多 768 MiB；另有最多 64 MiB 的本机比对暂存抓包。每轮至少 2 秒；复杂站点建议增加采集时长。

- 每轮至少需要 6 条完整、无丢包且关联 Chrome 的 TLS 1.3 连接。简单站点连接不足时明确失败并保留原始抓包，不虚构 padding。
- 每轮最多均匀保留 128 条连接；按上行/下行、前 8 个加密 record 的位置、后续阶段分别统计。生成规则时每轮权重相同，每个位置每条连接只贡献一个样本，大下载不会凭记录数量压倒其他连接。
- 只用训练轮生成按位置变化的 P25–P75、P10–P90 两组候选，认证/控制规则保留默认值；后续位置缺少支持时停止生成该位置。浏览器 record 序号仅作为参考位置，不能由此恢复应用或 AnyTLS 的真实 Write 边界。
- 按每条连接的平均上行记录长度分层，每轮选 6 条代表序列（小、中、大各两个），用于**长度驱动的本机合成负载**。负载长度用 record body 减 17 估计，限制到 1–16384 字节；不重放网站正文，不将该估计标注为解密后的真实长度。
- 默认配置与最多两组候选各重复两次；反转候选测试顺序，每次使用独立会话，先完成配置同步再测试。Rust/libpcap 实际采集回环流量、独立重组 TLS，逐项核对节点中继标记的记录序列；缺包、标签不一致或清理失败都不允许推荐。
- 以长度 CDF 差异（KS）、对数分位数差异、发送位置长度误差和记录数量差异评分，越低越接近参考。训练集只选一个胜者；独立复核及两次复核重复均需改善至少 5% 且绝对下降 0.01，上行测试窗口 TLS 字节不能超过默认的 110%，P95 写入往返耗时不能超过默认三倍或 50ms 中的较大者。否则推荐经过互通验证的默认基线。
- 上行 TLS/负载比包含测试窗口内真实 TLS 头、加密开销、AnyTLS 帧与填充；不包含初始化认证/握手、TCP/IP 和 ACK。下行保留分层统计，当前客户端 padding 规则不控制服务端下载包长。

这是**本机样本长度负载的实际 TLS 记录对比**，不等于 Chrome 通过公网生产节点后完整流量特征已得到验证。候选比对最多 90 秒，状态目录中的独占锁防止并行启动多组比对任务；节点只监听回环地址、低优先级并受 CPU/内存目标限制，正常结束、失败和中断自动清理。不会更改 SSH、网站、路由、代理或网卡卸载设置。

多轮任务顶层包含 `report.txt`、`report.json`、`selection.json`、`sampling.json`、`strata.json`、`calibration-input.json`、`calibration-runtime.json`、`calibration-capture.json`、`目标站点-anytls-comparison.pcap` 及最终 `padding-verified.txt`。各轮原始抓包和浏览器证据位于 `round-01/目标站点-…/` 等目录。独立复核失败不尝试用同一复核集改选第二名，避免把复核数据反过来用于调参。

## 产物和成功条件

单轮运行在 `capture-results/目标站点-时间-随机后缀/`（例如 `corporate.comcast.com-时间-随机后缀/`） 创建独立私有目录：

| 文件 | 用途 |
|---|---|
| `目标站点.pcap` | 根据 Chrome NetLog 本地/远端地址和端口关联后的原始包 |
| `session.json` | 设置、实际 UA、浏览器请求、连接归属、错误与抓包质量 |
| `netlog.json` | Chrome 默认级别网络日志，供复核连接归属 |
| `report.txt` / `report.json` | 可读报告及结构化统计 |
| `padding-candidate.txt` | 质量与样本量达标时生成的候选配置 |
| `padding-verified.txt` | 仅在本机临时 AnyTLS 节点验证通过、清理完成后生成 |
| `padding-validation.json` / `.log` | 配置哈希、同步确认、测试连接数、双向数据校验和清理状态 |
| `chrome.log` / `display.log` | 浏览器及虚拟显示器诊断 |
| `tls.keys` | 仅启用 `--keylog` 时生成，本次浏览器 TLS 密钥 |
| `failure.json` | 明确记录失败或部分成功 |

先启动抓包器，再让 Chrome 访问页面。短期暂存采集覆盖接口 TCP/UDP，最后根据本次浏览器套接字和页面请求筛选，并删除暂存文件。不会依据一次 DNS 解析固定单个 IP，也不会将其他进程访问同一站点的连接混入结果。NetLog 默认模式不包含 socket 原始载荷，但请求 URL 仍可能带敏感参数，产物应由使用者妥善保存。

成功要求主页面得到成功响应并完成加载、匹配到双向有效流量、无采集错误或内核丢包。失败仍保存可用诊断；不会仅凭文件存在就宣称成功。退出码：`0` 成功，`1` 配置/初始化/解析失败，`2` 页面失败、采集不完整或候选验证失败，`130` 采集中断。

## 网页无法加载时

终端、`failure.json` 和报告会显示 Chrome 网络错误、HTTP 状态、超时或丢包原因。网页失败与抓包器失败分别保留证据；HTTP 403、证书错误和未完成的页面不会被记为成功。

v2.0.1 在本机访问 `https://corporate.comcast.com/` 时，默认无头原生 UA 导致主页面出现 `net::ERR_HTTP2_PROTOCOL_ERROR`，NetLog 记录服务端重置请求流。普通 Chrome UA 和有界面模式对照成功；仅关闭 HTTP/2 无效。v2.1.0 默认桌面 UA 在相同机器上通过实际 HTTP/2 请求获得 HTTP 200，并完成双向抓包；不需要更换为 curl，也未关闭证书验证。

旧版部署先重新下载本页安装命令中的 `capture.sh`，再执行 `bash capture.sh --update`，以启用新的安装前验证流程。若为对照测试显式指定了 `--ua native`，可改为 `--ua desktop` 或 `--browser headed`。仍失败时根据具体诊断检查 DNS、证书、页面耗时及目标响应；该修复不保证所有站点或所有出口 IP 都能访问。

## 自动验证与三天清理

生成候选后自动创建两个仅监听 `127.0.0.1` 空闲高位端口的 AnyTLS 测试进程，以及本机回显端点。检查服务端加载配置、客户端同步 padding 摘要，在连接复用和新建连接两种模式下分别测试 1、64、512、1400、4096、16384、65536 字节的双向传输。通过后才生成 `padding-verified.txt`；失败保留诊断并返回退出码 2。离线重新生成候选也执行相同验证。

测试采用临时随机密码，进程低优先级运行，并限制 CPU 时间和文件描述符数。正常结束、异常、超时和可捕获的中断都会清理本次客户端/服务端和临时配置。不会修改系统代理、路由、防火墙、SSH、现有站点配置或监听端口。范围是 **anytls-go v0.0.13 在本机的互通与数据完整性**，不代表其他生产实现或流量相似性已经验证。

安装时自动建立专用 systemd 定时器；无 systemd 时使用当前账号 crontab（需要可用的 cron 服务）。每小时检查一次，删除已满 72 小时的本工具抓包目录，包含其中 pcap、报告、日志、密钥及候选配置；到期后的下次调度执行删除。每次采集开始也执行检查。只识别带本工具标记的目录，跳过符号链接和有活动文件锁的采集任务，不清理旧版无标记目录或无关文件。

目录登记和 AnyTLS 工具默认存放在 `${XDG_STATE_HOME:-$HOME/.local/state}/YJpdding`，可用 `YJPADDING_STATE_DIR` 指定。需要长期保留的成果应复制到抓包任务目录之外。`YJPADDING_SKIP_TIMER=1` 仅供测试环境关闭定时器配置，不能据此保证无人值守清理。

## 分析口径和限制

IP 总长、TCP payload、UDP payload、TLS record 分开统计。TCP 包长包含线上重传；TLS record 来自按连接方向重组、去重后的字节流。支持以太网/VLAN、Linux cooked v1/v2、RAW、回环，支持 TCP 乱序、跨包/同包多条 TLS record，检测缺口、重叠冲突、截断及资源上限。未完成的流不用于候选生成。

IP 分片会跳过并计入质量问题；混合链路类型的 pcapng 受 libpcap 离线接口限制。GRO/GSO/TSO 可能使本机抓包长度与线上帧长不同，因此不推断 MTU。没有密钥时不会把 TLS 1.3 加密 record 冒充识别出的 Finished、证书或 HTTP 请求。

AnyTLS 规则依据[官方协议](https://github.com/anytls/anytls-go/blob/fd6167acd6d73b9fa3e607659951847fbc9e6c50/docs/protocol.md)：`0` 为认证填充、后续计数为 TLS Write 次数、`c` 是条件停止标记。单轮快速采集及离线分析的候选保留原有保守算法：认证/控制规则固定，其余区间来自合格上行样本的 P25–P75，并展示假设和简化开销估算；至少需要 3 条完整连接、20 个上行加密 record。多轮模式采用上文的按位置生成和实测筛选。

**网站 TLS record 无法精确还原 AnyTLS Write 边界。自动测试确认本机参考实现能接受候选并正确传输数据，不等于用户生产节点互通、流量相似性或伪装效果已验证。**

## 开发和验证

Rust 源码在 `src/`，依赖固定在 `Cargo.lock`。开发需要 Rust 1.85+，发布构建使用 Rust 1.95、musl、libpcap 1.10.5。

```bash
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
bash build-release.sh
sudo python3 tests/e2e.py target/x86_64-unknown-linux-musl/release/capture-rs
python3 tests/runtime_validation.py
python3 tests/installer.py
sudo python3 tests/tuning.py --binary target/x86_64-unknown-linux-musl/release/capture-rs
sudo python3 tests/tuning.py --binary target/x86_64-unknown-linux-musl/release/capture-rs --case interrupt
sudo python3 tests/tuning.py --binary target/x86_64-unknown-linux-musl/release/capture-rs --case insufficient
sudo python3 tests/tuning.py --binary target/x86_64-unknown-linux-musl/release/capture-rs --case tampered
python3 tests/calibration_cleanup.py
```

Debian 发布构建依赖：`build-essential musl-tools flex bison pkg-config libpcap-dev python3`，以及通过 rustup 安装的 Rust 工具链。构建脚本验证 libpcap 源码 SHA-256，生成静态发行包和 `SHA256SUMS`；发行包包含第三方版权声明。浏览器自动化使用 [Chrome DevTools Protocol](https://chromedevtools.github.io/devtools-protocol/)，不依赖 ChromeDriver。
