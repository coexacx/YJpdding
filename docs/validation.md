# v2.0.0 验证记录

验证日期：2026-10-08。环境：Debian 13 x86_64，Chrome 154.0.8037.57，Rust 1.95.0；发行内核静态链接 musl 与 libpcap 1.10.5。

## 代码审阅

在浏览器实测前审阅了参数输入、Chrome/CDP 生命周期、抓包线程、NetLog 归属、报文解码、TCP 重组、TLS record 解析、AnyTLS 规则和安装器。修复了重定向被误判为成功、进程组重复清理、截断重复计数、原始质量状态未保留、重组内存上限等问题，再进入实测。

实测发现 Chrome 154 的 TCP_CONNECT 结束事件使用 `local_address` / `remote_address`；已同时兼容旧字段。短突发流量在 libpcap immediate mode 下触发丢包，调整为 64 MiB 缓冲和 20ms 批量接收后测试零丢包。修复均加入了相应复核或回归测试。

## 已通过

- `cargo fmt --check`
- `cargo clippy --locked --all-targets -- -D warnings`
- 16 项 Rust 单元测试，包括 10000 组随机字节输入的报文解码检查。
- 10 项独立字节夹具/命令行测试：Ethernet、RAW、Linux cooked v1/v2、pcapng、TCP 乱序重组、重传去重、空/坏文件、参数边界。
- 14 项真实 Chrome 本地 TLS 测试：原生 UA、随机 UA、自定义 UA、有界面/Xvfb、IPv6、重定向、自然协议模式、证书拒绝、HTTP 403、响应超时、DNS 失败、大小上限、SIGINT、错误网卡。
- 同时由另一进程请求同一测试站点，关联结果排除了其套接字。
- 网页 JavaScript 实际执行；自定义 UA 在 HTTP 请求和浏览器中生效。
- 在线与离线重分析的包数、TCP payload 和 TLS record 统计一致。
- 达到样本门槛时生成候选，候选通过严格语法校验；失败/样本不足时不生成候选。
- 公网 `https://example.com`：证书验证开启、HTTP/2、43 个关联包、2 条连接、内核零丢包；样本不足时正确不生成配置。
- TTY 菜单选择、环境检查和进程清理。
- ShellCheck、Bash 语法检查；发行构建脚本已在本机完整运行。
- 内核 `file/ldd` 确认为静态链接，在不含任何系统动态库的空 chroot 中可启动。

测试脚本：`tests/e2e.py`、`tests/offline.py`；实际抓包、密钥及浏览器日志不上传仓库。

## 验证范围

本机验证的是 Linux x86_64。其他发行版安装分支尚未逐一运行，aarch64 发行物未在本机验证。自然模式测试保留了协议协商，没有把 HTTP/2 回退宣称为 HTTP/3 成功。可选密钥已验证导出，内核本身不实现 TLS 解密。

本次未在用户的生产 AnyTLS 客户端/服务端部署候选配置。因此结果是有依据的实验性候选，而不是已验证的生产配置或流量伪装效果保证。

## 发布下载复核

公开 Release 已在独立临时目录中以无 GitHub Token 的方式成功下载；SHA-256 校验、安装切换、内核启动与下载后公网 HTTPS 抓包均通过。部署流程不调用 Rust/Cargo。下载复核发现 Python 的 tar 解压弃用提示，v2.0.1 显式选择安全解压过滤器并兼容旧版 Python，同时在依赖完整时直接复用现有环境；采集内核逻辑保持 v2.0.0 的验证结果。
