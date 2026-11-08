# UDP over QUIC 审计修复（2026-11-08）

本轮检查 `codex/udp-over-quic` 的新增 UDP 路径及关联客户端/Caddy patches。
审计起点：`a0a598514b7ffb7bd98f6121bcf227a0ba48cae9`。

已修复：

- 默认 ACL 增加 IPv4 link-local `169.254.0.0/16` 与 IPv6 ULA `fc00::/7`；
  防止有效账户默认访问这些服务器本地可达资源。显式 allow 仍优先，TCP/UDP 一致。
- 等待 peer SETTINGS 的已认证请求提前占用 admission quota，避免等待者绕过
  handler/user/process 会话限额。取消与能力拒绝均释放。
- 未知 Context ID 同样扣减共享 packet budget；DATAGRAM/Capsule 入口统一
  发送、丢弃、MTU 错误和短写处理，补齐 Capsule 路径计数。
- 每隧道 Capsule 处理额外限制为 100/s、burst 100；控制洪泛超限关闭隧道。
- 空闲计时改为 monotonic duration，原子更新只接受较新时间，避免校时和并发
  touch 导致误判。
- UDP Provision 拒绝畸形 Base64、缺少冒号或用户名为空的配置凭据；安全提取
  已认证 token，避免未检查索引。

回归新增：pending SETTINGS quota/cancel、未知 Context 预算、Capsule 洪泛/
截断、默认 ACL/显式 allow、monotonic timer、畸形配置凭据，以及未认证
CONNECT-UDP 的 probe resistance。Go UDP 单元和真实 HTTP/3 集成 `-race`
通过，关键并发/限速回归重复五次通过；`go vet ./...` 和 patched Caddy
构建通过。paired native 客户端真实 SOCKS/IPv4/IPv6/domain/empty/1200-byte/
oversized recovery/source pinning/TCP padding 共存测试通过。macOS 本地只跑
UDP Go 子集，完整 Linux Go 测试由分支 CI 执行。

UDP over QUIC 不能宣称比 HTTPS 更隐蔽：CONNECT-UDP 元数据和 DATAGRAM
内容受加密保护，但 Initial 可分析、包长/方向/时序可观察，主动连接可检查
服务端能力。相比普通 TCP HTTPS，应按更大的传输分类/阻断面评估；相比
普通 HTTP/3，尚无定量依据证明更低风险。未开启 `probe_resistance` 的
407 仍可暴露代理身份。本轮未做公网防火墙识别率测试。

完整的双端发现、受控密文包长测量、风险对比与规范依据见
[naiveproxy 审计报告](https://github.com/kinmeic/naiveproxy/blob/codex/udp-over-quic/docs/udp-over-quic-audit.zh-CN.md)。
