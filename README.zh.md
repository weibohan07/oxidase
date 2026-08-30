# Oxidase

[English](README.md) | 简体中文

Oxidase 是一个使用 Rust 编写的声明式 HTTP Service 程序编译器与运行时。

网关配置在 Oxidase 中是一段源程序。Oxidase 会解析 import 与引用，验证完整
程序，预编译 Pattern、Expression、Template 与 Oxista Site，准备共享资源，最后
发布不可变运行时快照。每个 Listener 都可以绑定任意根 Service。

## 核心模型

- **Listener**：管理传输层元数据，并指向根 Service。
- **Service Program**：组合终结型（`Respond`、`Redirect`、`Site`、`Proxy`）、
  包装型（`Transform`、`Observe`、`Timeout`、`Recover`）与组合型（`Route`、
  `Fallback`、`Reenter`）节点。
- **Resource Registry**：持有已验证的 Certificate、可复用 SiteSnapshot、Cluster 等
  共享状态；Resource 不是 Service。
- **Router DSL**：可选的源码语法，在执行前降解为普通 Service IR；运行时没有
  特权 Router。
- **Oxista**：把 `.oxsite`、`.oxr`、`.oxt` 编译为不可变 Site 索引；请求期不解析
  这些源文件。

每个 Service 明确返回 `Handled(response)`、`Declined` 或 `Failed(error)`。
Fallback 只在 `Declined` 时继续；HTTP 404 和 500 仍是正常的 Handled 响应。请求
overlay 与 Route bindings 具有词法作用域，Declined 分支不会向兄弟分支泄漏捕获
或改写。

## 当前 v0.2 alpha

当前入站数据面支持明文 HTTP/1.1，以及通过 TLS 1.2/1.3 和 ALPN 选择 HTTP/1.1
或 HTTP/2 的 HTTPS；所有现有 Service 节点均可在选定协议上运行。Proxy 继续通过
共享连接池执行流式 HTTP/1.1、HTTPS 与上游 HTTP/2。Asset 使用异步文件流，支持
按质量值选择 identity/Brotli/gzip、各表示独立 ETag、正确的 validator 优先级、
If-Range 与单 Range。Range 只作用于 GET：有效单 bytes Range 在 identity 可接受时
使用 identity；HEAD、未知/错误 unit、multiple Range，以及 identity 被排除的请求都
回到正常的完整表示协商路径。

Cluster 可选择 `auto`、强制 `http1` 或强制 `h2` 的上游连接池。从 H2 downstream 到
显式 H2 Cluster，Proxy 会保留 DATA 与 trailer frame。当前 TLS/H2 集成 fixture 已验证
请求/响应 trailers 与透明的多消息 `application/grpc`，包括终止 trailer frame 中的
`grpc-status` 和 `grpc-message`。Oxidase 不解析 protobuf、不重新解释 gRPC status，
也不实现 gRPC-Web。

所有 Listener program 共享一张不可变 `ServiceGraph`；普通请求既不复制整图，也
不收集 explain trace。所有已处理响应统一经过 framing finalizer，Gateway/Oxista
源码不能控制 hop-by-hop 或 framing Header。HEAD、1xx、204、205、304 的 body 规则
均有 wire-level 测试。

`Observe` 已是生产包装型 Service，而不再只是 explain 事件。它以有界结构化字段
记录从进入 wrapper 到 child 返回 response head 的 Handled/Declined/Failed、超时和
嵌套作用域；完整 explain trace 仍默认关闭。独立的流式 body adapter 记录产出字节、
正常结束、body error、idle timeout 与下游取消。指标 label 只来自配置中的 Observe
名称和固定枚举，不包含 URL、query 或 Header value。

Oxista Header 按 global defaults → logical extension → profiles → local OXR 分层
执行；普通 Asset 与 OXR Asset 共用 extension defaults。外部 OXT 会继承 Site 的
output/autoescape 默认值；自定义 404 在编译期验证为可零参数调用，并使用有效模板
元数据。模板预算超限可由 `Recover` 精确分类，内部细节不会泄漏给客户端。

OXT include 具有类型化调用契约，例如
`{% include "_templates/card.oxt" with item=item only %}`。参数表达式统一编译；缺少、
未知、重复参数和常量类型错误在 preparation 阶段失败，动态值在 render 前验证。
普通 include 继承调用方 locals；`only` 丢弃 template/loop/with locals，但保留只读的
`request`、`bindings`、`site`、`resource`、`page` 根。预算在表达式、循环 body、
include 和输出写入前扣费：恰好达到 limit 允许，第 N+1 次不会执行。

正确性身份统一使用完整 SHA-256；结构化对象使用 domain separator、字段名和长度
前缀。强 Asset ETag 为最终 representation bytes 对应的
`"sha256-<64 位小写十六进制>"`。一次 `SiteSourceIndex` 扫描同时提供 Site 复用身份、
representation ETag、Oxista 源文本与编译 metadata，大 Asset 内容不会常驻内存。
Gateway 与 Oxista semantic diagnostic 会保留精确 byte/行列、secondary label、关联定义
以及 import/include reference chain。所有会编译源码的 CLI 命令均接受
`--diagnostic-format human|json`；JSON 使用带版本的 `oxidase.diagnostics/v1`
envelope，stdout 不混入人类输出。RequestFrame 的 Header/query/bindings/request
namespace 采用 frame-local lazy cache，同一未修改 frame 只构造一次。

Certificate 作为 Resource 在发布前完成 PEM/X.509、唯一受支持私钥、证书与私钥
匹配、SNI 与证书兼容性以及 Listener setting 验证。SNI 先精确匹配，再匹配仅一个
label 的最左侧 wildcard，最后使用 default certificate。保留的 Listener socket 会在
每次新连接时读取当前不可变 TLS/HTTP plan，因此合法证书轮换可在不重新 bind 的情况
下原子生效；既有连接继续使用旧 TLS 状态。每个 HTTP/2 stream 在请求开始时固定当前
snapshot，Listener retire 时先 graceful shutdown/GOAWAY，再受 drain deadline 约束。

HTTP/1 Proxy 已有 server-local trusted Upgrade 路径：普通 Respond/OXR/Transform
无法伪造它的 101 响应，验证后的 tunnel 由 connection 持有并执行双向流式复制与
有界指标。其 parser、上游 101 匹配、部分字节计数和内存内 copy/cancellation 已有
聚焦测试；完整的明文/TLS WebSocket、reload 与 drain socket 资格仍待验证，因此当前
alpha 尚不宣称 WebSocket 已完整合格。HTTP/2 extended CONNECT、任意 CONNECT、明文
h2c、gRPC-Web、客户端证书认证/mTLS、ACME、OCSP stapling 与用户自定义 cipher
suite 均未实现；HTTP/1/H2 跨版本 trailer 组合也仍待 socket-level 验证。OXT
`extends/block` 同样不支持。

使用 `serve --watch` 可以启用保留 last-known-good 的原子 reload；通过独立、显式的
`--admin-bind` 可启用健康检查与有界指标。准确边界见
[`docs/implementation-status.md`](docs/implementation-status.md)。
本版本仍是 `0.2.0-alpha`，不宣称 production-ready。

## 运行垂直切片

```bash
cargo run -p oxidase-cli -- check examples/basic-gateway/oxidase.yaml
cargo run -p oxidase-cli -- test examples/basic-gateway/oxidase.yaml
cargo run -p oxidase-cli -- explain examples/basic-gateway/oxidase.yaml \
  --request examples/basic-gateway/requests/home.yaml
cargo run -p oxidase-cli -- serve examples/basic-gateway/oxidase.yaml
cargo run -p oxidase-cli -- serve examples/basic-gateway/oxidase.yaml --watch
cargo run -p oxidase-cli -- serve examples/basic-gateway/oxidase.yaml --watch \
  --admin-bind 127.0.0.1:7590
```

示例覆盖：

- `/`：已编译 OXT 页面；
- `/about.html`：由 OXR 响应策略管理的 sibling asset；
- `/old-page`：Oxista redirect；
- `/feed.json`：结构化 JSON；
- `/legacy`：Service 级 redirect；
- Site 缺失时 Decline，再由显式 Respond 生成 404；
- 外层 response Transform 统一作用于所有已处理分支。

`/api/*` 会代理到 `127.0.0.1:3000` 上游；没有该 fixture upstream 时会得到安全
502。`explain` 无需执行网络请求即可展示编译后的改写与 Cluster 选择。

## 配置片段

```yaml
api_version: oxidase.dev/v1alpha1
kind: gateway

services:
  public:
    type: transform
    response:
      headers:
        set:
          X-Content-Type-Options: nosniff
    service:
      type: fallback
      services:
        - type: site
          site: web
        - type: respond
          status: 404
          body:
            text: Not Found

listeners:
  - name: public-http
    bind: 127.0.0.1:7589
    service:
      ref: public
```

Gateway 与所有 Oxista 格式共享同一套严格 v1alpha1 YAML 边界：未知键、重复键、
anchor、alias、merge key、自定义 tag、tab 缩进和 flow mapping 都会报错；允许 flow
sequence 以及 literal/folded block scalar。Import/reference cycle 会被检查，已解析
但当前没有语义的字段值会带迁移建议直接拒绝。`check` 与 `serve` 使用同一条编译
和 Site 准备管线。

入站 transport 配置见 [`docs/configuration/tls.md`](docs/configuration/tls.md) 与
[`docs/configuration/http2.md`](docs/configuration/http2.md)。HTTPS Listener 默认
`versions: [h2, http1]`；明文 Listener 默认 `http1`，若配置 `h2` 会明确拒绝，而
不会暗示支持 h2c。

## CLI

```text
oxidase check <config>
oxidase serve <config>
oxidase explain <config> --request <request-file> [--listener <name>]
oxidase compile <config> --output <manifest.json>
oxidase test <config>
```

在 `check`、`compile`、`test`、`serve` 或失败的 `explain` 命令后添加
`--diagnostic-format json` 可获得确定性的机器可读诊断。Alpha schema 与位置约定见
[`docs/diagnostics.md`](docs/diagnostics.md)。

`compile` 当前输出确定性的检查清单，并非包含全部资源的可执行二进制快照。

`serve --watch` 会监控 imported config 和已编译 Site 的依赖。Reload 会先完成候选
版本的完整编译与资源准备，预绑定新增 Listener，复用未变化资源，全部成功后才
原子提交。阻塞式 preparation 不占用 Tokio worker；失败候选中新发现的 import
与无效证书轮换仍会被观察，last-known-good 继续服务。失败 Site 候选已扫描的
OXT/OXR/asset、缺失声明路径、template root、预压缩候选及父目录也会保留在 watcher
依赖集中。Retired HTTP/1 connection 会收到 graceful shutdown，HTTP/2 connection
会收到 GOAWAY：空闲连接及时关闭，活跃请求/stream 继续在其固定快照上 drain。
trusted HTTP/1 tunnel 同样固定原 snapshot 并由 connection task 持有；Listener 保留时
继续运行，retire 时使用同一 drain window，超时后才强制取消。这一生命周期已实现，
但完整 WebSocket reload/drain socket 矩阵仍待验证。

## 开发

```bash
cargo +1.88.0 check --workspace --all-targets --all-features --locked
cargo +1.88.0 test --workspace --locked
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --locked
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked
cargo deny check
cargo check --manifest-path fuzz/Cargo.toml --bins --locked
cargo build --workspace --release --locked
```

HTTP 端到端测试会绑定临时 loopback 端口；沙箱环境可能需要相应权限。

架构入口为 [`ARCHITECTURE.md`](ARCHITECTURE.md)。v0.1 原型说明位于
[`docs/legacy/v0.1.md`](docs/legacy/v0.1.md)，完整旧实现仍保留在 Git 历史中。

Oxidase 使用 [MIT License](LICENSE)。
