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
- **Resource Registry**：持有可复用的 SiteSnapshot、Cluster 等共享状态；Resource
  不是 Service。
- **Router DSL**：可选的源码语法，在执行前降解为普通 Service IR；运行时没有
  特权 Router。
- **Oxista**：把 `.oxsite`、`.oxr`、`.oxt` 编译为不可变 Site 索引；请求期不解析
  这些源文件。

每个 Service 明确返回 `Handled(response)`、`Declined` 或 `Failed(error)`。
Fallback 只在 `Declined` 时继续；HTTP 404 和 500 仍是正常的 Handled 响应。请求
overlay 与 Route bindings 具有词法作用域，Declined 分支不会向兄弟分支泄漏捕获
或改写。

## 当前 v0.2 alpha

当前可运行的 HTTP/1.1 垂直切片支持 Respond、Redirect、Route、Fallback、
Transform、Observe、Timeout、Recover 与已编译 Site。Asset 使用异步文件流，
支持单 Range、ETag/Last-Modified 条件请求与预压缩表示选择。

Proxy 已进入规范 Service 计划并参与完整校验，但生产上游适配器仍是下一阶段。
TLS、HTTP/2、Listener 生命周期感知的 reload、管理接口及 OXT `extends/block` 尚未
实现。准确边界见 [`docs/implementation-status.md`](docs/implementation-status.md)。

## 运行垂直切片

```bash
cargo run -p oxidase-cli -- check examples/basic-gateway/oxidase.yaml
cargo run -p oxidase-cli -- test examples/basic-gateway/oxidase.yaml
cargo run -p oxidase-cli -- explain examples/basic-gateway/oxidase.yaml \
  --request examples/basic-gateway/requests/home.yaml
cargo run -p oxidase-cli -- serve examples/basic-gateway/oxidase.yaml
```

示例覆盖：

- `/`：已编译 OXT 页面；
- `/about.html`：由 OXR 响应策略管理的 sibling asset；
- `/old-page`：Oxista redirect；
- `/feed.json`：结构化 JSON；
- `/legacy`：Service 级 redirect；
- Site 缺失时 Decline，再由显式 Respond 生成 404；
- 外层 response Transform 统一作用于所有已处理分支。

`/api/*` 需要 `127.0.0.1:3000` 上游；Proxy 阶段完成前，真实请求会得到安全 502，
但 `explain` 已能展示编译后的改写与 Cluster 选择。

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

v1alpha1 YAML 边界默认严格：未知键、重复键、import cycle 和普通 Service cycle
都会报错，不支持 YAML alias/merge key。`check` 与 `serve` 使用同一条编译和 Site
准备管线。

## CLI

```text
oxidase check <config>
oxidase serve <config>
oxidase explain <config> --request <request-file> [--listener <name>]
oxidase compile <config> --output <manifest.json>
oxidase test <config>
```

`compile` 当前输出确定性的检查清单，并非包含全部资源的可执行二进制快照。

## 开发

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
cargo doc --workspace --no-deps
```

HTTP 端到端测试会绑定临时 loopback 端口；沙箱环境可能需要相应权限。

架构入口为 [`ARCHITECTURE.md`](ARCHITECTURE.md)。v0.1 原型说明位于
[`docs/legacy/v0.1.md`](docs/legacy/v0.1.md)，完整旧实现仍保留在 Git 历史中。

Oxidase 使用 [MIT License](LICENSE)。
