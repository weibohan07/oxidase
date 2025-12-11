# Oxidase

[English](README.md) | 简体中文

Oxidase 是一个基于 Rust / Tokio / Hyper 的轻量级 HTTP 网关，支持路由匹配、改写、反向代理与静态文件服务。

## 太长了不想读

你可以通过寥寥数行配置快速建立下述业务！

- **静态服务 (`Static`)**：从任意文件夹**安全地**启动一个静态网站或文件服务。邪恶的路径会被自动过滤！具有目录策略、`index` / `404` 页面等选项。
- **反向代理服务 (`Forward`)**：将请求转发到上游 HTTP(S)，并返回上游返回的响应。具有 `pass_host` 策略、`X-Forwarded` 控制等选项。
- **可编程路由流水线服务 (`Router`)**：
  - 整个流水线由规则驱动，每条规则在匹配的同时可以从请求头中捕获变量。（详见**模式**）
  - 规则被匹配后可以按照请求头中捕获的变量进行分支。
  - 分支树的叶子节点可以对请求头进行各种编辑操作（并且可以使用捕获的变量，详见**模板**），也可以直接返回错误页面或直接委托指定的其他服务。
  - 可以指定托底服务，在规则耗尽后会委托该服务。

此外，我们还有这些激动人心的功能：

- **配置引用**：配置中任意需要 `Service` 对象的字段都可通过 `import: ./foo.yaml` 从其他文件中读取服务。
- **多实例**：配置中可包含多个 `HttpServer` 对象。若提供 `name` 字段，则可以通过 `--pick` 按名称单独启动。
- **实时监听配置变化**：可以通过 `--watch` 标志实时监听配置文件的变化。

## 快速开始

```bash
cargo build --release
./target/release/oxidase -c config.yaml
```

我们想要在一个端口上启动一个服务，我们可以在配置文件中指定一个 `HttpServer` 对象。

`HttpServer` 对象包含了 `bind`、`service`、以及可选的 `name` 字段——其中：`bind` 表示绑定的端口，是一个字符串；`service` 表示绑定的服务，是一个 `Service` 对象；`name` 表示赋予该 `HttpServer` 一个名字，可以通过 `--pick` 单独启动。

```yaml
# config.yaml
bind: "127.0.0.1:7589"
service:
  handler: static
  source_dir: "./public"
```

当我们的配置文件变得愈发复杂，或许可以考虑将一些 `Service` 对象拆分成独立文件。

```yaml
# main.yaml
bind: "127.0.0.1:7589"
service:
  import: "./service.yaml"

# service.yaml
handler: static
source_dir: "./public"
```

此外，我们也可以直接在配置文件里列出多个 `HttpServer` 对象，在默认情况下，这些服务会全部启动。

```yaml
# config.yaml
servers:
  - name: web
    bind: "0.0.0.0:7589"
    service:
      import: "./service_web.yaml"
  - name: api
    bind: "0.0.0.0:7588"
    service:
      handler: forward
      target:
        scheme: http
        host: "localhost"
        port: 3000
```

## CLI 选项

- `-c, --config <FILE>`：从完整配置文件启动一个或多个服务。
- `-f, --service-file <FILE>`：从仅含 `Service` 的配置文件，结合 `--bind` 参数启动一个服务。
- `-i, --service-inline <YAML/JSON>`：从行内 `Service` 配置，结合 `--bind` 参数启动一个服务。
- `-b, --bind <ADDR>`：为仅提供 `Service` 配置的启动模式绑定地址与端口（默认 `127.0.0.1:7589`）。
- `-p, --pick <NAME>`：在配置文件里列出的多个 `HttpServer` 对象中指定具有特定名称的一个服务启动。
- `-v, --validate-only`：只校验配置，不启动服务。
- `-w, --watch`：监听配置文件的变化，自动重启服务。

## 配置结构

- **HttpServer**
  ```yaml
  name?: (string)
  bind: (string)
  tls?: (TlsConfig) # 开发中
  service: (ServiceRef)
  ```
- **ServiceRef**
  ```yaml
  # 内联
  handler: static | forward | router
  ... # 具体服务的选项

  # 或从其他文件引用
  import: (./path/to/service.yaml)
  ```
- **Service**
  - **Router**
    ```yaml
    handler: router
    rules: ([RouterRule...])
    next?: (ServiceRef)
    max_steps?: (u32)
    ```
  - **Forward**
    ```yaml
    handler: forward
    target:
      scheme: http | https
      host: (host)
      port: (u16)
      path_prefix: (path)
    pass_host: incoming | target | custom{(host)}
    x_forwarded?: bool
    tls?: ... # 开发中
    timeouts?: ... # 开发中
    http_version?: ... # 开发中
    ```
  - **Static**
    ```yaml
    handler: static
    source_dir: (string)
    file_index: (string)
    file_404?: (string)
    file_500?: (string) # 开发中
    evil_dir_strategy?:
      if_index_exists?: serve_index | redirect{(u16)} | not_found
      if_index_missing?: redirect{(u16)} | not_found
    index_strategy?: serve_index | redirect{(u16)} | not_found
    ```
- **RouterRule**
  ```yaml
  when?: (RouterMatch)
  ops: ([RouterOp...])
  on_match?: stop | continue | restart
  ```
- **RouterMatch**
  ```yaml
  scheme?: http | https
  host?: (pattern)
  path?: (pattern)
  methods?: ([(GET | POST | ...)])
  headers?:
    - { name: (string), pattern: (pattern), not?: (bool) }
    - ...
  queries?:
    - { key: (string), pattern: (pattern), not?: (bool) }
    - ...
  cookies?:
    - { name: (string), pattern: (pattern), not?: (bool) }
    - ...
  ```
- **RouterOp**
  - 请求头重写：
    - `set_scheme`
    - `set_host`
    - `set_port`
    - `set_path`
    - `header_set/add/delete/clear`
    - `query_set/add/delete/clear`
  - 控制流：
    - `branch { if, then, else }`
    - `internal_rewrite`
  - 最终操作：
    - `redirect { status, location }`
    - `respond { status, body?, headers? }`
    - `use { (ServiceRef) }`

## 模式（`Pattern`）与模板（`Template`）

举个例子，我们现在正在配置一个 `Router` 服务，想要将形如 `https://docs.example.com/rust/oxidase-web-server.html` 的优雅 URL 改写为 `http://192.168.12.34:5678/index.php?blog=docs&category=rust&post=oxidase-web-server` 并转发给 PHP 实现的上游业务。

那我们就可以编写如下配置：

```yaml
# config.yaml
bind: "0.0.0.0:443"
service:
  handler: router
  rules:
    - when:
        scheme: https
        host: '<blog_name:label>.example.com'
        path: '/<category_slug:slug>/<post_slug:slug>.html'
      ops:
        - set_scheme: http
        - set_host: "192.168.12.34"
        - set_port: 5678
        - set_path: 'index.php?blog=${blog_name|url_encode}&category=${category_slug|url_encode}&post=${post_slug|url_encode}'
    - ... # 其他规则
  next:
    handler: forward
    target:
      scheme: http
      host: "192.168.12.34"
      port: 5678
```

当然，目前 https 相关的功能还在开发中，实际使用时还不能处理 https 的请求，此处仅作为演示。

在这个案例中，我们可以发现通过强大的模式引擎和模板引擎，我们可以很方便地从请求头中捕获一些变量，并在后续的请求头重写中将使用这些变量。

### 模式（Pattern）语法

- **上下文**：`host` / `path` / `value`，整字段匹配，不做子串搜索。
- **占位符**：
  - 结构类：`<:label>/<:labels>`（DNS label）、`<:seg>`（单段路径）、`<:any>`（贪婪匹配余下）。
  - 类型类：`<:uint/int/slug/hex/uuid>`。
  - 自定义：`<:regex(...)>`（受限子集，避免灾难性回溯）。
  - 当冒号前存在命名，就会生成捕获，可在模板中引用。
- **受限 regex 说明**：只允许安全的字面量/字符类/有限量词和非捕获分组，默认整字段锚定；按上下文编译（如 host 下的 label 规则）。

### 模板（Template）语法

- **形式**：`${var | filter(...) | filter2}`，自左向右应用过滤器。
- **变量**：`method/scheme/host/port/path`，`header.<Name>`（不区分大小写），`query.<key>`，`cookie.<name>`，以及前述模式的命名捕获。
- **过滤器**：`default(x)`、`lower/upper`、`url_encode`、`trim_prefix(x)/trim_suffix(x)`、`replace(a,b)`；缺失变量展开为空串。

## 运行与并发

Oxidase 基于多线程 Tokio Runtime。

## 开发

- 测试：`cargo test`（或 `cargo test cli` 等模块级）。
- 主要模块：
  - `config`（解析 / 校验 / `import`）
  - `build`（运行态构建）
  - `handler`（`router` / `forward` / `static`）
  - `pattern`
  - `template`
  - `cli`

## 规划

- [ ] HTTPS 支持。
- [ ] 更好的热更新支持。
- [ ] Forward 上游 HTTPS/HTTP2、TLS。
- [ ] 更好的观测与日志（结构化日志、指标）。 

## 贡献

本项目采用 [MIT 协议](LICENSE)开源。

本项目使用 [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/)。

贡献时请编写测试。
