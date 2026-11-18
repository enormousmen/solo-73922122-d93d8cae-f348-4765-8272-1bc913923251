# 单进程影子流量网关（FastAPI + aiohttp）

新版报价接口上线前的旁路比对网关：固定并行调用**主端**与**影子端**两个本地 GET 报价服务，
客户端只收到主端的原始状态码与原始字节；影子端的慢、失败、超时完全不影响主响应。

`GET /quote` 与 `/quote-big` 强制 HMAC-SHA256 验签 + 一次性 nonce 防重放，
阻止被复制的请求反复占用主端和影子端资源。

## 架构

```
浏览器 (web 控制台, 值班员临时输入密钥, 浏览器本地签名)
      │  GET /quote, /quote-big
      │  头: X-Sign-Timestamp / X-Sign-Nonce / X-Sign / X-Sign-Algorithm
      ▼
┌──────────────── gateway (FastAPI, 单进程, mem_limit 96m) ───────────────┐
│  HMAC 验签  nonce 防重放(≤1024)  名额信号量(最多4)  并行 aiohttp 调用   │
│  验签失败/重放/满额: 直接拒绝, 不请求上游, 不占影子名额                  │
│  流式 SHA-256  比对记录(内存环形)                                       │
└───────┬───────────────────────────────────────────┬────────────────────┘
        ▼                                           ▼
   primary:8000 (主报价服务)                  shadow:8000 (影子报价服务)
   响应原样透传给客户端                         只做摘要/状态码比对
```

- 两端使用同一镜像 `shadow-gateway:latest`，以 `SERVICE_ROLE=primary|shadow` 区分。
- 网关只代理 `GET /quote` 与 `GET /quote-big`；网页与 `/api/*` 管理接口不拦截。

## HMAC-SHA256 验签与防重放

### 签名规则

签名串依次以换行（`\n`）连接 4 段，使用服务端环境变量 `SIGNING_SECRET` 做 HMAC-SHA256，
输出十六进制摘要放入 `X-Sign` 头：

```
GET
<原始路径及查询串，例如 /quote?symbol=ACME>
<秒级 Unix 时间戳>
<一次性随机数 nonce>
```

| 请求头 | 含义 |
| --- | --- |
| `X-Sign-Timestamp` | 秒级 Unix 时间戳，与服务端时钟相差不超过 60 秒（`SIGN_WINDOW_S` 可调） |
| `X-Sign-Nonce` | 一次性随机数，ASCII、长度 ≤ 128；签名仍有效期间同一 nonce 只放行一次 |
| `X-Sign` | HMAC-SHA256 十六进制摘要，服务端常量时间比较（`hmac.compare_digest`） |
| `X-Sign-Algorithm` | 固定 `HMAC-SHA256`，缺省时按该算法处理 |

### 安全语义

- **密钥只从服务端环境读取**：不接受请求传入、不随任何响应/日志/页面输出；
  网页由值班员**临时输入**密钥，仅保存在当前页 JS 变量中，浏览器内用 Web Crypto 签名，
  不上传、不写 localStorage/cookie、刷新即失。
- **时间窗口**：`abs(服务端时间 - 时间戳) > 60s` 一律 401 拒绝（过去与未来都拦）。
- **一次性 nonce**：锁内原子 check-and-insert，并发重放也只有一个请求能进入上游；
  nonce 保留到该签名自身失效为止，之后惰性清除。
- **容量上限**：单进程最多保留 1024 个有效 nonce（`MAX_NONCES` 可调）；
  先清过期项，仍满则对新请求返回 503。
- **拒绝不碰上游**：验签失败（401）、重放（401）、满额（503）均直接返回
  （响应体含 `rejected_before_upstream: true`），不请求主端/影子端、不占影子名额、
  不产生比对记录；拒绝原因在 `/api/state` 的 `auth_rejected` 计数中可见。
- 服务端未配置 `SIGNING_SECRET` 时返回 503，绝不退化为免签放行。

### 网页演示

控制台第③区可一键演示：正常签名、**同签名并发重放**（两个请求仅一个放行）、
错误签名、过期时间戳、缺少签名头，每个请求展示状态码与网关返回的拒绝原因；
顶栏实时显示有效 nonce 数与各类拒绝计数。

## 关键语义（与需求逐条对应）

| 需求 | 实现位置 |
| --- | --- |
| 两端并行调用，客户端只收主端原状态码、原字节 | `app/gateway.py` `proxy()` / `body_iter()` 逐块透传 |
| 影子慢/失败/超时不拖住主响应 | 影子为独立后台任务；主端流结束即返回客户端，`wait_for(2s)` 只取消影子 |
| 两端流式 SHA-256，完整结束才比较 | 每块 `hash.update()` 后立即释放；`_compare()` 仅在两端 `completed` 时调用 |
| 未收完整不能报一致 | 中间态 `shadow_pending` / 断连 / 超时 / 主端不完整均不会产生 `match` |
| 最多 4 个影子调用，满则跳过并注明原因 | `ShadowLimiter`（acquire/release 覆盖整个影子通信生命周期） |
| 影子发起起 2 秒超时，只终止影子 | `asyncio.wait_for(coro, timeout=2.0)` 包住完整影子请求 |
| 客户端断连终止两端 | `request.is_disconnected()` 检测后取消影子任务并释放主端连接 |
| 通信实际退出后才归还名额 | 名额在 `run_shadow` 的 `finally` 中释放 |
| 不整份缓存/落盘，内存限 96MiB | 仅保存 64KiB 块与哈希状态；compose `mem_limit: 96m`，实测峰值 < 60MiB |
| HMAC 签名：GET/路径查询串/时间戳/nonce 换行连接 | `compute_signature()`；浏览器端 `hmacSha256Hex()` 同构实现 |
| ±60s 时间窗口、常量时间比较 | `verify_request()` + `hmac.compare_digest` |
| nonce 一次性、并发重放进不了上游 | `NonceStore.check_and_consume()` 锁内原子裁决 |
| 最多 1024 个有效 nonce，满则拒新 | `NonceStore` 容量控制 + 过期惰性清理，满额 503 |
| 失败/重放/满额不请求上游、不占影子名额 | 路由先 `verify_request()` 再 `proxy()`，拒绝路径完全在代理逻辑之前 |

## 启动

### Docker Compose（推荐）

```bash
# 可选: 覆盖开发默认密钥
export SIGNING_SECRET=$(openssl rand -hex 32)
docker compose up --build
# 网页控制台:  http://localhost:8000/
# 网关健康检查: http://localhost:8000/healthz
```

compose 已为网关注入 `SIGNING_SECRET`（默认开发值 `dev-only-signing-secret-change-me`，
生产请用环境变量覆盖）、`SIGN_WINDOW_S=60`、`MAX_NONCES=1024`。
打开网页后在第①区输入同一密钥即可签名发请求。

### 本地直接运行（无 Docker）

```bash
python3 -m pip install -r requirements.txt   # 或使用虚拟环境
SIGNING_SECRET=dev-only-signing-secret-change-me bash scripts/run_local.sh
```

## 报价服务的可控参数（query string 会被网关原样转发，并参与签名）

| 参数 | 作用 |
| --- | --- |
| `delay=<秒>` | 两端首字节前共同延迟 |
| `p_delay` / `s_delay` | 仅主端 / 仅影子端延迟（验证超时隔离） |
| `diff=1` | 仅影子端制造差异（JSON 改价 / 大响应改首字节） |
| `status=<码>` | 自定义 HTTP 状态码（验证原状态码透传） |
| `fail=1` | 两端返回相同的 500 |
| `size=<字节>` | `/quote-big` 响应大小，默认 33554432（32MiB） |
| `chunk_ms=<毫秒>` | 大响应每块间隔（验证流式与客户端断连） |

## 网页控制台

- ①区输入签名密钥（仅本页内存，不上传/不持久化），并展示服务端公开签名参数。
- ②区表单可设置延迟、并发数（最多 20，每请求独立时间戳与 nonce）、差异/失败场景并**并发发起**。
- ③区一键演示正常请求、并发重放、错签、过期时间戳、缺头及对应拒绝原因。
- 右上"主端响应（逐块）"按请求分 Tab，展示每块序号、字节数与内容预览及累计字节。
- 右下"比对记录"每 1.5s 自动刷新：结果药丸、两端状态码、耗时、SHA-256 摘要与原因
  （只有验签通过的请求才会出现记录）。

## 管理 API

- `GET /healthz`：上下游地址、影子在途数、容量、超时配置、签名/nonce 状态（不含密钥）。
- `GET /api/records`：比对记录（最新在前，内存环形缓冲，默认保留 100 条）。
- `GET /api/state`：影子在途数、记录数、峰值 RSS、有效 nonce 数、各类验签拒绝计数。
- `GET /api/sign-config`：浏览器签名所需公开参数（算法、头名、窗口、容量、签名串格式）。

## 自测

```bash
# 先按 scripts/run_local.sh 启动三服务(默认 8000/8001/8002), 然后:
python3 tests/selftest.py http://127.0.0.1:8000
```

覆盖：
- 原有：一致/不一致比对、主端字节与状态码原样透传、影子 2s 超时隔离、4 名额满跳过且注明原因、
  名额归还、32MiB 流式完整性与摘要、96MiB 内存约束、客户端断连双端终止。
- 新增：缺头/错密钥/路径不匹配 401、过去与未来超窗 401、窗口内放行、
  串行重放 401、**8 并发同签名恰好 1 个放行且只产生 1 条上游记录**、
  拒绝计数累加、辅助网关（`MAX_NONCES=4, SIGN_WINDOW_S=2`）满额 503、
  过期惰性清理后容量恢复、过期旧签名再用被拒。
