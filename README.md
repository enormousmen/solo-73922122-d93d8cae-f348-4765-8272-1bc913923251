# 单进程影子流量网关（FastAPI + aiohttp）

新版报价接口上线前的旁路比对网关：固定并行调用**主端**与**影子端**两个本地 GET 报价服务，
客户端只收到主端的原始状态码与原始字节；影子端的慢、失败、超时完全不影响主响应。

## 架构

```
浏览器 (web 控制台)
      │  GET /quote, /quote-big
      ▼
┌──────────────── gateway (FastAPI, 单进程, mem_limit 96m) ───────────────┐
│  名额信号量(最多4)  并行 aiohttp 调用  流式 SHA-256  比对记录(内存环形) │
└───────┬───────────────────────────────────────────┬────────────────────┘
        ▼                                           ▼
   primary:8000 (主报价服务)                  shadow:8000 (影子报价服务)
   响应原样透传给客户端                         只做摘要/状态码比对
```

- 两端使用同一镜像 `shadow-gateway:latest`，以 `SERVICE_ROLE=primary|shadow` 区分。
- 网关只代理 `GET /quote` 与 `GET /quote-big`；网页与 `/api/*` 管理接口不拦截。

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

## 启动

### Docker Compose（推荐）

```bash
docker compose up --build
# 网页控制台:  http://localhost:8000/
# 网关健康检查: http://localhost:8000/healthz
```

### 本地直接运行（无 Docker）

```bash
python -m venv .venv
.venv/bin/pip install -r requirements.txt
bash scripts/run_local.sh
```

## 报价服务的可控参数（query string 会被网关原样转发）

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

- 左侧表单可设置延迟、并发数（最多 20）、差异/失败场景并**并发发起**。
- 右上"主端响应（逐块）"按请求分 Tab，展示每块序号、字节数与内容预览及累计字节。
- 右下"比对记录"每 1.5s 自动刷新：结果药丸（一致/不一致/影子超时/影子失败/名额满跳过/断连…）、
  两端状态码、耗时、SHA-256 摘要与原因。

## 管理 API

- `GET /healthz`：上下游地址、影子在途数、容量、超时配置。
- `GET /api/records`：比对记录（最新在前，内存环形缓冲，默认保留 100 条）。
- `GET /api/state`：影子在途数、记录数、网关峰值 RSS。

## 自测

```bash
# 先按 scripts/run_local.sh 启动三服务, 然后:
.venv/bin/python -I tests/selftest.py http://127.0.0.1:8000
```

覆盖：一致/不一致比对、主端字节与状态码原样透传、影子 2s 超时隔离、4 名额满跳过且注明原因、
名额归还、32MiB 流式完整性与摘要、96MiB 内存约束、客户端断连双端终止。
