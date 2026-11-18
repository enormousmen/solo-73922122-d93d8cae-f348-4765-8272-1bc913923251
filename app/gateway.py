"""
单进程影子流量网关 (FastAPI + aiohttp)

- 固定两个本地 GET 报价服务: 主端 PRIMARY_URL / 影子端 SHADOW_URL
- 两端并行调用, 客户端只收到主端的原始状态码和原始字节(逐块透传)
- 影子慢/失败/超时(发起起 2s)只影响影子, 不拖住主响应
- 两端各自流式计算 SHA-256, 两端都完整结束才比较状态码与摘要
- 最多 4 个影子并发, 名额满时跳过影子并注明原因, 主请求照常通过
- 客户端断连同时终止两端; 影子通信实际退出后才归还名额
- 不整份缓存/落盘响应, 每块读取后立即更新哈希并释放

HMAC-SHA256 验签与防重放 (仅 GET /quote 与 /quote-big):
- 签名串依次以换行连接 GET、原始路径及查询串、秒级时间戳、一次性随机数
- 密钥只从服务端环境变量 SIGNING_SECRET 读取; 时间戳与服务端相差不超过 60s
- 同一 nonce 在签名有效期内只放行一次; 单进程最多保留 1024 个有效 nonce, 满则拒新
- 验签失败/重放/满额直接拒绝, 不请求主端与影子端, 不占影子名额
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import logging
import os
import resource
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Optional

import aiohttp
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

PRIMARY_URL = os.environ.get("PRIMARY_URL", "http://primary:8001")
SHADOW_URL = os.environ.get("SHADOW_URL", "http://shadow:8002")
MAX_SHADOW_CALLS = int(os.environ.get("MAX_SHADOW_CALLS", "4"))
SHADOW_TIMEOUT_S = float(os.environ.get("SHADOW_TIMEOUT_S", "2.0"))
READ_CHUNK = 64 * 1024
MAX_RECORDS = int(os.environ.get("MAX_RECORDS", "100"))

# ---- HMAC-SHA256 验签 / 防重放配置 (仅作用于 GET /quote 与 /quote-big) ----
# 密钥只从服务端环境读取, 不接受请求传入, 不随响应/日志/页面输出
SIGNING_SECRET = os.environ.get("SIGNING_SECRET", "")
SIGN_WINDOW_S = int(os.environ.get("SIGN_WINDOW_S", "60"))
MAX_NONCES = int(os.environ.get("MAX_NONCES", "1024"))
MAX_NONCE_LEN = 128
HMAC_ALGO = "HMAC-SHA256"
HDR_TS = "X-Sign-Timestamp"
HDR_NONCE = "X-Sign-Nonce"
HDR_SIG = "X-Sign"
HDR_ALGO = "X-Sign-Algorithm"

HOP_BY_HOP = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade",
    # 长度由实际透传的字节流重新决定, 避免上游声明与透传块边界不一致
    "content-length",
}

# 已定性的终态: finalize 不得覆盖
TERMINAL_RESULTS = {
    "match", "mismatch", "shadow_timeout", "shadow_error",
    "client_disconnected", "primary_error", "primary_incomplete",
    "shadow_skipped_no_slot",
}


@dataclass
class ShadowLimiter:
    """影子名额: acquire 到 release 之间覆盖整个影子通信的生命周期。"""
    capacity: int = MAX_SHADOW_CALLS
    in_flight: int = 0
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    async def acquire(self) -> bool:
        async with self.lock:
            if self.in_flight >= self.capacity:
                return False
            self.in_flight += 1
            return True

    async def release(self) -> None:
        async with self.lock:
            self.in_flight -= 1


class NonceStore:
    """
    一次性随机数存储 (单进程内存, 不落盘):

    - key=nonce, value=该签名的失效时刻 (秒级时间戳 + 窗口)
    - 同一 nonce 在签名仍有效期间只允许消费一次, 并发下由同一把锁串行裁决,
      check-and-insert 原子完成, 并发重放也无法进入上游
    - 容量上限 MAX_NONCES (默认 1024); 先清过期项, 仍满则拒绝新请求
    - 过期项惰性清理: 每次校验时顺手清除, 不做后台定时任务
    """

    def __init__(self, capacity: int = MAX_NONCES, window_s: int = SIGN_WINDOW_S):
        self.capacity = capacity
        self.window_s = window_s
        self._nonces: dict[str, int] = {}
        self.lock = asyncio.Lock()

    def _purge_expired(self, now: int) -> None:
        expired = [n for n, exp in self._nonces.items() if exp <= now]
        for n in expired:
            del self._nonces[n]

    async def check_and_consume(self, nonce: str, ts: int, now: int) -> tuple[bool, str]:
        """返回 (是否放行, 拒绝原因)。放行时 nonce 立即登记, 重放再来必被拒。"""
        async with self.lock:
            self._purge_expired(now)
            if nonce in self._nonces:
                return False, "replay: nonce has already been used"
            if len(self._nonces) >= self.capacity:
                return False, (
                    f"nonce store full: {self.capacity} valid nonces retained, "
                    "retry after the window expires"
                )
            # 登记到该签名自身失效为止: 失效前重放必拦, 失效后惰性清除腾出名额
            self._nonces[nonce] = ts + self.window_s
            return True, ""

    def count(self) -> int:
        return len(self._nonces)


@dataclass
class CallContext:
    rid: str
    target: str
    started_at: float
    primary_done: bool = False
    shadow_done: bool = False
    saved: bool = False
    record: Optional[dict] = None
    shadow_task: Optional[asyncio.Task] = None


state: dict = {}
# 后台影子任务的强引用集合: 防止生成器返回后 ctx 被回收导致任务被 GC 销毁,
# 任务完成时通过 done_callback 自行移除
background_tasks: set[asyncio.Task] = set()


@asynccontextmanager
async def lifespan(app: FastAPI):
    connector = aiohttp.TCPConnector(limit=64)
    # 主端不用总超时(由客户端断连控制), 仅设连接级保护
    timeout = aiohttp.ClientTimeout(total=None, sock_connect=5, sock_read=30)
    state["session"] = aiohttp.ClientSession(connector=connector, timeout=timeout)
    state["limiter"] = ShadowLimiter()
    state["records"] = []
    state["records_lock"] = asyncio.Lock()
    state["nonce_store"] = NonceStore()
    # 验签拒绝计数: 按原因归类, 证明拒绝发生在上游调用之前
    state["auth_rejected"] = {
        "missing_headers": 0,
        "bad_signature": 0,
        "timestamp_expired": 0,
        "replay": 0,
        "nonce_store_full": 0,
        "secret_not_configured": 0,
    }
    try:
        yield
    finally:
        await state["session"].close()


app = FastAPI(title="shadow-traffic-gateway", lifespan=lifespan)


def now_ms() -> int:
    return int(time.time() * 1000)


def _reject(reason_key: str, detail: str, status_code: int = 401) -> JSONResponse:
    """统一的验签拒绝出口: 在此之前绝不触碰主端/影子端, 也不占影子名额。"""
    state["auth_rejected"][reason_key] = state["auth_rejected"].get(reason_key, 0) + 1
    logging.getLogger("auth").warning("rejected quote request: %s", detail)
    return JSONResponse(
        status_code=status_code,
        content={"detail": detail, "rejected_before_upstream": True},
    )


def compute_signature(secret: str, method: str, path_and_query: str,
                      timestamp: str, nonce: str) -> str:
    """签名串: method、原始路径及查询串、秒级时间戳、nonce 依次以换行连接。"""
    message = "\n".join([method, path_and_query, timestamp, nonce])
    return hmac.new(secret.encode("utf-8"),
                    message.encode("utf-8"), hashlib.sha256).hexdigest()


async def verify_request(request: Request) -> Optional[JSONResponse]:
    """
    校验 GET /quote 与 /quote-big 的 HMAC-SHA256 签名与一次性 nonce。

    顺序: 头存在性 -> 算法标识 -> 时间戳窗口 -> 签名常量时间比较 -> nonce 原子消费。
    任一步失败立即返回 JSONResponse(401/503), 放行返回 None。
    """
    if not SIGNING_SECRET:
        # 服务端未配置密钥属于部署故障: 直接拒绝, 绝不退化为免签放行
        return _reject(
            "secret_not_configured",
            "server signing secret is not configured",
            status_code=503,
        )

    timestamp = request.headers.get(HDR_TS, "")
    nonce = request.headers.get(HDR_NONCE, "")
    signature = request.headers.get(HDR_SIG, "")
    if not timestamp or not nonce or not signature:
        return _reject(
            "missing_headers",
            f"missing signing header(s): require {HDR_TS}, {HDR_NONCE}, {HDR_SIG}",
        )
    if request.headers.get(HDR_ALGO, HMAC_ALGO) != HMAC_ALGO:
        return _reject("bad_signature", f"unsupported sign algorithm, require {HMAC_ALGO}")

    # 秒级时间戳, 与服务端时钟相差不超过 SIGN_WINDOW_S 秒
    if not timestamp.isdigit():
        return _reject("bad_signature", "timestamp must be a unix epoch in seconds")
    ts = int(timestamp)
    now = int(time.time())
    if abs(now - ts) > SIGN_WINDOW_S:
        return _reject(
            "timestamp_expired",
            f"timestamp out of window: |server_time - timestamp| > {SIGN_WINDOW_S}s "
            f"(timestamp={timestamp}, server_time={now})",
        )

    if len(nonce) > MAX_NONCE_LEN or not nonce.isascii():
        return _reject("bad_signature",
                       f"nonce must be ascii and no longer than {MAX_NONCE_LEN} chars")

    # 原始路径及查询串: 与浏览器/客户端签名时使用的字符串完全一致
    path_and_query = request.url.path
    if request.url.query:
        path_and_query += "?" + request.url.query
    expected = compute_signature(SIGNING_SECRET, request.method,
                                 path_and_query, timestamp, nonce)
    if not hmac.compare_digest(expected, signature.strip().lower()):
        return _reject("bad_signature", "HMAC-SHA256 signature verification failed")

    # 签名有效: 原子地消费 nonce。锁内 check-and-insert, 并发重放只有一个能通过
    ok, reason = await state["nonce_store"].check_and_consume(nonce, ts, now)
    if not ok:
        if reason.startswith("replay"):
            return _reject("replay", reason)
        return _reject("nonce_store_full", reason, status_code=503)
    return None


async def append_record(rec: dict) -> None:
    async with state["records_lock"]:
        recs = state["records"]
        recs.append(rec)
        if len(recs) > MAX_RECORDS:
            del recs[:-MAX_RECORDS]


def filtered_headers(resp: aiohttp.ClientResponse) -> dict[str, str]:
    return {k: v for k, v in resp.headers.items() if k.lower() not in HOP_BY_HOP}


async def run_shadow(ctx: CallContext) -> None:
    """
    执行一次影子调用 (从发起起整体 2s 硬超时)。
    无论成功/失败/超时/取消, 通信实际退出后才归还影子名额。
    只更新记录字段, 记录统一由主端生命周期落库, 避免出现半条记录。
    """
    acquired = ctx.record.get("shadow") == "started"
    rec = ctx.record
    try:
        session = state["session"]
        try:
            coro = session.get(SHADOW_URL + ctx.target, allow_redirects=False)
            # wait_for 从任务创建(发起)时刻起计时, 超时只取消影子请求
            async with await asyncio.wait_for(coro, timeout=SHADOW_TIMEOUT_S) as resp:
                shadow_status = resp.status
                shadow_hash = hashlib.sha256()
                async for chunk in resp.content.iter_chunked(READ_CHUNK):
                    shadow_hash.update(chunk)  # 流式哈希, 不缓存整份响应
                shadow_digest = shadow_hash.hexdigest()
        except asyncio.TimeoutError:
            rec["result"] = "shadow_timeout"
            rec["shadow"] = f"timeout after {SHADOW_TIMEOUT_S:g}s"
            return
        except asyncio.CancelledError:
            # 客户端断连或主端失败: 影子随主端一起终止
            rec["result"] = "client_disconnected"
            rec["shadow"] = "cancelled with primary"
            raise
        except aiohttp.ClientError as exc:
            rec["result"] = "shadow_error"
            rec["shadow"] = f"connection error: {type(exc).__name__}"
            return
        except Exception as exc:  # 防御: 影子侧任何意外都不能拖垮主流程
            logging.getLogger("shadow").exception("shadow task failed: %r", exc)
            rec["result"] = "shadow_error"
            rec["shadow"] = f"unexpected error: {type(exc).__name__}: {exc}"
            return

        rec["shadow_status"] = shadow_status
        rec["shadow_sha256"] = shadow_digest
        rec["shadow_ms"] = now_ms() - ctx.started_at
        rec["shadow"] = "completed"

        if not ctx.primary_done:
            # 主端尚未完整结束, 暂时不能比较; 最终结果由 finalize 补算
            rec["result"] = "shadow_completed_primary_incomplete"
            return

        _compare(rec)
    finally:
        ctx.shadow_done = True
        if acquired:
            # 通信实际退出(含超时/取消)后才归还名额
            await state["limiter"].release()
        if not ctx.primary_done:
            # 主端未完整(客户端断连/主端失败): 记录由主端生命周期保存
            return
        # 主端已完整: 影子在此收口, 把最终结果写回已落库的记录(原地更新)
        finalize(rec, ctx)
        if not ctx.saved:
            await save_record(ctx)


def _compare(rec: dict) -> None:
    """两端都完整结束后才调用: 比较状态码与 SHA-256 摘要。"""
    same_status = rec["shadow_status"] == rec["primary_status"]
    same_digest = rec["shadow_sha256"] == rec["primary_sha256"]
    if same_status and same_digest:
        rec["result"] = "match"
    else:
        rec["result"] = "mismatch"
        if not same_status:
            rec["detail"] = (
                f"status differs: primary={rec['primary_status']} "
                f"shadow={rec['shadow_status']}"
            )
        else:
            rec["detail"] = "same status but sha256 differs"


def finalize(rec: dict, ctx: CallContext) -> None:
    """主端完整结束后的统一收口: 补算比较结果。"""
    # 终态(断连/超时/失败等)不得被覆盖
    if rec["result"] in TERMINAL_RESULTS:
        return
    if not ctx.shadow_done:
        # 影子仍在跑(受 2s 硬超时保护): 先挂起, 等其退出时再更新,
        # 绝不能在未收完整时报一致
        rec["result"] = "shadow_pending"
        rec["shadow"] = "in flight"
        return
    # 影子已完整且主端也完整 -> 若之前挂着 incomplete 标记则补算
    if rec["result"] in ("shadow_completed_primary_incomplete", "shadow_pending"):
        _compare(rec)
    elif rec["result"] == "pending":
        # 理论上不进入(无影子任务时走 skipped 分支), 兜底
        rec["result"] = "unknown"


async def save_record(ctx: CallContext) -> None:
    """记录只落库一次: 谁先收口谁保存。"""
    if ctx.saved:
        return
    ctx.saved = True
    await append_record(ctx.record)


async def proxy(request: Request, target: str) -> StreamingResponse:
    rid = f"r{now_ms()}-{id(request) % 100000:05d}"
    started = now_ms()
    rec: dict = {
        "id": rid,
        "target": target,
        "started_at": started,
        "result": "pending",
        "primary": "pending",
        "shadow": "not_started",
    }
    ctx = CallContext(rid=rid, target=target, started_at=started, record=rec)

    # 先占影子名额(非阻塞); 满了直接跳过, 但主请求照常通过
    if await state["limiter"].acquire():
        rec["shadow"] = "started"
        task = asyncio.create_task(run_shadow(ctx))
        ctx.shadow_task = task
        background_tasks.add(task)
        task.add_done_callback(background_tasks.discard)
    else:
        rec["shadow"] = "skipped"
        rec["result"] = "shadow_skipped_no_slot"
        rec["detail"] = (
            f"shadow skipped: {MAX_SHADOW_CALLS} shadow calls already in flight"
        )

    session = state["session"]
    try:
        primary_resp = await session.get(PRIMARY_URL + target, allow_redirects=False)
    except (aiohttp.ClientError, asyncio.TimeoutError, OSError) as exc:
        rec["primary"] = f"connection error: {type(exc).__name__}"
        rec["result"] = "primary_error"
        if ctx.shadow_task is not None:
            # 主端连接失败: 终止已发起的影子; 名额由任务自身在退出时归还
            ctx.shadow_task.cancel()
            try:
                await ctx.shadow_task
            except (asyncio.CancelledError, Exception):
                pass
        await save_record(ctx)
        return JSONResponse(
            status_code=502,
            content={"detail": "primary quote service unavailable"},
        )

    async def body_iter():
        primary_hash = hashlib.sha256()
        try:
            async for chunk in primary_resp.content.iter_chunked(READ_CHUNK):
                if await request.is_disconnected():
                    raise asyncio.CancelledError
                primary_hash.update(chunk)  # 流式哈希, 不缓存整份响应
                yield chunk
        except asyncio.CancelledError:
            # 客户端断连: 同时终止主端读取与影子调用
            rec["primary"] = "aborted before completion"
            rec["result"] = "client_disconnected"
            primary_resp.release()
            if ctx.shadow_task is not None and not ctx.shadow_task.done():
                ctx.shadow_task.cancel()
            if ctx.shadow_task is not None:
                # 等待影子通信实际退出(名额随之归还), 但此路径下客户端已离开
                try:
                    await asyncio.shield(ctx.shadow_task)
                except (asyncio.CancelledError, Exception):
                    pass
            await save_record(ctx)
            return
        except aiohttp.ClientError as exc:
            # 主端传输中途断开: 主响应不完整, 同样终止影子
            rec["primary"] = f"stream error: {type(exc).__name__}"
            rec["result"] = "primary_incomplete"
            primary_resp.release()
            if ctx.shadow_task is not None and not ctx.shadow_task.done():
                ctx.shadow_task.cancel()
            if ctx.shadow_task is not None:
                try:
                    await asyncio.shield(ctx.shadow_task)
                except (asyncio.CancelledError, Exception):
                    pass
            await save_record(ctx)
            return

        # 主端完整结束: 客户端响应到此立刻收尾, 不等待影子
        primary_resp.release()
        ctx.primary_done = True
        rec["primary_status"] = primary_resp.status
        rec["primary_sha256"] = primary_hash.hexdigest()
        rec["primary_ms"] = now_ms() - started
        rec["primary"] = "completed"

        if ctx.shadow_task is None:
            # 名额满被跳过: 没有影子结果, 不产生一致性结论
            await save_record(ctx)
            return

        # 主端响应到此完整结束并立即返回客户端, 不等待影子
        finalize(rec, ctx)
        await save_record(ctx)  # 影子仍在跑时先落 shadow_pending, 其退出后原地更新

    return StreamingResponse(
        body_iter(),
        status_code=primary_resp.status,
        headers=filtered_headers(primary_resp),
        media_type=primary_resp.headers.get("Content-Type"),
    )


@app.get("/healthz")
async def healthz():
    lim: ShadowLimiter = state["limiter"]
    nonces: NonceStore = state["nonce_store"]
    return {
        "status": "ok",
        "primary": PRIMARY_URL,
        "shadow": SHADOW_URL,
        "shadow_in_flight": lim.in_flight,
        "shadow_capacity": lim.capacity,
        "shadow_timeout_s": SHADOW_TIMEOUT_S,
        "signing": {
            "algorithm": HMAC_ALGO,
            "window_s": SIGN_WINDOW_S,
            "secret_configured": bool(SIGNING_SECRET),
            "nonce_retained": nonces.count(),
            "nonce_capacity": nonces.capacity,
        },
    }


@app.get("/api/records")
async def get_records():
    async with state["records_lock"]:
        return list(reversed(state["records"]))


@app.get("/api/state")
async def get_state():
    lim: ShadowLimiter = state["limiter"]
    nonces: NonceStore = state["nonce_store"]
    rss_kb = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return {
        "shadow_in_flight": lim.in_flight,
        "shadow_capacity": lim.capacity,
        "records": len(state["records"]),
        "max_rss_mib": round(rss_kb / 1024, 2),
        "nonce_retained": nonces.count(),
        "nonce_capacity": nonces.capacity,
        "sign_window_s": SIGN_WINDOW_S,
        "secret_configured": bool(SIGNING_SECRET),
        "auth_rejected": dict(state["auth_rejected"]),
    }


@app.get("/api/sign-config")
async def sign_config():
    """只返回浏览器签名所需的公开参数, 绝不返回密钥本身。"""
    return {
        "algorithm": HMAC_ALGO,
        "method": "GET",
        "headers": {
            "timestamp": HDR_TS,
            "nonce": HDR_NONCE,
            "signature": HDR_SIG,
            "algorithm": HDR_ALGO,
        },
        "window_s": SIGN_WINDOW_S,
        "max_nonce_len": MAX_NONCE_LEN,
        "nonce_capacity": MAX_NONCES,
        "secret_configured": bool(SIGNING_SECRET),
        "canonical_string": "GET\\n<原始路径及查询串>\\n<秒级时间戳>\\n<一次性随机数>",
    }


# 报价相关 GET 请求走代理; 网页与管理 API 不拦截
@app.get("/quote")
@app.get("/quote-big")
async def quote_proxy(request: Request):
    # 先验签再触碰任何上游: 失败/重放/满额都不会请求主端与影子端, 不占影子名额
    rejected = await verify_request(request)
    if rejected is not None:
        return rejected
    target = request.url.path
    if request.url.query:
        target += "?" + request.url.query
    return await proxy(request, target)


app.mount("/", StaticFiles(
    directory=os.path.join(os.path.dirname(__file__), "web"), html=True),
    name="web")
