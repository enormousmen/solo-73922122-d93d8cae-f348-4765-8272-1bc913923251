"""
本地 GET 报价服务, 主端与影子端共用同一镜像, 用 SERVICE_ROLE 区分。

能力:
- GET /quote            普通 JSON 报价 (两端默认字节完全一致)
- GET /quote-big        流式大响应 (默认 32 MiB, 确定性字节, 两端一致)
- GET /healthz          健康检查

可控参数 (query string 会被网关原样转发):
- delay=<秒>            首字节前延迟 (两端各自生效)
- p_delay / s_delay     仅主端 / 仅影子端生效的延迟
- status=<码>           自定义 HTTP 状态码
- fail=1                立即返回 500
- diff=1                影子端制造可比对的差异 (主端忽略)
- size=<字节>           /quote-big 的响应大小 (默认 33554432 = 32MiB)
- chunk_ms=<毫秒>       /quote-big 每块之间的延迟, 便于观察流式行为
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import os

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, StreamingResponse

ROLE = os.environ.get("SERVICE_ROLE", "primary")
PORT = int(os.environ.get("SERVICE_PORT", "8000"))
DEFAULT_BIG = 32 * 1024 * 1024  # 32 MiB
BIG_CHUNK = 256 * 1024

app = FastAPI(title=f"quote-service-{ROLE}")


def _delay_params(request: Request) -> float:
    q = request.query_params
    delay = float(q.get("delay", "0"))
    if ROLE == "primary":
        delay += float(q.get("p_delay", "0"))
    else:
        delay += float(q.get("s_delay", "0"))
    return delay


def _base_quote(request: Request) -> dict:
    # 确定性内容: 不含时间戳/随机数, 保证两端默认响应字节一致
    return {
        "symbol": request.query_params.get("symbol", "ACME"),
        "currency": "USD",
        "price": "128.50",
        "qty": 1000,
        "tier": "standard",
        "conditions": ["firm", "spot", "net"],
    }


@app.get("/healthz")
async def healthz():
    return {"status": "ok", "role": ROLE}


@app.get("/quote")
async def quote(request: Request):
    delay = _delay_params(request)
    if delay:
        # 必须是非阻塞睡眠: 单 worker 内 time.sleep 会堵住其他在途请求
        await asyncio.sleep(delay)

    q = request.query_params
    status = int(q.get("status", "200"))

    if q.get("fail") == "1":
        return JSONResponse(status_code=500, content={
            "error": "forced failure",
        })

    body = _base_quote(request)
    # diff 仅影子端生效, 主端忽略 -> 制造可被摘要比对发现的差异
    if ROLE == "shadow" and q.get("diff") == "1":
        body["price"] = "129.75"
        body["shadow_diff"] = True
        status = int(q.get("s_status", str(status)))

    payload = json.dumps(body, separators=(",", ":"), sort_keys=True).encode()
    # 两端响应头保持一致, 差异只体现在 body 上, 避免干扰字节级比对
    return JSONResponse(status_code=status, content=json.loads(payload))


def _deterministic_block(index: int, size: int) -> bytes:
    """
    生成确定性的块内容: 块级种子经 SHA-256 派生后重复填充,
    两端同参数产出完全相同的字节流, 且无需逐字节 Python 循环。
    """
    seed = hashlib.sha256(f"quote-big:{index}".encode()).digest()
    repeats = (size // len(seed)) + 1
    return (seed * repeats)[:size]


@app.get("/quote-big")
async def quote_big(request: Request):
    delay = _delay_params(request)
    q = request.query_params
    size = int(q.get("size", str(DEFAULT_BIG)))
    size = max(0, min(size, 64 * 1024 * 1024))
    chunk_ms = int(q.get("chunk_ms", "0"))
    status = int(q.get("status", "200"))

    if q.get("fail") == "1":
        return JSONResponse(status_code=500, content={
            "error": "forced failure",
        })

    shadow_diff = ROLE == "shadow" and q.get("diff") == "1"

    async def gen():
        if delay:
            await asyncio.sleep(delay)
        remaining = size
        index = 0
        while remaining > 0:
            n = min(BIG_CHUNK, remaining)
            block = _deterministic_block(index, n)
            if shadow_diff and index == 0:
                block = b"X" + block[1:]  # 首字节差异, 摘要必然不同
            yield block
            remaining -= n
            index += 1
            if chunk_ms:
                await asyncio.sleep(chunk_ms / 1000.0)

    return StreamingResponse(
        gen(),
        status_code=status,
        media_type="application/octet-stream",
        headers={"X-Response-Bytes": str(size)},
    )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=PORT)
