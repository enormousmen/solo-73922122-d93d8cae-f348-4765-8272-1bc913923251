"""关键功能自测脚本: 通过真实 HTTP 并发压测网关行为。"""
import asyncio
import hashlib
import json
import sys
import time

import aiohttp

GW = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8020"
PASS, FAIL = [], []


def check(name, ok, detail=""):
    (PASS if ok else FAIL).append(name)
    print(f"[{'PASS' if ok else 'FAIL'}] {name} {detail}")


PENDING_RESULTS = {"shadow_pending", "shadow_completed_primary_incomplete", "pending"}


async def wait_record(s, gw, marker, timeout_s=5.0):
    """按 marker 轮询等待对应比对记录到达终态后返回。"""
    deadline = asyncio.get_event_loop().time() + timeout_s
    while asyncio.get_event_loop().time() < deadline:
        recs = await (await s.get(f"{gw}/api/records")).json()
        hit = [x for x in recs if marker in x["target"]]
        if hit and hit[0]["result"] not in PENDING_RESULTS:
            return hit[0]
        await asyncio.sleep(0.15)
    raise AssertionError(f"terminal record with {marker} not found")


async def main():
    run_id = f"run{int(time.time() * 1000) % 1000000}"
    async with aiohttp.ClientSession() as s:
        # 1. 基础一致: 主端原始字节透传 + match
        url = f"{GW}/quote?symbol=ZZZ&marker={run_id}-t1"
        async with s.get(url) as r:
            body = await r.read()
            gw_status = r.status
        rec = await wait_record(s, GW, f"marker={run_id}-t1")
        check("1 一致请求报 match", rec["result"] == "match", rec["result"])
        check("1 客户端收主端200", gw_status == 200)
        check("1 透传字节=主端原始字节",
              rec["primary_sha256"] == hashlib.sha256(body).hexdigest())

        # 2. diff 制造差异
        async with s.get(f"{GW}/quote?diff=1&marker={run_id}-t2") as r:
            await r.read()
        rec = await wait_record(s, GW, f"marker={run_id}-t2")
        check("2 diff 报 mismatch", rec["result"] == "mismatch", rec.get("detail", ""))
        check("2 摘要确实不同", rec["primary_sha256"] != rec["shadow_sha256"])

        # 3. 影子超时不拖住主端
        t0 = time.monotonic()
        async with s.get(f"{GW}/quote?s_delay=3&marker={run_id}-t3") as r:
            await r.read()
        elapsed = time.monotonic() - t0
        check("3 影子超时时主端快速返回", elapsed < 0.5, f"{elapsed:.3f}s")
        rec = await wait_record(s, GW, f"marker={run_id}-t3")
        check("3 记录为 shadow_timeout", rec["result"] == "shadow_timeout", rec["shadow"])

        # 4. 名额: 6 个真并发(各自独立 TCP 连接), 影子延迟占住名额, 主端零延迟
        async def one(i):
            # 独立 connector 保证 6 个请求同时在途, 而不是单连接流水线串行
            async with aiohttp.ClientSession() as cs:
                async with cs.get(f"{GW}/quote?s_delay=1.2&marker={run_id}-t4-{i}") as r:
                    return r.status, time.monotonic()
        t0 = time.monotonic()
        results = await asyncio.gather(*(one(i) for i in range(6)))
        wall = time.monotonic() - t0
        check("4 六个主请求全部200", all(st == 200 for st, _ in results))
        # 主端无延迟: 若被影子名额/影子通信阻塞, 墙钟会接近 1.2s
        check("4 主请求不被影子名额阻塞", wall < 0.8, f"wall={wall:.2f}s")
        await asyncio.sleep(0.3)
        recs = (await (await s.get(f"{GW}/api/records")).json())
        batch = [x for x in recs if f"marker={run_id}-t4-" in x["target"]]
        skipped = [x for x in batch if x["result"] == "shadow_skipped_no_slot"]
        # 6 个请求有毫秒级启动抖动: 期望 2~3 个跳过(容量 4), 关键是满额即跳且主端不阻塞
        check("4 名额满导致跳过(6并发/4名额)", 2 <= len(skipped) <= 3,
              f"skipped={len(skipped)}/6")
        check("4 跳过注明原因", all("already in flight" in x.get("detail", "")
                                    for x in skipped))

        # 5. 名额归还: 等测试4的影子通信实际退出后, 新请求影子恢复
        for _ in range(30):
            st = await (await s.get(f"{GW}/api/state")).json()
            if st["shadow_in_flight"] == 0:
                break
            await asyncio.sleep(0.2)
        async with s.get(f"{GW}/quote?marker={run_id}-t5") as r:
            await r.read()
        rec = await wait_record(s, GW, f"marker={run_id}-t5")
        check("5 名额已归还影子恢复", rec["shadow"] == "completed", rec["shadow"])

        # 6. 32MiB 流式: 字节完整、摘要一致、网关不缓存
        async with s.get(f"{GW}/quote-big?marker={run_id}-t6") as r:
            h = hashlib.sha256()
            total = 0
            async for chunk in r.content.iter_chunked(65536):
                h.update(chunk)
                total += len(chunk)
        check("6 32MiB 字节数=33554432", total == 32 * 1024 * 1024, str(total))
        rec = await wait_record(s, GW, f"marker={run_id}-t6")
        check("6 大响应两端 match", rec["result"] == "match", rec["result"])
        check("6 客户端流式摘要=主端摘要",
              h.hexdigest() == rec["primary_sha256"])
        state = await (await s.get(f"{GW}/api/state")).json()
        check("6 网关峰值RSS<96MiB",
              (state["max_rss_mib"] or 0) < 96, f"{state['max_rss_mib']}MiB")

        # 7. 客户端提前断连: 两端都终止, 名额最终归还
        try:
            async with s.get(f"{GW}/quote-big?chunk_ms=50&marker={run_id}-t7") as r:
                count = 0
                async for _ in r.content.iter_chunked(65536):
                    count += 1
                    if count >= 3:
                        break
        except Exception:
            pass
        # 记录在影子通信实际退出后才落库: 轮询等待
        disc = []
        for _ in range(30):
            await asyncio.sleep(0.2)
            recs = (await (await s.get(f"{GW}/api/records")).json())
            disc = [x for x in recs if f"chunk_ms=50&marker={run_id}-t7" in x["target"]]
            if disc:
                break
        state = await (await s.get(f"{GW}/api/state")).json()
        check("7 断连有记录", len(disc) == 1, str(len(disc)))
        check("7 断连结果标记", disc and disc[0]["result"] == "client_disconnected",
              disc[0]["result"] if disc else "")
        check("7 断连后影子名额归零", state["shadow_in_flight"] == 0,
              str(state["shadow_in_flight"]))

    print(f"\n汇总: {len(PASS)} passed, {len(FAIL)} failed")
    if FAIL:
        print("失败项:", FAIL)
        sys.exit(1)


asyncio.run(main())
