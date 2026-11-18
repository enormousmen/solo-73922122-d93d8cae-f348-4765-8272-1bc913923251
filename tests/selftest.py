"""
关键功能自测脚本: 通过真实 HTTP 并发压测网关行为。

覆盖:
- 原有: 一致/不一致比对、逐块透传、影子超时隔离、名额跳过/归还、32MiB 流式、断连
- 新增 HMAC-SHA256 验签:
  * 正常签名放行 / 缺头 / 错签 / 路径不匹配 / 时间戳过期(过去与未来) / 窗口边界
  * 串行重放与并发重放: 同一签名只放行一次, 其余全部 401, 且不进入上游、不占影子名额
  * nonce 容量上限: 辅助网关(MAX_NONCES=4, 窗口 2s)满额拒新, 过期清理后恢复
  * 被拒请求不产生比对记录; /api/state 拒绝计数累加
"""
import asyncio
import hashlib
import hmac
import json
import os
import signal
import subprocess
import sys
import time

import aiohttp

GW = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8000"
SECRET = os.environ.get("SIGNING_SECRET", "dev-only-signing-secret-change-me")
PRIMARY_URL = os.environ.get("PRIMARY_URL", "http://127.0.0.1:8001")
SHADOW_URL = os.environ.get("SHADOW_URL", "http://127.0.0.1:8002")
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PASS, FAIL = [], []

HDR_TS = "X-Sign-Timestamp"
HDR_NONCE = "X-Sign-Nonce"
HDR_SIG = "X-Sign"
HDR_ALGO = "X-Sign-Algorithm"


def check(name, ok, detail=""):
    (PASS if ok else FAIL).append(name)
    print(f"[{'PASS' if ok else 'FAIL'}] {name} {detail}")


def sign_headers(target, ts=None, nonce=None, secret=SECRET):
    """与网关/浏览器严格同构: GET、原始路径及查询串、秒级时间戳、nonce 换行连接。"""
    ts = ts if ts is not None else str(int(time.time()))
    nonce = nonce if nonce is not None else hashlib.sha256(os.urandom(32)).hexdigest()
    message = "\n".join(["GET", target, ts, nonce])
    sig = hmac.new(secret.encode(), message.encode(), hashlib.sha256).hexdigest()
    return {HDR_TS: ts, HDR_NONCE: nonce, HDR_SIG: sig, HDR_ALGO: "HMAC-SHA256"}


def sget(s, url, **kw):
    headers = kw.pop("headers", None) or sign_headers(url[len(GW):] if url.startswith(GW) else url)
    return s.get(url, headers=headers, **kw)


PENDING_RESULTS = {"shadow_pending", "shadow_completed_primary_incomplete", "pending"}


async def wait_record(s, gw, marker, timeout_s=5.0):
    """按 marker 轮询等待对应比对记录到达终态后返回。"""
    loop = asyncio.get_event_loop()
    deadline = loop.time() + timeout_s
    while loop.time() < deadline:
        recs = await (await s.get(f"{gw}/api/records")).json()
        hit = [x for x in recs if marker in x["target"]]
        if hit and hit[0]["result"] not in PENDING_RESULTS:
            return hit[0]
        await asyncio.sleep(0.15)
    raise AssertionError(f"terminal record with {marker} not found")


async def records_with(s, gw, marker):
    recs = await (await s.get(f"{gw}/api/records")).json()
    return [x for x in recs if marker in x["target"]]


async def wait_epoch_at_least(target_epoch: int) -> None:
    """等待整秒级 Unix 时钟到达 target_epoch, 避免 sleep 固定秒数被亚秒对齐吞掉。"""
    while int(time.time()) < target_epoch:
        await asyncio.sleep(0.1)


def start_helper_gateway(port, max_nonces, window_s):
    """启动独立的辅助网关进程用于容量/过期清理测试, 测试结束后关闭。"""
    env = dict(os.environ)
    env.update({
        "SIGNING_SECRET": SECRET,
        "MAX_NONCES": str(max_nonces),
        "SIGN_WINDOW_S": str(window_s),
        "PRIMARY_URL": PRIMARY_URL,
        "SHADOW_URL": SHADOW_URL,
    })
    proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "app.gateway:app",
         "--host", "127.0.0.1", "--port", str(port)],
        cwd=REPO_ROOT, env=env,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    return proc


async def wait_health(s, base, timeout_s=15.0):
    loop = asyncio.get_event_loop()
    deadline = loop.time() + timeout_s
    while loop.time() < deadline:
        try:
            async with s.get(f"{base}/healthz") as r:
                if r.status == 200:
                    return await r.json()
        except aiohttp.ClientError:
            pass
        await asyncio.sleep(0.3)
    raise AssertionError(f"helper at {base} never became healthy")


async def main():
    run_id = f"run{int(time.time() * 1000) % 1000000}"
    helper_port = int(os.environ.get("HELPER_PORT", "8021"))
    helper = start_helper_gateway(helper_port, max_nonces=4, window_s=2)
    helper_base = f"http://127.0.0.1:{helper_port}"
    try:
        async with aiohttp.ClientSession() as s:
            await wait_health(s, helper_base)

            # 0. 管理接口与网页不需要签名
            async with s.get(f"{GW}/healthz") as r:
                check("0 健康检查免签可访问", r.status == 200)
            async with s.get(f"{GW}/api/sign-config") as r:
                cfg_text = await r.text()
                cfg = json.loads(cfg_text)
                check("0 签名配置不泄露密钥",
                      r.status == 200 and SECRET not in cfg_text
                      and cfg.get("algorithm") == "HMAC-SHA256",
                      str(cfg.get("algorithm")))

            # 1. 基础一致: 主端原始字节透传 + match
            url = f"{GW}/quote?symbol=ZZZ&marker={run_id}-t1"
            async with sget(s, url) as r:
                body = await r.read()
                gw_status = r.status
            rec = await wait_record(s, GW, f"marker={run_id}-t1")
            check("1 一致请求报 match", rec["result"] == "match", rec["result"])
            check("1 客户端收主端200", gw_status == 200)
            check("1 透传字节=主端原始字节",
                  rec["primary_sha256"] == hashlib.sha256(body).hexdigest())

            # 2. diff 制造差异
            async with sget(s, f"{GW}/quote?diff=1&marker={run_id}-t2") as r:
                await r.read()
            rec = await wait_record(s, GW, f"marker={run_id}-t2")
            check("2 diff 报 mismatch", rec["result"] == "mismatch", rec.get("detail", ""))
            check("2 摘要确实不同", rec["primary_sha256"] != rec["shadow_sha256"])

            # 3. 影子超时不拖住主端
            t0 = time.monotonic()
            async with sget(s, f"{GW}/quote?s_delay=3&marker={run_id}-t3") as r:
                await r.read()
            elapsed = time.monotonic() - t0
            check("3 影子超时时主端快速返回", elapsed < 0.5, f"{elapsed:.3f}s")
            rec = await wait_record(s, GW, f"marker={run_id}-t3")
            check("3 记录为 shadow_timeout", rec["result"] == "shadow_timeout", rec["shadow"])

            # 4. 名额: 6 个真并发(各自独立 TCP 连接), 影子延迟占住名额, 主端零延迟
            async def one(i):
                target = f"/quote?s_delay=1.2&marker={run_id}-t4-{i}"
                async with aiohttp.ClientSession() as cs:
                    async with cs.get(f"{GW}{target}", headers=sign_headers(target)) as r:
                        return r.status, time.monotonic()
            t0 = time.monotonic()
            results = await asyncio.gather(*(one(i) for i in range(6)))
            wall = time.monotonic() - t0
            check("4 六个主请求全部200", all(st == 200 for st, _ in results))
            check("4 主请求不被影子名额阻塞", wall < 0.8, f"wall={wall:.2f}s")
            await asyncio.sleep(0.3)
            batch = await records_with(s, GW, f"marker={run_id}-t4-")
            skipped = [x for x in batch if x["result"] == "shadow_skipped_no_slot"]
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
            async with sget(s, f"{GW}/quote?marker={run_id}-t5") as r:
                await r.read()
            rec = await wait_record(s, GW, f"marker={run_id}-t5")
            check("5 名额已归还影子恢复", rec["shadow"] == "completed", rec["shadow"])

            # 6. 32MiB 流式: 字节完整、摘要一致、网关不缓存
            async with sget(s, f"{GW}/quote-big?marker={run_id}-t6") as r:
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
                target = f"/quote-big?chunk_ms=50&marker={run_id}-t7"
                async with s.get(f"{GW}{target}", headers=sign_headers(target)) as r:
                    count = 0
                    async for _ in r.content.iter_chunked(65536):
                        count += 1
                        if count >= 3:
                            break
            except Exception:
                pass
            disc = []
            for _ in range(30):
                await asyncio.sleep(0.2)
                disc = await records_with(s, GW, f"chunk_ms=50&marker={run_id}-t7")
                if disc:
                    break
            state = await (await s.get(f"{GW}/api/state")).json()
            check("7 断连有记录", len(disc) == 1, str(len(disc)))
            check("7 断连结果标记", disc and disc[0]["result"] == "client_disconnected",
                  disc[0]["result"] if disc else "")
            check("7 断连后影子名额归零", state["shadow_in_flight"] == 0,
                  str(state["shadow_in_flight"]))

            # ============ HMAC 验签 / 防重放 ============
            before = await (await s.get(f"{GW}/api/state")).json()

            # 8. 缺少签名头: 裸请求 401, 不产生记录
            async with s.get(f"{GW}/quote?marker={run_id}-t8-noheader") as r:
                body = await r.json()
                check("8 缺签名头返回401", r.status == 401, str(r.status))
                check("8 拒绝发生在上游之前", body.get("rejected_before_upstream") is True)
            check("8 被拒请求无比对记录",
                  not await records_with(s, GW, f"marker={run_id}-t8-noheader"))

            # 9. 错误签名 / 错误密钥
            target = f"/quote?marker={run_id}-t9-badsig"
            bad_headers = sign_headers(target, secret="wrong-secret")
            async with s.get(f"{GW}{target}", headers=bad_headers) as r:
                check("9 错误密钥返回401", r.status == 401)
            # 签名与路径绑定: 给 /quote 的签名不能用于 /quote-big
            target9b = f"/quote-big?marker={run_id}-t9-path"
            async with s.get(f"{GW}{target9b}",
                             headers=sign_headers(f"/quote?marker={run_id}-t9-path")) as r:
                check("9 路径不匹配返回401", r.status == 401)
            check("9 错签请求无比对记录",
                  not await records_with(s, GW, f"marker={run_id}-t9-badsig"))

            # 10. 时间戳窗口: 过去/未来超 60s 拒绝, 窗口内通过
            old_ts = str(int(time.time()) - 62)
            target = f"/quote?marker={run_id}-t10-old"
            async with s.get(f"{GW}{target}",
                             headers=sign_headers(target, ts=old_ts)) as r:
                check("10 过去时间戳(now-62s)返回401", r.status == 401,
                      (await r.json()).get("detail", ""))
            fut_ts = str(int(time.time()) + 62)
            target = f"/quote?marker={run_id}-t10-future"
            async with s.get(f"{GW}{target}",
                             headers=sign_headers(target, ts=fut_ts)) as r:
                check("10 未来时间戳(now+62s)返回401", r.status == 401)
            ok_ts = str(int(time.time()) - 5)
            target = f"/quote?marker={run_id}-t10-inwindow"
            async with s.get(f"{GW}{target}",
                             headers=sign_headers(target, ts=ok_ts)) as r:
                check("10 窗口内时间戳(now-5s)放行", r.status == 200, str(r.status))
            await wait_record(s, GW, f"marker={run_id}-t10-inwindow")

            # 11. 串行重放: 同一签名第二次必须 401, 且只有一条上游记录
            target = f"/quote?marker={run_id}-t11-replay"
            headers = sign_headers(target)
            async with s.get(f"{GW}{target}", headers=headers) as r:
                check("11 首次签名放行", r.status == 200)
            async with s.get(f"{GW}{target}", headers=headers) as r:
                detail = (await r.json()).get("detail", "")
                check("11 同签名重放返回401", r.status == 401, detail)
                check("11 拒绝原因为 replay", detail.startswith("replay"), detail)
            await asyncio.sleep(0.2)
            check("11 重放只产生一条上游记录",
                  len(await records_with(s, GW, f"marker={run_id}-t11-replay")) == 1)

            # 12. 并发重放: 8 个完全相同签名同时发出, 恰好 1 个放行
            target = f"/quote?marker={run_id}-t12-creplay"
            headers = sign_headers(target)

            async def one_replay():
                async with aiohttp.ClientSession() as cs:
                    async with cs.get(f"{GW}{target}", headers=headers) as r:
                        return r.status
            statuses = await asyncio.gather(*(one_replay() for _ in range(8)))
            ok_n = sum(1 for x in statuses if x == 200)
            replay_n = sum(1 for x in statuses if x == 401)
            check("12 8并发同签名恰好1个放行", ok_n == 1, f"200x{ok_n}, 401x{replay_n}")
            check("12 其余7个全部重放拒绝", replay_n == 7, str(statuses))
            await asyncio.sleep(0.2)
            check("12 并发重放只产生一条上游记录",
                  len(await records_with(s, GW, f"marker={run_id}-t12-creplay")) == 1)
            state = await (await s.get(f"{GW}/api/state")).json()
            check("12 重放期间不占影子名额", state["shadow_in_flight"] == 0,
                  str(state["shadow_in_flight"]))

            # 13. 拒绝计数累加
            after = await (await s.get(f"{GW}/api/state")).json()
            counters = after["auth_rejected"]
            check("13 缺头计数累加",
                  counters["missing_headers"] > before["auth_rejected"]["missing_headers"])
            check("13 错签计数累加",
                  counters["bad_signature"] > before["auth_rejected"]["bad_signature"])
            check("13 过期计数累加",
                  counters["timestamp_expired"] > before["auth_rejected"]["timestamp_expired"])
            check("13 重放计数累加",
                  counters["replay"] > before["auth_rejected"]["replay"],
                  str(counters["replay"]))

            # 14. nonce 容量: 辅助网关 MAX_NONCES=4, 满额新请求 503, 不进上游
            hgw = helper_base
            hstate0 = await (await s.get(f"{hgw}/api/state")).json()
            check("14 辅助网关容量=4", hstate0["nonce_capacity"] == 4)

            async def helper_one(i):
                t = f"/quote?marker={run_id}-t14-{i}"
                async with aiohttp.ClientSession() as cs:
                    async with cs.get(f"{hgw}{t}", headers=sign_headers(t)) as r:
                        return r.status, await r.json()
            res = await asyncio.gather(*(helper_one(i) for i in range(4)))
            check("14 前4个新nonce全部放行", all(st == 200 for st, _ in res), str(res))
            t5 = f"/quote?marker={run_id}-t14-full"
            async with s.get(f"{hgw}{t5}", headers=sign_headers(t5)) as r:
                body = await r.json()
                check("14 nonce满额返回503", r.status == 503, str(r.status))
                check("14 满额拒绝不请求上游", body.get("rejected_before_upstream") is True)
            check("14 满额请求无比对记录",
                  not await records_with(s, hgw, f"marker={run_id}-t14-full"))
            hstate = await (await s.get(f"{hgw}/api/state")).json()
            check("14 保留有效nonce=4", hstate["nonce_retained"] == 4,
                  str(hstate["nonce_retained"]))

            # 15. 过期清理: 窗口 2s, 等过期后旧 nonce 被惰性清除, 容量恢复
            # 按整秒时钟等待而非固定 sleep, 避免亚秒对齐导致实际只走过 2 个整数秒
            fill_epoch = int(time.time())
            await wait_epoch_at_least(fill_epoch + 3)
            t6 = f"/quote?marker={run_id}-t15-recover"
            async with s.get(f"{hgw}{t6}", headers=sign_headers(t6)) as r:
                check("15 过期清理后新请求恢复", r.status == 200, str(r.status))
            hstate = await (await s.get(f"{hgw}/api/state")).json()
            check("15 清理后nonce回落(<=4且含新请求)",
                  1 <= hstate["nonce_retained"] <= 4, str(hstate["nonce_retained"]))

            # 16. 签名过期后旧签名不可复用(时间戳先于 nonce 校验被拒)
            target = f"/quote?marker={run_id}-t16-expired-reuse"
            reuse_headers = sign_headers(target)  # 首次用当前时间戳, 在 2s 窗口内
            async with s.get(f"{hgw}{target}", headers=reuse_headers) as r:
                check("16 窗口内首次放行", r.status == 200)
            # 确保重放时整秒时钟至少领先签名时间戳 3s, 稳定落在 2s 窗口之外
            await wait_epoch_at_least(int(reuse_headers[HDR_TS]) + 3)
            async with s.get(f"{hgw}{target}", headers=reuse_headers) as r:
                body = await r.json()
                check("16 过期后旧签名再用被拒(时间戳过期)", r.status == 401, str(r.status))
                check("16 拒绝原因标注时间戳过期",
                      "out of window" in body.get("detail", ""), body.get("detail", ""))

    finally:
        # 某些受限容器(seccomp)会拒绝 kill 系统调用: 收尾失败不应让测试变红
        try:
            helper.send_signal(signal.SIGTERM)
            try:
                helper.wait(timeout=10)
            except subprocess.TimeoutExpired:
                helper.kill()
        except (PermissionError, OSError) as exc:
            print(f"[WARN] 辅助网关进程无法由本环境终止: {exc} (端口 {helper_port} 进程保留)")

    print(f"\n汇总: {len(PASS)} passed, {len(FAIL)} failed")
    if FAIL:
        print("失败项:", FAIL)
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
