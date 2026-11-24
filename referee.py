#!/usr/bin/env python3
"""
轮内程序裁判 (Program-level Referee) —— 零依赖版

不依赖任何模型，纯规则复验 agent 提交的 claim。
目的：长跑进行中，秒级拦掉假阳性。

输入:  claims/*.json
输出:  verdicts.jsonl

claim schema:
{
  "claim_id": "T042-C3",
  "target": "app.example.com",
  "class": "sqli_blind_time",
  "locus": {"file": "api/search.py", "line": 88},
  "hypothesis": "sort 参数未过滤进入 ORDER BY",
  "evidence": {
    "request":  {"method":"GET","path":"/api/search?sort=1","headers":{},"body":null},
    "response": {"status":200,"timing_ms":3120,"body_sha256":"..."},
    "control":  {"payload":"1","timing_ms":210}
  },
  "reproduce": "curl -sS ..."
}

用法:
  python referee.py --claims ./claims --base http://127.0.0.1:8081
"""
import argparse
import json
import hashlib
import statistics
import sys
import time
import urllib.request
import urllib.error
from pathlib import Path
from urllib.parse import urljoin

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

REPEAT = 3
TIMING_TOLERANCE = 0.35     # 三次复现的相对标准差上限
MIN_TIME_DELTA_MS = 1000    # 盲注类：与对照组最小时间差

# 显式绕过系统代理：Windows 上 urllib 会自动读取注册表里的代理设置，
# 目标若是本机/内网，会被错误地送进代理导致 RemoteDisconnected。
_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def sha(b):
    return hashlib.sha256(b).hexdigest()


def replay(base, req, cookie, timeout=30):
    url = urljoin(base, req.get("path", "/"))
    headers = dict(req.get("headers") or {})
    if cookie:
        headers.setdefault("Cookie", cookie)
    data = req.get("body")
    if isinstance(data, str):
        data = data.encode()
    r = urllib.request.Request(url, data=data, method=req.get("method", "GET"))
    for k, v in headers.items():
        r.add_header(k, str(v))
    t0 = time.perf_counter()
    try:
        with _OPENER.open(r, timeout=timeout) as resp:
            body = resp.read()
            ms = (time.perf_counter() - t0) * 1000
            return resp.status, body, ms
    except urllib.error.HTTPError as e:
        body = e.read()
        ms = (time.perf_counter() - t0) * 1000
        return e.code, body, ms
    except Exception as e:
        ms = (time.perf_counter() - t0) * 1000
        return -1, str(e).encode(), ms


def judge(claim, base, cookie):
    ev = claim.get("evidence") or {}
    req = ev.get("request")
    control = ev.get("control") or {}
    if not req:
        return "INSUFFICIENT", "没有 request，无法复验", {}

    runs = [replay(base, req, cookie) for _ in range(REPEAT)]
    codes = [c for c, _, _ in runs]
    times = [t for _, _, t in runs]
    bodies = [b for _, b, _ in runs]

    if -1 in codes:
        return "INSUFFICIENT", "连接失败: %r" % (runs[0][1][:120],), {"codes": codes}

    if not [c for c in codes if 200 <= c < 400]:
        return "REFUTED", "三次全部非 2xx/3xx: %s，服务端异常不等于漏洞" % codes, {"codes": codes}

    if len(set(codes)) > 1:
        return "REFUTED", "三次状态码不一致 %s，不可复现" % codes, {"codes": codes}

    mean = statistics.mean(times)
    sd = statistics.pstdev(times) / mean if mean else 0
    detail = {"codes": codes, "timing_ms": [round(t) for t in times], "cv": round(sd, 3)}

    cls = (claim.get("class") or "").lower()

    if "time" in cls or "blind" in cls:
        if sd > TIMING_TOLERANCE:
            return "REFUTED", "时间抖动 %.0f%% 过大 %s，像网络噪声不像 sleep" % (sd * 100, detail["timing_ms"]), detail
        delta = mean - float(control.get("timing_ms") or 0)
        if delta < MIN_TIME_DELTA_MS:
            return "INSUFFICIENT", "与对照组仅差 %.0fms，不够构成盲注证据" % delta, detail
        return "CONFIRMED", "三次稳定 %.0fms，对照组 %sms，差值 %.0fms" % (mean, control.get("timing_ms"), delta), detail

    if control.get("body_sha256") and sha(bodies[0]) == control["body_sha256"]:
        return "REFUTED", "响应体与 benign 对照组完全一致，payload 未生效", detail

    if len({sha(b) for b in bodies}) > 1:
        return "REFUTED", "三次响应体不一致，结果不稳定", detail

    return "CONFIRMED", "三次状态码与响应体稳定，且与对照组有差异", detail


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--claims", required=True)
    ap.add_argument("--base", required=True)
    ap.add_argument("--cookie", default="")
    ap.add_argument("--out", default="verdicts.jsonl")
    args = ap.parse_args()

    seen, stats = set(), {"CONFIRMED": 0, "REFUTED": 0, "INSUFFICIENT": 0}
    out = Path(args.out).open("w", encoding="utf-8")

    for f in sorted(Path(args.claims).glob("*.json")):
        try:
            claim = json.loads(f.read_text(encoding="utf-8-sig"))
        except json.JSONDecodeError:
            print("[skip] %s JSON 解析失败" % f.name)
            continue

        key = (claim.get("target"), claim.get("class"),
               json.dumps(claim.get("locus"), sort_keys=True))
        if key in seen:
            print("[dup ] %s 重复 claim，跳过" % claim.get("claim_id"))
            continue
        seen.add(key)

        verdict, reason, detail = judge(claim, args.base, args.cookie)
        stats[verdict] += 1
        out.write(json.dumps({"claim_id": claim.get("claim_id"), "verdict": verdict,
                              "reason": reason, "detail": detail}, ensure_ascii=False) + "\n")
        print("[%-12s] %-12s %s" % (verdict, claim.get("claim_id"), reason))

    out.close()
    total = sum(stats.values())
    print("\n合计 %d 条: %s" % (total, ", ".join("%s=%d" % kv for kv in stats.items())))
    if total:
        print("假阳性拦截率(非 CONFIRMED 占比): %.0f%%" % ((total - stats["CONFIRMED"]) / total * 100))


if __name__ == "__main__":
    main()
