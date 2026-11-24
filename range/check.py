#!/usr/bin/env python3
"""
L3 差分验证器

对同一组 payload，分别打漏洞版和修复版，要求:
    漏洞版 触发  +  修复版 不触发   →  PASS
任何一个不满足 → FAIL

用法:
    python check.py 8081 8082
"""
import sys
import json
import urllib.request
import urllib.error

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

VULN_PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8081
FIXED_PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 8082

_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def req(port, path, cookie=None):
    url = "http://127.0.0.1:%d%s" % (port, path)
    r = urllib.request.Request(url)
    if cookie:
        r.add_header("Cookie", cookie)
    try:
        with _OPENER.open(r, timeout=5) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()
    except Exception as e:
        return -1, str(e).encode()


CASES = [
    ("SQLi",     "/api/item?id=1%20OR%201=1",        None,          b"count"),
    ("IDOR",     "/api/user/2",                      "user=alice",  b"pw_hint"),
    ("Traversal","/download?file=../range.py",       None,          b"ThreadingHTTPServer"),
    ("SSRF",     "/fetch?url=http://127.0.0.1:PORT/internal/secret", None, b"INTERNAL-SECRET"),
]


def main():
    print("差分验证: 漏洞版 :%d  vs  修复版 :%d\n" % (VULN_PORT, FIXED_PORT))
    print("%-10s %-8s %-8s %-6s %s" % ("类型", "漏洞版", "修复版", "结果", "说明"))
    print("-" * 72)

    passed = 0
    for name, path, cookie, marker in CASES:
        p_v = path.replace("PORT", str(VULN_PORT))
        p_f = path.replace("PORT", str(FIXED_PORT))

        sv, bv = req(VULN_PORT, p_v, cookie)
        sf, bf = req(FIXED_PORT, p_f, cookie)

        # 漏洞版应该"命中"
        hit_v = (200 <= sv < 300) and (marker in bv)
        # 修复版应该"打不中"
        hit_f = (200 <= sf < 300) and (marker in bf)

        ok = hit_v and not hit_f
        passed += ok
        print("%-10s %-8s %-8s %-6s %s" % (
            name,
            "%d %s" % (sv, "命中" if hit_v else "无"),
            "%d %s" % (sf, "命中" if hit_f else "无"),
            "PASS" if ok else "FAIL",
            "" if ok else ("漏洞版未触发" if not hit_v else "修复版仍触发"),
        ))

    total = len(CASES)
    print("-" * 72)
    print("通过 %d/%d" % (passed, total))
    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(main())
