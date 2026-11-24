#!/usr/bin/env python3
"""
本地差分靶场 —— 零依赖，只用 Python 标准库

用法:
    python range.py 8081 1      # 漏洞版 (VULN=1)
    python range.py 8082 0      # 修复版 (VULN=0)

同一份代码，两个端口，语义上是真修复而不是假装：
    SQLi   : 字符串拼接        →  参数化查询
    IDOR   : 不校验归属        →  校验 session 用户 == 资源所有者
    穿越   : 直接拼路径        →  realpath 包含性检查
    SSRF   : 任意 URL 都取     →  仅允许 /internal/ 前缀

安全说明: SSRF 端点故意只允许 loopback，避免 agent 被指向后扫你家局域网。
"""
import os
import sys
import json
import sqlite3
import urllib.request
from urllib.parse import urlparse, parse_qs
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

VULN = True
PORT = 8081
DB = ":memory:"

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass


def init_db():
    conn = sqlite3.connect(DB, check_same_thread=False)
    conn.executescript("""
        CREATE TABLE items(id INTEGER PRIMARY KEY, name TEXT, owner TEXT, secret TEXT);
        CREATE TABLE users(id INTEGER PRIMARY KEY, user TEXT, pw TEXT);
    """)
    rows = [
        (1, "alpha", "alice", "flag-item-1"),
        (2, "beta", "bob", "flag-item-2"),
        (3, "gamma", "alice", "flag-item-3"),
    ]
    conn.executemany("INSERT INTO items VALUES (?,?,?,?)", rows)
    conn.executemany("INSERT INTO users VALUES (?,?,?)",
                     [(1, "alice", "alice123"), (2, "bob", "bob123")])
    conn.commit()
    return conn


CONN = None

# 绕过系统代理，否则 SSRF 端点会被本机代理劫持
_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


class H(BaseHTTPRequestHandler):
    server_version = "LocalRange/1.0"

    def log_message(self, fmt, *args):
        sys.stderr.write("%s %s\n" % (self.command, self.path))

    # ---------- helpers ----------
    def _send(self, code, body, ctype="text/plain; charset=utf-8"):
        if isinstance(body, (dict, list)):
            body = json.dumps(body, ensure_ascii=False)
        b = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def _whoami(self):
        c = self.headers.get("Cookie", "")
        for part in c.split(";"):
            if part.strip().startswith("user="):
                return part.strip().split("=", 1)[1]
        return None

    # ---------- routing ----------
    def do_GET(self):
        u = urlparse(self.path)
        q = parse_qs(u.query)
        p = u.path

        if p == "/":
            return self._send(200, "local differential range\nvuln=%s\n" % VULN)

        if p == "/login":
            user = (q.get("u") or [""])[0]
            pw = (q.get("p") or [""])[0]
            row = CONN.execute("SELECT user FROM users WHERE user=? AND pw=?",
                               (user, pw)).fetchone()
            if not row:
                return self._send(401, "bad creds")
            self.send_response(200)
            self.send_header("Set-Cookie", "user=%s; Path=/" % row[0])
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"ok")
            return

        if p == "/api/item":
            return self._item((q.get("id") or ["1"])[0])

        if p.startswith("/api/user/"):
            return self._user(p.rsplit("/", 1)[-1])

        if p == "/download":
            return self._download((q.get("file") or ["readme.txt"])[0])

        if p == "/fetch":
            return self._fetch((q.get("url") or [""])[0])

        if p == "/internal/secret":
            # 只应通过 SSRF 触达的"内网服务"
            return self._send(200, "INTERNAL-SECRET-9f3a2b\n")

        return self._send(404, "not found")

    # ---------- 1. SQL 注入 ----------
    def _item(self, idv):
        try:
            if VULN:
                sql = "SELECT id,name,owner,secret FROM items WHERE id = %s" % idv
                rows = CONN.execute(sql).fetchall()
            else:
                rows = CONN.execute(
                    "SELECT id,name,owner,secret FROM items WHERE id = ?",
                    (idv,)).fetchall()
        except Exception as e:
            return self._send(500, "sql error: %s" % e)
        if not rows:
            return self._send(404, "no item")
        return self._send(200, {"items": rows, "count": len(rows)})

    # ---------- 2. 越权 (IDOR) ----------
    def _user(self, uid):
        me = self._whoami()
        try:
            row = CONN.execute(
                "SELECT id,user FROM users WHERE id = ?", (uid,)).fetchone()
        except Exception as e:
            return self._send(500, str(e))
        if not row:
            return self._send(404, "no user")
        if VULN:
            return self._send(200, {"id": row[0], "user": row[1], "pw_hint": row[1] + "123"})
        # 修复版: 必须登录且只能看自己
        if me != row[1]:
            return self._send(403, "forbidden")
        return self._send(200, {"id": row[0], "user": row[1], "pw_hint": row[1] + "123"})

    # ---------- 3. 路径穿越 ----------
    def _download(self, name):
        base = os.path.join(os.path.dirname(os.path.abspath(__file__)), "public")
        os.makedirs(base, exist_ok=True)
        rp = os.path.join(base, "readme.txt")
        if not os.path.exists(rp):
            open(rp, "w").write("public readme\n")
        if VULN:
            path = os.path.join(base, name)          # 直接拼，可 ../..
        else:
            name = os.path.basename(name)            # 剥掉目录成分
            path = os.path.realpath(os.path.join(base, name))
            if not path.startswith(os.path.realpath(base) + os.sep) and path != os.path.realpath(base):
                return self._send(403, "forbidden")
        try:
            with open(path, "rb") as f:
                return self._send(200, f.read())
        except Exception as e:
            return self._send(404, str(e))

    # ---------- 4. SSRF ----------
    def _fetch(self, url):
        if not url:
            return self._send(400, "need url")
        u = urlparse(url)
        if u.scheme not in ("http",):
            return self._send(400, "only http")
        if VULN:
            pass                                     # 任意 http 都放行
        else:
            # 修复: 拒绝任何回环/私网目标，只允许白名单外网域
            host = u.hostname or ""
            private = (
                host in ("127.0.0.1", "localhost", "::1", "0.0.0.0")
                or host.startswith("127.")
                or host.startswith("10.")
                or host.startswith("192.168.")
                or host.startswith("172.16.")
            )
            if private:
                return self._send(403, "private address blocked")
            if host not in ("example.com", "www.example.com"):
                return self._send(403, "host not allowed")
        try:
            with _OPENER.open(url, timeout=3) as r:
                data = r.read(4096)
            return self._send(200, data)
        except Exception as e:
            return self._send(502, "fetch failed: %s" % e)


def main():
    global VULN, PORT, CONN
    PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8081
    VULN = (sys.argv[2] if len(sys.argv) > 2 else "1") == "1"
    CONN = init_db()
    srv = ThreadingHTTPServer(("127.0.0.1", PORT), H)
    print("listening 127.0.0.1:%d  vuln=%s" % (PORT, VULN), flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
