# 本地复验靶场 Runbook

## 它要解决什么

你需要的不是"能打的靶机",是**能证明"修了就不复现"的对照环境**。

一句话判据:

> 同一个请求, 在未修复环境返回 A, 在已修复环境返回 B。且 A≠B 的原因是漏洞本身, 不是网络抖动。

这就是 CyberGym 判 PoC 的标准(L3), 也是 triager 认的标准。

---

## 一、起环境

```bash
cd deploy/range
docker compose up -d
docker compose ps
```

| 服务 | 地址 | 说明 |
|---|---|---|
| DVWA | http://127.0.0.1:8081 | admin / password |
| Juice Shop | http://127.0.0.1:8082 | 自带注册 |
| 取证代理 | http://127.0.0.1:8080 | 设为 HTTP_PROXY 即可 |

国内拉镜像慢的话, 先在 Docker Desktop 里配镜像加速:

```json
{
  "registry-mirrors": [
    "https://docker.m.daocloud.io",
    "https://dockerproxy.com"
  ]
}
```

---

## 二、DVWA 的四种难度 = 天然 L3 对照

DVWA 每个漏洞模块都有四档, 这四档就是现成的"补丁版本":

| 档位 | 代码状态 | 用途 |
|---|---|---|
| low | 完全无过滤 | **未修复环境** |
| medium | 弱过滤 | 中间态 |
| high | 强过滤(仍可绕) | 测试绕过能力 |
| **impossible** | **PDO 预处理/令牌校验** | **已修复环境** |

### 差分验证流程

以 SQL 注入为例:

```bash
# 1. 切到 low, 打 payload
curl -s "http://127.0.0.1:8081/vulnerabilities/sqli/?id=1'%20OR%20'1'='1&Submit=Submit" \
     -b "PHPSESSID=xxx; security=low" | grep -c "First name"

# 2. 切到 impossible, 打同一个 payload
curl -s "http://127.0.0.1:8081/vulnerabilities/sqli/?id=1'%20OR%20'1'='1&Submit=Submit" \
     -b "PHPSESSID=xxx; security=impossible" | grep -c "First name"
```

- low 返回多条记录 → 触发
- impossible 返回零条 → 未触发
- **两个结果不同, 且差在"是否有 SQL 语义被解释"** → L3 通过

切档位在 DVWA 的 `DVWA Security` 页面, 或直接改 cookie 里的 `security=`。

---

## 三、把 agent 的 claim 接进来

### 流程

```
agent 产出 claims/*.json
        ↓
referee.py 程序裁判 (秒级, 判稳定性/对照组/状态码)
        ↓ 通过
人工按 claim 里的 reproduce 在靶场跑一遍
        ↓
DVWA low vs impossible 差分 (或 juice old vs new tag 差分)
        ↓ 通过
自己重写报告 → 提交
```

### 命令

```bash
python deploy/referee.py \
  --claims ./claims \
  --base http://127.0.0.1:8081 \
  --cookie "PHPSESSID=xxx; security=low" \
  --out verdicts.jsonl
```

`referee.py` 判 `CONFIRMED` 不等于洞是真的, 只等于"这个 claim 的表述自洽且可稳定复现"。**L3 那一步必须人做。**

---

## 四、取证: 别信 agent 自报

agent 说"我收到了 3120ms 的延迟", 你要能自己看到那 3120ms。

开启代理后, 所有请求自动落盘:

```bash
# agent 侧 (或你自己复验时)
export HTTP_PROXY=http://127.0.0.1:8080
export HTTPS_PROXY=http://127.0.0.1:8080

# 事后回放
mitmproxy -r flows/range-20261123.flow
```

这样你手里的证据是**网络层抓的**, 不是模型写的。这是"人工审核"和"复核 AI 说辞"的分界线。

---

## 五、重置

agent 会把靶场打到稀烂(改数据、删表、留后门)。每轮跑完重置:

```bash
./reset.sh
```

不用重建镜像, `down -v` + `up -d` 十几秒。

---

## 六、下一步: 接真实 CVE

DVWA 练熟之后, 换成真实软件, 因为赏金项目里的洞都是这种:

```
WordPress 6.x
  + 某插件 v2.1.0  (有 CVE, 未修复)
  + 同一插件 v2.1.1 (官方修复版)
```

两个容器, 同一份 PoC, 打两边。这个才是能拿去提交的证据形态 ——
也是 ARES 那篇论文评测用的方法(WordPress 插件, 静态分析找洞)。

再往后可以把老版本应用和它的补丁 diff 一起交给 agent,
让它自己读 diff 反推漏洞 —— 这是 XekRung/SecLLM 那类模型的训练方式,
你本地也能复现这个循环。
