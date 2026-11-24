# bug-bounty-triage

A verification layer for vulnerability reports: a differential test range, a programmatic
judge, and one rule — **write down what would prove the hypothesis false before you test it.**

> Nine and a half hours of work. A complete pipeline. **Zero submitted vulnerabilities.**
>
> This repository is about the part that made the zero honest instead of embarrassing.

---

## Scope and ethics

Everything described here ran inside the authorized scope of public Chinese vulnerability
disclosure programs (SRC), where the listed assets are explicitly in scope and testing is
permitted under the program's rules.

This repository deliberately contains **no target names, no hostnames, no captured responses,
and no credentials**. The differential range in `range/` is a local, self-contained target
built for testing the verifier — it is not a copy of anything.

---

## The idea

Self-hosted inference drives marginal cost toward zero. If checking a claim is nearly free,
you can afford to check many and discard most of them — breadth against depth.

The hypothesis is easy to state and hard to make safe. An autonomous scanner pointed at real
systems produces false positives faster than it produces findings, and a false report costs
more than a missed one: it costs standing with the program, and possibly the account.

So most of the engineering went the other way: **build the thing that tries to kill each claim
before a human ever sees it.**

---

## Architecture

| # | Module | What it does |
|---|---|---|
| 1 | Model service | 309B-A15B MoE, FP8, vLLM with tensor parallelism; 65k context, 129 tok/s warm |
| 2 | Differential range | Same app, two builds — one vulnerable, one fixed. Real code difference, not a flag |
| 3 | Referee | Replays each claim three times, compares against a control, filters by status code, dedupes by `(target, class, locus)` |
| 4 | Recon pipeline | DNS enumeration → single GET per host → model ranks and proposes the next verification step |
| 5 | Agent loop | Model emits `ACTION: http_get <url>` or `DONE:`; the script executes under hard limits |
| 6 | Browser automation | Headless clients are detected by modern bot checks; a real profile is required |

### The differential range

The point of a differential range is that the *fix* is real. A vulnerable build and a hardened
build run side by side on two ports, and the checker asserts that the same request behaves
differently against each:

```
python range/range.py 8081 1     # vulnerable build
python range/range.py 8082 0     # fixed build
python range/check.py 8081 8082
```

Four classes covered — SQL injection, IDOR, path traversal, SSRF — and the difference is a
genuine code difference (string concatenation vs parameterized query, ownership check present
or absent), so a passing check cannot be satisfied by toggling a config.

Without this, "the scanner found something" is untestable. With it, the scanner's own recall
and false-positive rate become measurable.

### The referee

Zero dependencies, rule-based. It answers one question: **is this claim reproducible, and does
the control group behave differently?**

```
real claim        -> CONFIRMED
fabricated claim  -> REFUTED
```

That second line is the whole project. A claim pointing at a path that does not exist is
trivially producible by a language model; a system that cannot tell the difference is a
random-report generator.

---

## Results: ten hypotheses, eight killed

| Hypothesis | Verdict | Why |
|---|---|---|
| An upload endpoint on an internal system was exposed | refuted | Route returned 404 — the controller was gone |
| VCS metadata (`.git` / `.svn`) was exposed | refuted | 403 from WAF, i.e. blocked, not exposed |
| A login page leaked a stack trace | refuted | Generic framework error page |
| A query parameter was injectable | refuted | Identical behavior for `1'` and `9999` |
| A user endpoint was unauthenticated | refuted | 302 to login |
| A staging build had debug output or weak auth | **unconfirmed** | Front-end flag only, no server-side evidence |
| A server banner implied an old, vulnerable version | refuted | Actual version was newer |
| An API leaked stack traces | refuted | Standard 401 JSON |
| A parameter reflected XSS | refuted | Parameter validated as an IP, value never rendered |
| A share link was vulnerable to IDOR | refuted | Token hashed and bound to the object id |

**Eight of ten were killed by the falsification habit before they became submissions.**
Eight N/A reports would have cost more than the eight hours.

### The three-request authorization test

A reusable method for any "share link" product:

```
1. drop the token        -> expect invalid_token
2. use a wrong token     -> expect mismatch
3. keep token, swap id   -> expect mismatch
```

All three pass means the protection is structural. Any one fails means it is worth a report.
This takes about thirty seconds and replaces an hour of guessing.

---

## Lessons

1. **Tooling is not the bottleneck; target selection is.** All eight targets were well defended.
   A perfect pipeline aimed at hardened infrastructure produces nothing.
2. **Authorization bugs need an account.** This is a logic problem before it is a technical one.
   First selection criterion: does the product have user registration?
3. **"Unverified" is worth more than "probably".** Every program in this space rejects claims
   without a proof of concept.
4. **Injection defense has to be architectural.** The model can be argued with; what it cannot
   do is execute anything. It emits JSON, and a script decides what runs.
5. **Infrastructure is deterministic; findings are probabilistic.** The hours went into the
   deterministic part, which is why the probabilistic part produced nothing.

---

## Repository layout

```
referee.py                 programmatic claim judge (zero dependencies)
range/range.py             differential target: vulnerable vs fixed build
range/check.py             asserts the two builds actually differ
range/RUNBOOK.md           how to run the range
TASK_CONTRACT.md           sub-agent contract: env/ + repro.sh + result.json
docs/web-vuln-catalog.md   40+ vulnerability classes, five sections each
                           (principle / probe / verify / falsify / severity)
```

---

## Status

Kept as the record of a negative result with a reusable verification harness.

The conclusion at the time was not "improve the tooling" — it was to point the same tooling at
a smaller target that has user registration and weak defenses. The pipeline was never the
problem.
