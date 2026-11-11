# Live compose-stack demo

This records a run of the attack simulation against the **actual Docker Compose stack** (not the offline
simulator): the hardened app container (php-fpm, read-only root fs, `cap_drop: ALL`, `no-new-privileges`,
non-root uid) behind the unprivileged nginx proxy, with a seeded SQLite database in a named volume.

Run on 2026-11-11. Everything is synthetic (RFC 5737 `203.0.113.0/24` source IPs, demo users, throw-away DB).

## How it was run

```bash
export PAYLOOP_TOKEN_SECRET=$(openssl rand -hex 24)   # 48 hex chars
make up        # docker compose up -d --build  (app + nginx proxy on 127.0.0.1:8080)
make seed      # docker compose --profile init run --rm init  -> "seeded 5 users"

# Phase 1 - fire every attack scenario at the running stack
python3 attack-sim/simulate.py --url http://127.0.0.1:8080

# Phase 2 - replay the real container log through the Wazuh rules
docker cp payloop-secure-sandbox-app-1:/srv/payloop/var/log/payloop.jsonl live.jsonl
python3 - <<'PY'
import sys; sys.path.insert(0, "tools"); import ruletest
rules = ruletest.load_rules("monitoring/wazuh/payloop_rules.xml")
alerts = ruletest.replay(rules, open("live.jsonl").read().splitlines())
# ... count distinct rules / max level ...
PY

make down       # docker compose down
```

A sanity check first: `POST /login` for `alice` returned **HTTP 200** with a signed token, confirming the
hardened stack serves real traffic.

## Phase 1 - every attack blocked by the live runtime

`simulate.py --url` exited 0 ("All attacks blocked"). HTTP results come straight from the running containers:

| ID | Scenario | Attacker | HTTP results |
|---|---|---|---|
| S1 | Password spraying | blocked | 401x10 |
| S2 | Brute force on one account | blocked | 401x5 429x7 |
| S3 | SQL injection (UNION) | blocked | 200 (no rows leaked) |
| S4 | Path traversal | blocked | 404 |
| S5 | SSRF (loopback, metadata, `file://`) | blocked | 400x3 |
| S6 | IDOR enumeration of wallets | blocked | 404x6 |
| S7 | Transfer from another customer's wallet | blocked | 404x3 |
| S8 | Negative and zero transfer amounts | blocked | 422x2 |
| S9 | Replayed payment request | blocked | 201 200 (idempotent) |
| S10 | Forged admin token (old leaked secret) | blocked | 401x6 |

Note the live rate limiter engaging on S2 (`429` after 5 failures), the SSRF guard rejecting all three
targets on S5 (`400x3`), and the forged token signed with the vulnerable build's committed secret being
rejected on S10 (`401x6`).

## Phase 2 - the SOC would see it

Replaying the **115 real log lines the live stack produced** through the Wazuh ruleset fired **19 distinct
rules, max level 12**:

| Rule | Level | Count | What | ATT&CK |
|---|---|---|---|---|
| 110112 | 12 | 8 | Successful login after repeated failures | T1110 |
| 110161 | 11 | 2 | Repeated forged or invalid tokens | T1606 |
| 110111 | 10 | 8 | Possible brute force or password spraying | T1110 |
| 110113 | 10 | 5 | Sustained login attempts despite throttling | T1110 |
| 110120 | 10 | 1 | SQL injection pattern in request | T1190 |
| 110121 | 10 | 1 | Path traversal pattern in request | T1190 |
| 110130 | 10 | 3 | Outbound request blocked (SSRF) | T1190 |
| 110153 | 10 | 2 | Transfer rejected with zero or negative amount | T1657 |
| 110141 | 9 | 7 | Repeated authorisation failures | T1213 |
| 110122 | 8 | 1 | File access blocked by validation | T1190 |
| 110160 | 8 | 4 | Invalid session token presented | T1606 |
| 110103 | 7 | 2 | Login throttled | T1110 |
| 110101 | 5 | 7 | Failed login | T1110 |
| 110152 | 5 | 1 | Duplicate transfer absorbed (idempotency) | - |
| 110105 | 4 | 2 | Authorisation denied | - |

(Lower-noise rules 110102/110104/110106/110107 also fired for the benign and informational events.)

## What this verifies and what it does not
- **Verified:** the container image builds, the hardened stack starts and serves, and under live attack the
  runtime blocks every scenario while producing a security log that drives 19 detection rules up to level 12.
- **Still not verified:** these rules fired in the repo's offline rule engine (`ruletest.py`) against the live
  log, not on a running Wazuh manager. Loading them into a real manager with `wazuh-logtest` is the remaining
  step; the procedure is in `payloop-vuln-lab/docs/WAZUH-VALIDATION.md`.
