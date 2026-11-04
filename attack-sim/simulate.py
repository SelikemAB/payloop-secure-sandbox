#!/usr/bin/env python3
"""Attack simulation: fire realistic attacks at the hardened PayLoop app and show, per scenario,
(1) did the attack succeed, (2) what the app logged, (3) which detection rules fired.

Each scenario uses its own source IP (via X-Forwarded-For from the trusted local proxy) so rate limits and
frequency rules do not bleed between scenarios. The app runs on a throw-away SQLite DB bound to 127.0.0.1.

  python3 attack-sim/simulate.py                   # run all scenarios, exit 1 if an attack succeeds or a detection is missing
  python3 attack-sim/simulate.py --only S3,S7      # subset
  python3 attack-sim/simulate.py --report docs/demo-output.md   # write the run as Markdown evidence
  python3 attack-sim/simulate.py --url http://127.0.0.1:8080    # attack an already-running instance instead (compose stack)
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.parse
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "tests"))
import lab  # noqa: E402  (HTTP client + free-port helper)
import ruletest  # noqa: E402


@dataclass
class Outcome:
    attacker_won: bool
    codes: list
    note: str


def rle(codes: list) -> str:
    """[401,401,429] -> '401x2 429' so long runs stay readable."""
    out, i = [], 0
    while i < len(codes):
        j = i
        while j < len(codes) and codes[j] == codes[i]:
            j += 1
        out.append(f"{codes[i]}x{j - i}" if j - i > 1 else str(codes[i]))
        i = j
    return " ".join(out)


def ip_for(n: int) -> str:
    return f"203.0.113.{n}"   # TEST-NET-3, documentation range: never a real address


def H(ip: str, **extra) -> dict:
    return {"X-Forwarded-For": ip, **extra}


# ----------------------------------------------------------------------------- scenarios
def s1_spray(c, ip):
    codes = [c.call("POST", "/login", {"username": f"user{i}", "password": "Winter2026!"}, headers=H(ip))[0] for i in range(10)]
    return Outcome(any(x == 200 for x in codes), codes, "one password sprayed across 10 usernames")


def s2_bruteforce(c, ip):
    codes = [c.call("POST", "/login", {"username": "dave", "password": f"guess-{i}"}, headers=H(ip))[0] for i in range(12)]
    return Outcome(any(x == 200 for x in codes), codes, "12 guesses against one account; throttle should engage after 5")


def s3_sqli(c, ip):
    t = c.login("alice", "alice-demo-pw", ip)
    q = "zzz%' UNION SELECT id,1,1,1,username||':'||pass_hash,'x' FROM users--"
    s, _, j = c.call("GET", "/statement?wallet=1&q=" + urllib.parse.quote(q), token=t, headers=H(ip))
    leaked = bool(j) and any("admin:" in str(i.get("note", "")) for i in j.get("items", []))
    return Outcome(leaked, [s], "UNION SELECT through the search term to read password hashes")


def s4_traversal(c, ip):
    t = c.login("alice", "alice-demo-pw", ip)
    s, _, j = c.call("GET", "/receipt?file=" + urllib.parse.quote("../internal/notes.txt"), token=t, headers=H(ip))
    return Outcome(s == 200 and bool(j) and "INTERNAL ONLY" in j.get("content", ""), [s], "../ in the receipt file name")


def s5_ssrf(c, ip):
    t = c.login("alice", "alice-demo-pw", ip)
    codes = []
    for url in ("http://127.0.0.1:8000/admin", "http://169.254.169.254/latest/meta-data/iam/security-credentials/", "file:///etc/hostname"):
        codes.append(c.call("POST", "/partner/webhook-test", {"url": url}, token=t, headers=H(ip))[0])
    return Outcome(any(x == 200 for x in codes), codes, "loopback, cloud metadata and file:// through the webhook tester")


def s6_idor_enum(c, ip):
    t = c.login("alice", "alice-demo-pw", ip)
    res = [c.call("GET", f"/wallet?id={i}", token=t, headers=H(ip)) for i in range(2, 8)]
    won = any(s == 200 for s, _, _ in res)
    return Outcome(won, [s for s, _, _ in res], "walk wallet ids 2..7 as alice")


def s7_transfer_from_victim(c, ip):
    t = c.login("alice", "alice-demo-pw", ip)
    codes = [c.call("POST", "/transfer", {"from_wallet": 2, "to_wallet": 1, "amount_minor": 1000}, token=t,
                    headers=H(ip, **{"Idempotency-Key": f"steal-{i:04d}-abcd"}))[0] for i in range(3)]
    bob = c.login("bob", "bob-demo-pw", ip_for(99))
    bal = c.call("GET", "/wallet?id=2", token=bob, headers=H(ip_for(99)))[2]["balance_minor"]
    return Outcome(any(x < 300 for x in codes) or bal != 50000, codes, f"spend from bob's wallet as alice; bob's balance is {bal}")


def s8_negative(c, ip):
    t = c.login("alice", "alice-demo-pw", ip)
    codes = [c.call("POST", "/transfer", {"from_wallet": 1, "to_wallet": 2, "amount_minor": a}, token=t,
                    headers=H(ip, **{"Idempotency-Key": f"neg-{i:04d}-abcdef"}))[0] for i, a in enumerate((-5000, 0))]
    return Outcome(any(x < 300 for x in codes), codes, "negative and zero amounts")


def s9_replay(c, ip):
    t = c.login("carol", "carol-demo-pw", ip)
    before = c.call("GET", "/wallet?id=3", token=t, headers=H(ip))[2]["balance_minor"]
    codes = [c.call("POST", "/transfer", {"from_wallet": 3, "to_wallet": 1, "amount_minor": 1000}, token=t,
                    headers=H(ip, **{"Idempotency-Key": "replay-0001-abcd"}))[0] for _ in range(2)]
    after = c.call("GET", "/wallet?id=3", token=t, headers=H(ip))[2]["balance_minor"]
    return Outcome(before - after != 1000, codes, f"same request sent twice; wallet moved GHS {(before - after) / 100:.2f} (should be 10.00)")


def s10_forged_token(c, ip):
    def b64(b):
        return base64.urlsafe_b64encode(b).rstrip(b"=").decode()
    codes = []
    for i in range(6):
        p = b64(json.dumps({"sub": 5, "usr": "admin", "role": "admin", "exp": int(time.time()) + 600}).encode())
        sig = hmac.new(b"payloop-dev-secret-2024", p.encode(), hashlib.sha256).hexdigest()   # the secret the old build shipped with
        codes.append(c.call("GET", "/admin/users", token=f"{p}.{sig}", headers=H(ip))[0])
    return Outcome(any(x == 200 for x in codes), codes, "admin token forged with the secret the vulnerable build had committed")


SCENARIOS = {
    "S1": ("Password spraying", "T1110", s1_spray, {110111}),
    "S2": ("Brute force on one account", "T1110", s2_bruteforce, {110103, 110113}),
    "S3": ("SQL injection (UNION)", "T1190", s3_sqli, {110120}),
    "S4": ("Path traversal", "T1190", s4_traversal, {110121, 110122}),
    "S5": ("SSRF (loopback, metadata, file://)", "T1190 / T1552.005", s5_ssrf, {110130}),
    "S6": ("IDOR enumeration of wallets", "T1213", s6_idor_enum, {110141}),
    "S7": ("Transfer from another customer's wallet", "T1657", s7_transfer_from_victim, {110141}),
    "S8": ("Negative and zero transfer amounts", "T1657", s8_negative, {110153}),
    "S9": ("Replayed payment request", "T1657", s9_replay, {110152}),
    "S10": ("Forged admin token (old leaked secret)", "T1606", s10_forged_token, {110160, 110161}),
}


# ----------------------------------------------------------------------------- app lifecycle
class LocalApp:
    def __init__(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="payloop-sim-"))
        work = self.tmp / "app"
        shutil.copytree(ROOT / "app", work, ignore=shutil.ignore_patterns("var"))
        self.log = self.tmp / "payloop.jsonl"
        env = dict(os.environ, PAYLOOP_DB=str(self.tmp / "db.sqlite"), PAYLOOP_LOG=str(self.log),
                   PAYLOOP_TOKEN_SECRET=os.urandom(24).hex(), PAYLOOP_WEBHOOK_ALLOWLIST="partner.example.test",
                   PAYLOOP_TRUSTED_PROXY="127.0.0.1")
        subprocess.run(["php", "db/seed.php"], cwd=work, env=env, check=True, capture_output=True)
        port = lab._free_port()
        self.proc = subprocess.Popen(["php", "-S", f"127.0.0.1:{port}", "-t", "public", "public/index.php"], cwd=work, env=env,
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.url = f"http://127.0.0.1:{port}"
        c = lab.Client(self.url)
        for _ in range(50):
            try:
                if c.call("GET", "/health")[0] == 200:
                    return
            except Exception:
                time.sleep(0.1)
        raise RuntimeError("app did not start")

    def close(self):
        self.proc.terminate()
        self.proc.wait(timeout=5)
        shutil.rmtree(self.tmp, ignore_errors=True)


def log_lines(path: Path) -> list[str]:
    return path.read_text().splitlines() if path.exists() else []


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--only")
    ap.add_argument("--url", help="attack an existing instance; detections are then read from --log")
    ap.add_argument("--log", type=Path, help="JSONL log of the instance given with --url")
    ap.add_argument("--report", type=Path)
    ap.add_argument("--quiet", action="store_true")
    a = ap.parse_args()

    rules = ruletest.load_rules(ROOT / "monitoring/wazuh/payloop_rules.xml")
    app = None if a.url else LocalApp()
    url, logpath = (a.url, a.log) if a.url else (app.url, app.log)
    if a.url and not a.log:
        print("note: with --url and no --log, detection results cannot be evaluated")
    client = lab.Client(url)
    wanted = [x.strip().upper() for x in a.only.split(",")] if a.only else list(SCENARIOS)

    rows, failures = [], []
    try:
        for n, sid in enumerate(wanted, start=10):
            title, attack, fn, expect = SCENARIOS[sid]
            start = len(log_lines(logpath)) if logpath else 0
            out = fn(client, ip_for(n))
            new = log_lines(logpath)[start:] if logpath else []
            alerts = ruletest.replay(rules, new)
            fired = sorted({al.rule.id for al in alerts if al.rule.level >= 4})
            top = max((al.rule.level for al in alerts), default=0)
            detected = expect <= {al.rule.id for al in alerts}
            if out.attacker_won:
                failures.append(f"{sid}: ATTACK SUCCEEDED ({out.note})")
            if logpath and not detected:
                failures.append(f"{sid}: expected rules {sorted(expect)} did not all fire (fired {fired})")
            sample = next((al.text for al in alerts if al.rule.id in expect), "")
            rows.append((sid, title, attack, out, fired, top, detected, sample))
    finally:
        if app:
            app.close()

    if not a.quiet:
        print(f"{'ID':<4}{'SCENARIO':<44}{'ATTACKER':<10}{'HTTP RESULTS':<20}{'RULES FIRED (level>=4)':<28}{'MAX LVL'}")
        for sid, title, attack, out, fired, top, detected, sample in rows:
            codes = rle(out.codes)
            print(f"{sid:<4}{title:<44}{'WON' if out.attacker_won else 'blocked':<10}{codes:<20}{' '.join(map(str, fired)):<28}{top}")
        print()
        for sid, _t, _a, out, *_ in rows:
            print(f"  {sid}: {out.note}")
    if a.report:
        md = ["# Attack simulation output", "", "_Generated by `attack-sim/simulate.py` against the hardened build. Do not edit by hand._", "",
              "| ID | Scenario | ATT&CK | Attacker | HTTP results | Detection rules fired | Max level | Example alert |", "|---|---|---|---|---|---|---|---|"]
        for sid, title, attack, out, fired, top, detected, sample in rows:
            md.append(f"| {sid} | {title} | {attack} | {'**WON**' if out.attacker_won else 'blocked'} | {rle(out.codes)} | "
                      f"{', '.join(map(str, fired)) or 'none'} | {top} | {sample.replace('|', '/')} |")
        md += ["", "What each scenario does:", ""] + [f"- **{sid}**: {out.note}" for sid, _t, _a, out, *_ in rows]
        md += ["", f"Result: {'all attacks blocked and all expected detections fired' if not failures else 'PROBLEMS: ' + '; '.join(failures)}", ""]
        a.report.write_text("\n".join(md))
    for f in failures:
        print("FAIL:", f)
    if not failures and not a.quiet:
        print("\nAll attacks blocked; every expected detection fired.")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
