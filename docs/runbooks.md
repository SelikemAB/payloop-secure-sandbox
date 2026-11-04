# Alert runbooks

One section per alert family. Rule ids are in `monitoring/wazuh/payloop_rules.xml`. Severity guidance: **level 12+ act now**, 8 to 11 triage within the hour, below 8 review in the daily queue.

Conventions used below
- `LOG` = the application log (`payloop.jsonl`). Replace the example address with the one in the alert.
- Wazuh dashboard queries use the indexed field names (`rule.id`, `data.srcip`, `data.username`, `data.event`); confirm the exact names in Discover for your Wazuh version.
- Containment steps that change production (blocking, rotating) need the approver your process names; they are listed so nobody improvises at 3 a.m.

---
## RB-1 Authentication attacks
**Rules:** 110101 failed login (5), 110103 throttled (7), 110111 spray or brute force (10), 110112 success after failures (12), 110113 attempts despite throttling (10). ATT&CK T1110.

**First five minutes**
1. Is it one source or many? Is it one account (brute force) or many accounts (spray)?
   `jq -c 'select(.event=="login_failed")' LOG | jq -s 'group_by(.srcip) | map({ip:.[0].srcip, n:length, users:(map(.username)|unique|length)})'`
2. Did any attempt succeed? **110112 means yes**: treat that account as compromised until proven otherwise.
   `jq -c 'select(.srcip=="203.0.113.10" and (.event=="login_success" or .event=="login_failed"))' LOG`
3. Are the targeted usernames real? Unknown usernames in volume suggest a spray from a wordlist.

**Containment:** block the source at the proxy or firewall. For 110112: force a password reset, review the account's transfers since the success time, notify the customer through the verified channel. The throttle already limits further guesses (5 per username, 20 per IP per 5 minutes).

**Known side effect (TM-17):** an attacker can lock a real customer out by failing logins for their username. If a customer reports lockout during an alert, check the throttle window (5 minutes) before assuming compromise.

**False positives:** shared office or carrier NAT addresses; a mobile app with a bug retrying a stale password.
**Escalate when:** 110112 fires, or the same source later appears on a different rule family.

---
## RB-2 Injection and file access
**Rules:** 110120 SQL injection pattern (10), 110121 path traversal pattern (10), 110122 path blocked (8). ATT&CK T1190.

**First five minutes**
1. Look at the request line and the response status. 200 with a normal body is unremarkable; a 500 or an oddly large response is not.
   `jq -c 'select(.event=="request" and (.query|test("union|\\.\\./";"i")))' LOG`
2. Check the same source and user for earlier reconnaissance (404 bursts, other rule families).
3. On the hardened build the query is parameterised and the file name is allow-listed, so a hit means an attempt, not a breach. If this alert fires on an **older build** treat it as a likely breach and check what the response returned.

**Containment:** block the source; no data rollback is needed if the build is current. **Follow-up:** add the payload as a test case to `tests/samples` so the rule keeps catching it.
**Blind spots:** payloads inside JSON bodies and double-encoded sequences; do not rely on this rule alone.
**False positives:** a customer searching notes for the word "union select" (rare); security scanners run by your own team (agree a source allow-list).

---
## RB-3 Server-side request forgery
**Rules:** 110130 blocked (10), 110131 internal fetch succeeded (12), 110132 metadata endpoint fetched (14). ATT&CK T1190, T1552.005.

**First five minutes**
1. **110130** is an attempt that the guard stopped: note the user, the target and the reason (`ip_literal_not_allowed`, `host_not_allowlisted`, `resolves_to_non_public_ip`).
2. **110131 or 110132 is an incident:** the server reached an internal address. Identify what answered and what came back.
3. Check cloud audit logs for use of any instance credentials from an unexpected place after the event.

**Containment (110131/110132):** disable the webhook-test route (feature flag or proxy rule), rotate any credentials the instance role exposes, block the user, confirm IMDSv2 with hop limit 1 is enforced, review egress rules.
**Follow-up:** confirm the allow-list contents; add the bypass as a case in `tests/ssrf_guard_test.php`.
**False positives:** a partner mistyping their own URL; a partner moving to a new host before it is allow-listed.

---
## RB-4 Access-control probing
**Rules:** 110105 authorisation denied (4), 110141 repeated denials (9), 110140 many different wallets viewed (8). ATT&CK T1213.

**First five minutes**
1. Which user, which resource ids, how fast? Sequential ids at machine speed is enumeration; one mistaken id is not.
   `jq -c 'select(.event=="authz_denied" and .user=="alice")' LOG`
2. Was any lookup **successful**? On the hardened build every foreign id is denied. Successful `wallet_view` events for ids the user does not own mean the guard was bypassed: that is a vulnerability, escalate.
3. Is the account itself compromised (RB-1) or is a legitimate customer being malicious?

**Containment:** suspend the account pending review; rate-limit the route at the proxy if the pattern continues across accounts.
**False positives:** support staff impersonation tooling; a client bug requesting stale wallet ids after an account closure.

---
## RB-5 Money-movement abuse
**Rules:** 110150 negative or zero amount **accepted** (12), 110153 rejected (10), 110151 two transfers with one idempotency key accepted (8), 110152 duplicate absorbed (5). ATT&CK T1657.

**First five minutes**
1. **110150 and 110151 mean money moved wrongly.** Freeze the involved wallets, then compute the exact discrepancy.
   `jq -c 'select(.event=="transfer" and .user=="alice")' LOG`
2. **110153** is an attempt the validation stopped. Look for the same user trying other tricks (RB-4, RB-6).
3. **110152** is normal retry behaviour most of the time. A burst of them with changing payloads for one key (HTTP 409 in the app log) suggests probing.

**Containment:** freeze wallets, hold related payouts, preserve the ledger and log slice, reconcile balances against the transfers table.
**Follow-up:** run the nightly reconciliation (documented gap in the threat model); if the cause was code, add the case to `tests/lab.py`.
**False positives:** mobile clients that retry with the same key are expected and absorbed by design (110152 at level 5 is informational).

---
## RB-6 Token forgery and admin access
**Rules:** 110160 invalid token (8), 110161 repeated invalid tokens (11), 110170 admin access (6). ATT&CK T1606, T1078.

**First five minutes**
1. `bad_signature` repeatedly from one source means someone is minting tokens with a guessed or **leaked** secret. Ask first: was the signing secret ever in source control, a log, a ticket or a chat?
2. Review every `admin_access` event around the alert: who, from where, at what hour. A forged token with the real secret produces **no** invalid-token event, so 110170 from an unusual source is the only signal.
3. Compare the admin's usual source addresses with this one.

**Containment:** rotate `PAYLOOP_TOKEN_SECRET` (signs every user out; there is no per-token revocation in this build) and restart; review admin actions since the earliest suspicious time; hunt for how the secret leaked.
**False positives:** clients with long-lived sessions across a deliberate secret rotation produce a burst of `bad_signature` that decays quickly.

---
## RB-7 Application errors and pipeline health
**Rules:** 110123 HTTP 5xx (4), 110124 repeated 5xx from one source (9), 110180 unhandled application error (7); Wazuh stock agent rules 504 and 506 (agent disconnected or stopped).

**First five minutes**
1. Match the request id in the alert to the `app_error` event: it carries the exception type and `file:line`, which the client never sees.
2. A burst from one source on many routes is fuzzing or exploitation; a burst from many sources after a deploy is a bug.
3. **Silence is also an alert:** if 504 or 506 fires, the SIEM is blind. Restore the agent first, then review the gap using the raw log on disk.

**Containment:** roll back the deploy if it is a regression; block the source if it is hostile. Add a test for the crash path.
