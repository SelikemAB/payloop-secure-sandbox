# Questions to rehearse

Answers are anchored in this repository. Replace anything you did not personally do with what you did; accuracy beats polish.

**1. Walk me through the threat model.**
STRIDE per element on a data-flow diagram with five trust boundaries, mapped to ATT&CK and scored likelihood x impact. It lives in `threats.yaml`; the docs, risk register, Navigator layers and traceability report are generated from it. 25 threats, each with controls, a status and a residual-risk sentence.

**2. How do you know your detections work?**
Three ways: unit-style replay of synthetic scenarios, replay of real logs captured while the exploit suite ran against vulnerable and fixed builds, and false-positive controls such as a normal customer day that must stay under level 5. I also mutation-tested the suite: loosening a regex, raising a threshold and reintroducing a rule-ordering bug each turned it red. The limit is that the offline simulator is not the Wazuh engine; `wazuh-logtest` on a real manager is the final check and the procedure is documented.

**3. What did tools miss that you found?**
IDOR, throttling and the transfer-logic flaws (negative amounts, overdraft, replay). Semgrep caught six of nine findings; the rest needed reading handlers against the access-control matrix and the "financial theft" branch of the attack tree.

**4. Which bug in your own fixes taught you something?**
An IPv4-mapped IPv6 address (`::ffff:127.0.0.1`) passed my SSRF range filter. The fix was to accept IPv4 only rather than chase IPv6 transition forms. Also a Wazuh rule that never fired because a sibling rule matched first; and a patch that quietly depended on another one.

**5. Why fail closed in the pipeline?**
A scanner that crashes or is skipped must not look like a clean scan. The gate exits 2 if a required report is missing or unparseable, and it runs even if upstream jobs failed.

**6. Why do waivers expire?**
Exceptions rot. Owner, reason and an expiry within 90 days are mandatory, and an expired waiver fails the build until someone fixes or renews it.

**7. How would you stop SSRF in production beyond the code?**
Egress filtering so the app host cannot reach metadata or internal ranges, IMDSv2 with hop limit 1, and an allow-list of destinations. The code guard (allow-list, resolved-IP checks, IP pinning, no redirects, no body reflection) is the first layer, not the only one.

**8. A level 12 alert, 110112 (success after repeated failures), fires. What do you do?**
Runbook RB-1: confirm the source and whether the account is real, review that account's activity since the success, force a reset, block the source, check for related alerts from the same address, notify the customer through a verified channel, and record the timeline.

**9. What is the biggest remaining risk?**
No MFA for customers or admins, no signed partner callbacks, and no runtime container telemetry. They are TM-02, TM-24, TM-22 and TM-21 in the model, marked open or partial.

**10. How would this change at real scale?**
Move from SQLite to a database with row-level locking or serialisable isolation, centralise rate limiting, terminate TLS at a managed edge, store secrets in a manager with rotation, sign images, and run detections against streaming data with proper tuning cycles.

**11. How did you use AI?**
Say only what is true. A defensible pattern: AI to widen coverage and draft fixes, with every finding reproduced by an exploit first and every patch verified mechanically (exploit now fails, other exploits unaffected, scanner quiet). See `payloop-vuln-lab/docs/AI-ASSISTED-WORKFLOW.md`.

**12. What did you not verify?**
The Wazuh rules on a live manager, the GitHub workflows on GitHub, and the container build, because those environments were not available when the repositories were written. Each is stated in the relevant README with the procedure to close it.
