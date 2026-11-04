# Security across the SDLC

Each row says what control exists at that stage, where the evidence is, and which threats it addresses. The four repositories line up with the stages.

| Stage | Control | Evidence you can run or open | Threats (TM-) | Repo |
|---|---|---|---|---|
| **Plan / design** | STRIDE threat model, attack tree, risk register, ATT&CK mapping; objectives and trust boundaries written down before code | `python3 scripts/build.py --check`, `docs/02-data-flow.md` | all | payloop-threat-model |
| **Code** | Prepared statements only, one central authorisation guard, `SsrfGuard`, allow-listed file names, strict input validation, fail-closed secret loading, generic errors with request ids | `app/src/`, `semgrep/payloop-php.yml` | 03, 04, 05, 07, 10, 11, 12, 13, 15 | payloop-vuln-lab (findings and fixes) |
| **Build / CI** | One required gate: secrets, SAST, dependency and image scan, IaC scan, SBOM; fail closed; waivers expire | `payloop-secure-pipeline` workflows, `tools/gate.py`, `make gate-demo-bad` | 19, 20, 21 | payloop-secure-pipeline |
| **Test** | Every historical exploit re-run on every change; SSRF bypass tests; detection rules replay-tested with false-positive controls; attack simulation | `make test`, `make demo` | 01 to 15 | this repo, vuln-lab |
| **Release / deploy** | Non-root, read-only root fs, dropped capabilities, no-new-privileges, secrets via environment, nginx rate limits and headers, DB constraints | `Dockerfile`, `docker-compose.yml`, `docker/nginx.conf`, `app/db/schema.sql` | 06, 16, 21, 23 | this repo |
| **Operate / monitor** | Structured security log, Wazuh rules tagged to ATT&CK, severity levels that map to runbooks | `monitoring/wazuh/`, `docs/runbooks.md` | 01, 02, 03, 08, 25 | this repo |
| **Respond** | Runbook per alert family: triage questions, queries, containment, evidence, closure | `docs/runbooks.md` | all with detections | this repo |
| **Improve** | Each finding becomes a regression test and each gap a threat-model entry; model rebuilds and fails if traceability breaks | `tests/lab.py`, `threats.yaml` | all | all |

## The loop that makes it a system rather than a checklist
A threat in the model has a control, the control has a test, the attack has a detection, the detection has a runbook, and an incident
or a missed attack feeds back into the model. Remove any link and the next two links go stale; the build checks are there to notice.

## What is not covered
Production TLS, MFA, signed partner callbacks, runtime container telemetry, image signing, and a dynamic scan of a deployed environment.
All are listed as open or partial in the threat model; none are claimed as done.
