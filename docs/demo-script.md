# Interview demo script (about 9 minutes, screen share)

Prepare: terminal in the repo, `docs/` open in an editor, one browser tab with the Navigator layer or the risk register. Run `make demo` once beforehand so you know it works on the day.

| Time | Show | Say |
|---|---|---|
| 0:00 | `README.md` architecture diagram | "PayLoop is a fictional payments API. I did the work in four stages: threat model, find and fix, pipeline gate, and this sandbox that ties them together." |
| 0:30 | `payloop-threat-model/docs/02-data-flow.md` attack tree | Pick two leaves. "This one has a detection. This one, the race condition, does not, because it is a prevention problem. The report says so and names the reconciliation job that would catch drift." |
| 2:00 | `docs/06-detection-traceability.md` | "The build fails if a high-risk threat has no detection and no written reason. I proved that by breaking it on purpose." |
| 3:00 | `make demo` | Narrate the table: attacker blocked in every row, rules that fired, max level. Pick **S8** (negative amount) and **S10** (forged token). |
| 5:00 | `jq -c 'select(.event=="transfer_rejected")' <log>`, then rule 110153 in `monitoring/wazuh/payloop_rules.xml`, then its case in `tests/detections.yml` | "Event, rule, test. Each has a control group that must stay quiet, so I know it is not just shouting at everything." |
| 6:30 | `payloop-secure-pipeline`: `make gate-demo-bad` | "The gate fails closed. A missing scanner report fails the build, and waivers expire." |
| 7:30 | `docs/sdlc-security-map.md` | "Each stage has a control, evidence, and a threat it addresses." |
| 8:15 | `docs/architecture.md` "Deliberate simplifications" | "What I did not do: TLS, MFA, signed callbacks, runtime container telemetry. They are open items in the model, not hidden." |
| 8:45 | Questions | Use `docs/interview-qa.md` as your rehearsal list. |

## Optional: a live URL
Only expose the **hardened** build, and only for the duration of the interview.
1. `export PAYLOOP_TOKEN_SECRET=$(openssl rand -hex 24)` and `docker compose up -d --build` then `docker compose --profile init run --rm init` (or `make run` for the PHP built-in server on port 8080).
2. Publish it with a free tunnel such as `cloudflared tunnel --url http://127.0.0.1:8080` and share the generated address.
3. The seeded accounts and passwords are public in the repo. Treat the instance as disposable, never reuse real credentials, and stop the tunnel afterwards.
(The tunnel and compose steps were not run when this repository was written; test them the day before.)

## If something breaks live
- `make demo` fails: show `docs/demo-output.md`, the committed run output, and say so.
- Compose will not start: use `make run`; the app has no container dependency.
- Someone asks something you did not build: say so, then say how you would approach it. The open items list is there for exactly this.
