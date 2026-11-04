PY ?= python3
.PHONY: run demo test mutate up seed down
run:        ## app on http://127.0.0.1:8080 with a throw-away DB (PHP built-in server, no Docker)
	@mkdir -p .run
	@export PAYLOOP_DB=$(CURDIR)/.run/db.sqlite PAYLOOP_LOG=$(CURDIR)/.run/payloop.jsonl PAYLOOP_TOKEN_SECRET=$${PAYLOOP_TOKEN_SECRET:-$$(openssl rand -hex 24)}; \
	 cd app && php db/seed.php && echo "listening on http://127.0.0.1:8080  (log: $(CURDIR)/.run/payloop.jsonl)" && php -S 127.0.0.1:8080 -t public public/index.php

demo:       ## run every attack, print blocked/detected table, refresh docs/demo-output.md and the README table
	$(PY) attack-sim/simulate.py --report docs/demo-output.md
	$(PY) scripts/embed_demo.py

test:       ## everything that runs without Docker or GitHub
	$(PY) tests/lab.py --app app --expect mitigated
	php tests/ssrf_guard_test.php app
	$(PY) tools/ruletest.py lint monitoring/wazuh/payloop_rules.xml
	$(PY) tools/ruletest.py suite tests/detections.yml
	$(PY) attack-sim/simulate.py --quiet

mutate:     ## prove the detection suite can fail: broken rules must turn it red
	$(PY) tools/mutation_check.py tests/detections.yml

up:         ## Docker: build and start app + proxy (needs PAYLOOP_TOKEN_SECRET in env or .env)
	docker compose up -d --build
seed:       ## Docker: create the schema and demo users once
	docker compose --profile init run --rm init
down:
	docker compose down
