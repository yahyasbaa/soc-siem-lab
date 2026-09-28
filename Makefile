# SOC & SIEM Security Monitoring Lab
# Run `make help` for the list of targets.

SHELL      := /bin/bash
.SHELLFLAGS := -eu -o pipefail -c
PY         := .venv/bin/python
PYTEST     := PYTHONPATH=scripts $(PY) -m pytest
COMPOSE    := docker compose
GEN        := $(PY) scripts/generate-test-events/generate.py
REPORTS    := reports

.DEFAULT_GOAL := help
.PHONY: help setup validate up down restart health generate-events test detection-test \
        integration-test infra-test all report dashboards docs golden reload-rules \
        investigate incidents logs ps clean distclean

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-18s\033[0m %s\n",$$1,$$2}'

setup: ## Prerequisites, .env secrets, venv, certificates, runtime dirs, images
	./scripts/setup.sh

validate: ## Validate configuration offline (compose, XML, catalog, fixtures, playbooks)
	@test -f .env || { echo "run 'make setup' first"; exit 1; }
	$(COMPOSE) config -q && echo "docker-compose.yml OK"
	$(PY) -c "import xml.dom.minidom as m,sys; [m.parseString('<r>'+open(f).read()+'</r>') for f in sys.argv[1:]]; print('rule/decoder XML well-formed')" \
	    wazuh/manager/etc/rules/soc_lab_rules.xml wazuh/manager/etc/decoders/soc_lab_decoders.xml
	bash -n scripts/*.sh wazuh/entrypoint-scripts/*.sh && echo "shell scripts OK"
	$(PYTEST) -q tests/detection/test_catalog.py tests/integration/test_playbooks.py

up: ## Start the SOC stack, wait for health, import dashboards
	@test -f .env || { echo "run 'make setup' first"; exit 1; }
	$(COMPOSE) up -d --wait --wait-timeout 600
	./scripts/validate-rules.sh
	PYTHONPATH=scripts $(PY) scripts/import-dashboards.py

down: ## Stop the stack (data volumes are kept)
	$(COMPOSE) down

restart: ## Full stack restart (down + up + health)
	$(MAKE) down
	$(MAKE) up
	$(MAKE) health

health: ## End-to-end health check (non-zero exit if anything is broken)
	./scripts/health-check.sh --wait 240

generate-events: ## Inject every synthetic security scenario into the lab hosts
	$(GEN) inject

test: ## Run the complete test-suite
	@mkdir -p $(REPORTS)
	$(PYTEST) -v --junitxml=$(REPORTS)/junit-all.xml tests

detection-test: ## Detection tests: catalog consistency, logtest engine, end-to-end pipeline
	@mkdir -p $(REPORTS)
	$(PYTEST) -v --junitxml=$(REPORTS)/junit-detection.xml tests/detection
	$(PY) scripts/build_docs.py

integration-test: ## Infrastructure + SIEM + ingestion + dashboards + investigation tests
	@mkdir -p $(REPORTS)
	$(PYTEST) -v --junitxml=$(REPORTS)/junit-integration.xml tests/infrastructure tests/integration

infra-test: ## Infrastructure tests only (containers, ports, networks)
	$(PYTEST) -v tests/infrastructure

all: ## validate -> up -> health -> synthetic telemetry -> detection + integration tests -> report
	$(MAKE) setup
	$(MAKE) validate
	$(MAKE) up
	$(MAKE) health
	$(MAKE) generate-events
	rm -f $(REPORTS)/junit-detection.xml $(REPORTS)/junit-integration.xml
	$(MAKE) detection-test
	$(MAKE) integration-test
	$(MAKE) report

report: ## Summarise the latest test results
	@$(PY) scripts/test-report.py

dashboards: ## Rebuild and (re)import the SOC dashboards
	$(PY) dashboards/build_dashboards.py
	PYTHONPATH=scripts $(PY) scripts/import-dashboards.py

docs: ## Regenerate catalog / MITRE / scenario docs
	$(PY) scripts/build_docs.py

golden: ## Rewrite the deterministic rendering snapshot after an intended fixture change
	$(GEN) golden

reload-rules: ## Validate and hot-deploy rule/decoder changes (restarts the manager)
	./scripts/validate-rules.sh
	$(COMPOSE) restart wazuh.manager
	$(COMPOSE) up -d --wait --wait-timeout 300
	./scripts/health-check.sh --wait 180

investigate: ## Investigate the newest alert of a rule: make investigate RULE=100101 [SRCIP=x]
	@test -n "$(RULE)" || { echo "usage: make investigate RULE=<rule id> [SRCIP=<ip>]"; exit 1; }
	PYTHONPATH=scripts $(PY) scripts/investigate.py --rule-id $(RULE) $(if $(SRCIP),--srcip $(SRCIP))

incidents: ## List open incidents
	PYTHONPATH=scripts $(PY) scripts/incident.py list

logs: ## Follow manager logs
	$(COMPOSE) logs -f --tail=100 wazuh.manager

ps: ## Container status
	$(COMPOSE) ps

clean: ## Stop and DELETE all lab data (volumes, runtime logs, evidence, reports)
	$(COMPOSE) down -v --remove-orphans
	rm -rf runtime $(REPORTS)

distclean: clean ## clean + remove .env, certificates, generated config and the venv
	rm -rf .env wazuh/certs wazuh/generated .venv
