VENV     := .venv
PYTHON   := $(VENV)/bin/python
PIP      := $(VENV)/bin/pip
ACTIVATE := source $(VENV)/bin/activate

.PHONY: help setup setup-dev shell test lint clean deploy-infra deploy-config

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'

# ── Setup ────────────────────────────────────────────────────────

$(VENV)/bin/activate:
	python3 -m venv $(VENV)
	$(PIP) install --upgrade pip

setup: $(VENV)/bin/activate ## Install CLI dependencies
	$(PIP) install -r requirements.txt
	@echo "\n  ✓ Run 'make shell' to start the interactive SIEM shell.\n"

setup-dev: $(VENV)/bin/activate ## Install CLI + dev/test dependencies
	$(PIP) install -r requirements-dev.txt
	@echo "\n  ✓ Run 'make test' to run the test suite.\n"

# ── CLI ──────────────────────────────────────────────────────────

shell: ## Launch the interactive SIEM shell
	@$(ACTIVATE) && $(PYTHON) cli/shell.py

# ── Tests ────────────────────────────────────────────────────────

test: ## Run all tests
	@$(ACTIVATE) && $(PYTHON) -m pytest infra/tests/ -v

# ── Deploy ───────────────────────────────────────────────────────

deploy-infra: ## Build and deploy SAM infrastructure
	sam build --template-file infra/template.yaml
	sam deploy

deploy-config: ## Upload rules and sources to S3
	@BUCKET=$$(aws cloudformation describe-stacks \
		--stack-name siemlessly \
		--query 'Stacks[0].Outputs[?OutputKey==`SiemDataBucketName`].OutputValue' \
		--output text 2>/dev/null); \
	if [ -z "$$BUCKET" ]; then \
		echo "Could not find bucket. Set BUCKET= manually."; exit 1; \
	fi; \
	echo "Uploading to $$BUCKET..."; \
	aws s3 cp config/rules/rules.json "s3://$$BUCKET/rules/rules.json"; \
	aws s3 cp config/sources/sources.json "s3://$$BUCKET/sources/sources.json"; \
	echo "✓ Config deployed."

# ── Housekeeping ─────────────────────────────────────────────────

clean: ## Remove venv, caches, build artifacts
	rm -rf $(VENV) .pytest_cache __pycache__ .aws-sam
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
