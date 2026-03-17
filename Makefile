.PHONY: help test-fixtures fixture-pack evidence-bundle compliance-pack wiz-report

PYTHON ?= python3
CONTAINER ?= my-postgres
WIZ_RESOURCE_ID ?= $(CONTAINER)

help:
	@echo "pg-stig-audit convenience targets"
	@echo ""
	@echo "  make test-fixtures    Run hardened/baseline/vulnerable integration suite"
	@echo "  make fixture-pack     Build deterministic fixture delta pack"
	@echo "  make evidence-bundle  Build compliance evidence bundle from hardened fixture"
	@echo "  make compliance-pack  Run test + fixture-pack + evidence-bundle"
	@echo "  make wiz-report CONTAINER=<name> [WIZ_RESOURCE_ID=<id>]"
	@echo "                        Run audit against an existing Docker Postgres container and push to Wiz"

test-fixtures:
	./test/run_tests.sh

fixture-pack:
	$(PYTHON) scripts/make_fixture_delta_pack.py --input-dir test/output --out-dir artifacts/fixture-pack

evidence-bundle:
	$(PYTHON) scripts/build_evidence_bundle.py --json test/output/hardened.json --sarif test/output/hardened.sarif.json --out-dir evidence/latest --label hardened-fixture

compliance-pack: test-fixtures fixture-pack evidence-bundle
	@echo ""
	@echo "✅ Compliance pack complete"
	@echo "   - artifacts/fixture-pack/fixture-delta-pack.json"
	@echo "   - evidence/latest/executive-summary.pdf"
	@echo "   - evidence/latest/results.sarif.json"

wiz-report:
	$(PYTHON) audit.py --mode docker --container "$(CONTAINER)" --json results.json --sarif results.sarif.json
	$(PYTHON) scripts/push_to_wiz.py issues --findings results.json --resource-id "$(WIZ_RESOURCE_ID)" --only-failures
	@echo "✅ Wiz report pushed for container $(CONTAINER)"
