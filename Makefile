PY = python3

.PHONY: help install setup train test run cli batch retrain check-drift docker clean

help:
	@echo ""
	@echo "  PhishGuard Pro — All commands from this folder"
	@echo "  ══════════════════════════════════════════════"
	@echo "  make install        Install Python packages"
	@echo "  make setup          Generate data + train model (first time)"
	@echo "  make train          Train / retrain model"
	@echo "  make test           Run all 44 tests"
	@echo "  make run            Start API server on :5050"
	@echo "  make cli URL=<url>  Analyze a single URL"
	@echo "  make batch          Analyze data/sample_urls.txt"
	@echo "  make retrain        Incremental retrain (uses feedback)"
	@echo "  make retrain-force  Force retrain regardless of drift"
	@echo "  make check-drift    Check if model needs retraining"
	@echo "  make docker         Build + start with Docker"
	@echo "  make clean          Remove model + DB artifacts"
	@echo ""

install:
	$(PY) -m pip install -r requirements.txt

setup:
	$(PY) dataset.py
	$(PY) train.py

train:
	$(PY) train.py

test:
	$(PY) tests.py

run:
	$(PY) app.py

cli:
	$(PY) cli.py --url "$(URL)"

batch:
	$(PY) cli.py --file data/sample_urls.txt

retrain:
	$(PY) retrain.py

retrain-force:
	$(PY) retrain.py --force

check-drift:
	$(PY) retrain.py --check

docker:
	docker-compose up --build -d

clean:
	rm -f data/phishguard.db
	rm -f models/model.pkl models/metadata.json
	rm -rf models/backups/
	find . -name "*.pyc" -delete
	find . -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true
