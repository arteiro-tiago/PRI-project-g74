VENV = venv
PYTHON = $(VENV)/bin/python
PIP = $(VENV)/bin/pip

SOLR_CONTAINER_NAME = my_solr
SOLR_PORT = 8983
COLLECTION_NAME = final_cves.csv

.PHONY: venv install run clean solr-up solr-create-collection solr-populate solr-setup solr-down

all: setup install run

setup:
	@test -d $(VENV) || python3 -m venv $(VENV)

install: setup
	@$(PIP) install -r requirements.txt

run: install
	@$(PYTHON) nvd_collection.py
	@$(PYTHON) nvd_preparation.py
	@$(PYTHON) ghad_collection.py
	@$(PYTHON) ghad_preparation.py

clean:
	rm -rf $(VENV) __pycache__ *.pyc

solr-up:
	@if [ $$(docker ps -a -q -f name=^$(SOLR_CONTAINER_NAME)$$) ]; then \
		if [ ! $$(docker ps -q -f name=^$(SOLR_CONTAINER_NAME)$$) ]; then \
			echo "Starting existing Solr container..."; \
			docker start $(SOLR_CONTAINER_NAME); \
		else \
			echo "Solr container is already running."; \
		fi; \
	else \
		echo "Pulling image and starting new Solr container..."; \
		docker run -d -p $(SOLR_PORT):8983 --name $(SOLR_CONTAINER_NAME) solr solr-precreate $(COLLECTION_NAME); \
	fi
	@echo "Waiting for Solr server to start..."
	@until curl -s "http://localhost:$(SOLR_PORT)/solr/admin/info/system" > /dev/null; do sleep 2; done

solr-create-collection:
	@echo "Creating collection '$(COLLECTION_NAME)'..."
	@curl -s -X GET "http://localhost:$(SOLR_PORT)/solr/admin/collections?action=CREATE&name=$(COLLECTION_NAME)&numShards=1&replicationFactor=1&collection.configName=_default" || true

solr-populate:
	@echo "Waiting for collection '$(COLLECTION_NAME)' to finish loading and populating data..."
	@until curl -s -X POST "http://localhost:$(SOLR_PORT)/solr/$(COLLECTION_NAME)/update?commit=true" \
		-H "Content-Type: application/json" \
		-d '[{"id": "test-1", "title": "Solr Readiness Check"}]' | grep -q '"status":0'; do \
		echo "Core is still loading. Retrying in 3 seconds..."; \
		sleep 3; \
	done
	@echo "Collection is ready and data indexed successfully!"

solr-setup: solr-up solr-populate

solr-down:
	docker stop $(SOLR_CONTAINER_NAME) || true
	docker rm $(SOLR_CONTAINER_NAME) || true