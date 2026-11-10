VENV = venv
PYTHON = $(VENV)/bin/python
PIP = $(VENV)/bin/pip

SOLR_CONTAINER_NAME = my-solr
SOLR_PORT = 8983
COLLECTION_SIMPLE = cves_simple
COLLECTION_ADVANCED = cves_advanced
SCHEMA_SIMPLE = schema_simple.json
SCHEMA_ADVANCED = schema_advanced.json
JSON_FILE = final_cves.json
SOLR_IMAGE = solr:latest

.PHONY: preparation setup install run clean solr-setup run-container create-collections configure-schemas populate-collections clean-solr

preparation: setup install run

setup:
	@test -d $(VENV) || python3 -m venv $(VENV)

install: setup
	@$(PIP) install -r requirements.txt

run: install
	@$(PYTHON) src/nvd_collection.py
	@$(PYTHON) src/nvd_preparation.py
	@$(PYTHON) src/ghad_collection.py
	@$(PYTHON) src/ghad_preparation.py

clean:
	rm -rf $(VENV) __pycache__ *.pyc

solr-setup: run-container create-collections configure-schemas populate-collections

run-container:
	@if [ $$(docker ps -a -q -f name=^/$(SOLR_CONTAINER_NAME)$$ | wc -l) -eq 0 ]; then \
		echo "Creating and starting new Solr container '$(SOLR_CONTAINER_NAME)'..."; \
		docker run -d -p $(SOLR_PORT):8983 --name $(SOLR_CONTAINER_NAME) $(SOLR_IMAGE); \
	elif [ $$(docker ps -q -f name=^/$(SOLR_CONTAINER_NAME)$$ | wc -l) -eq 0 ]; then \
		echo "Starting existing Solr container '$(SOLR_CONTAINER_NAME)'..."; \
		docker start $(SOLR_CONTAINER_NAME); \
	else \
		echo "Solr container '$(SOLR_CONTAINER_NAME)' is already running."; \
	fi
	@echo "Waiting for Solr server to start..."
	@until docker exec $(SOLR_CONTAINER_NAME) solr status > /dev/null 2>&1; do \
		sleep 2; \
	done
	@echo "Solr server is ready!"

create-collections:
	@echo "Checking collection '$(COLLECTION_SIMPLE)'..."
	@if docker exec $(SOLR_CONTAINER_NAME) solr status | grep -q "$(COLLECTION_SIMPLE)"; then \
		echo "Collection '$(COLLECTION_SIMPLE)' already exists."; \
	else \
		echo "Creating collection '$(COLLECTION_SIMPLE)'..."; \
		docker exec -i $(SOLR_CONTAINER_NAME) solr create -c $(COLLECTION_SIMPLE); \
	fi
	@echo "Checking collection '$(COLLECTION_ADVANCED)'..."
	@if docker exec $(SOLR_CONTAINER_NAME) solr status | grep -q "$(COLLECTION_ADVANCED)"; then \
		echo "Collection '$(COLLECTION_ADVANCED)' already exists."; \
	else \
		echo "Creating collection '$(COLLECTION_ADVANCED)'..."; \
		docker exec -i $(SOLR_CONTAINER_NAME) solr create -c $(COLLECTION_ADVANCED); \
	fi

configure-schemas:
	@echo "Applying schema from $(SCHEMA_SIMPLE) to $(COLLECTION_SIMPLE)..."
	curl -X POST -H 'Content-type:application/json' \
		--data-binary "@$(SCHEMA_SIMPLE)" \
		"http://localhost:$(SOLR_PORT)/solr/$(COLLECTION_SIMPLE)/schema"
	@echo "\nApplying schema from $(SCHEMA_ADVANCED) to $(COLLECTION_ADVANCED)..."
	curl -X POST -H 'Content-type:application/json' \
		--data-binary "@$(SCHEMA_ADVANCED)" \
		"http://localhost:$(SOLR_PORT)/solr/$(COLLECTION_ADVANCED)/schema"
	@echo "\nAll schemas configured successfully!"

populate-collections:
	@echo "Copying $(JSON_FILE) to container..."
	docker cp $(JSON_FILE) $(SOLR_CONTAINER_NAME):/tmp/$(JSON_FILE)
	@echo "Populating collection '$(COLLECTION_SIMPLE)'..."
	docker exec $(SOLR_CONTAINER_NAME) curl -X POST \
		'http://localhost:8983/solr/$(COLLECTION_SIMPLE)/update/json/docs?commit=true' \
		-H 'Content-Type: application/json' \
		--data-binary @/tmp/$(JSON_FILE)
	@echo "Populating collection '$(COLLECTION_ADVANCED)'..."
	docker exec $(SOLR_CONTAINER_NAME) curl -X POST \
		'http://localhost:8983/solr/$(COLLECTION_ADVANCED)/update/json/docs?commit=true' \
		-H 'Content-Type: application/json' \
		--data-binary @/tmp/$(JSON_FILE)
	@echo "Both collections populated successfully!"

clean-solr:
	@echo "Removing container '$(SOLR_CONTAINER_NAME)'..."
	-docker rm -f $(SOLR_CONTAINER_NAME)