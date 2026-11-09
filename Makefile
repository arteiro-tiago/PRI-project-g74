VENV = venv
PYTHON = $(VENV)/bin/python
PIP = $(VENV)/bin/pip

SOLR_CONTAINER_NAME = my-solr
SOLR_PORT = 8983
COLLECTION_NAME = cves
CSV_FILE = final_cves.csv
SOLR_IMAGE = solr:latest
SCHEMA_FILE = schema.json

.PHONY: preparation setup install run clean solr-setup run-container create-collection populate-collection clean-solr

preparation: setup install run

setup:
	@test -d $(VENV) || python3 -m venv $(VENV)

install: setup
	@$(PIP) install -r requirements.txt

run: install
	@$(PYTHON) src/nvd_preparation.py
	
clean:
	rm -rf $(VENV) __pycache__ *.pyc

solr-setup: run-container create-collection configure-schema populate-collection

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

create-collection:
	@echo "Checking if collection '$(COLLECTION_NAME)' exists..."
	@if docker exec $(SOLR_CONTAINER_NAME) solr status | grep -q "$(COLLECTION_NAME)"; then \
		echo "Collection '$(COLLECTION_NAME)' already exists."; \
	else \
		echo "Creating collection '$(COLLECTION_NAME)'..."; \
		docker exec -i $(SOLR_CONTAINER_NAME) solr create -c $(COLLECTION_NAME); \
	fi

configure-schema:
	@echo "Applying custom schema from $(SCHEMA_FILE)..."
	curl -X POST -H 'Content-type:application/json' \
		--data-binary "@$(SCHEMA_FILE)" \
		"http://localhost:$(SOLR_PORT)/solr/$(COLLECTION_NAME)/schema"
	@echo "\nSchema configured successfully!"

populate-collection:
	@echo "Copying final_cves.json to container..."
	docker cp final_cves.json my-solr:/tmp/final_cves.json
	@echo "Populating collection using Solr JSON update handler..."
	docker exec my-solr curl -X POST \
		'http://localhost:8983/solr/cves/update/json/docs?commit=true' \
		-H 'Content-Type: application/json' \
		--data-binary @/tmp/final_cves.json
	@echo "Data populated successfully!"

clean-solr:
	@echo "Removing container '$(SOLR_CONTAINER_NAME)'..."
	-docker rm -f $(SOLR_CONTAINER_NAME)