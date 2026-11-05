VENV = venv
PYTHON = $(VENV)/bin/python
PIP = $(VENV)/bin/pip

.PHONY: all setup install run clean

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