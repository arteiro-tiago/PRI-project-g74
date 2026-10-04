# AGENTS.md

## Project: CVE-based Information Retrieval and Data Recovery

This repository is the working project for the PRI course at FEUP, focused on building a search system for cybersecurity vulnerabilities using CVE data.

The project follows the course requirements for a text-rich, unstructured dataset and aims to support ad hoc retrieval over vulnerability documents, with queries such as:

- "Which vulnerabilities affect a specific product or vendor?"
- "Which CVEs have high severity and a public exploit?"
- "Which vulnerabilities are related to a given CWE or attack vector?"
- "Which CVEs mention a specific platform or component?"

---

## 1. Project goal

Design and implement a retrieval pipeline for cybersecurity vulnerability data based on:

- CVE identifiers (e.g. CVE-2026-12345)
- CVSS severity and impact metrics
- affected products / targets
- vulnerability descriptions
- exploit and advisory details
- cross-linked metadata from additional sources

The final system should support information needs over a document collection built from structured and unstructured text.

---

## 2. Topic and data sources

### Selected theme

Cybersecurity — CVEs

### Primary source

- NVD (National Vulnerability Database)
- Data feed: https://github.com/fkie-cad/nvd-json-data-feeds
- Rich structured data source with CVE records, severity metrics, affected products, references, and descriptions.

### Secondary source for enrichment

- GitHub Advisory Database
- Used to enrich CVEs with additional textual information such as summaries, details, and contextual explanations.
- The cross-reference key is the CVE alias / identifier.

### Project requirement

The dataset must combine at least two distinct sources and include both:

- structured data (e.g. CVSS score, affected software, CWE, date, references)
- unstructured textual data (e.g. descriptions, advisory notes, summaries, exploit details)

This is essential for the course milestone regarding data preparation and later retrieval work.

---

## 3. Repository purpose

This repo is intended to support the first milestone pipeline for:

1. collecting CVE data, 2. filtering relevant records, 3. linking multiple sources, 4. normalizing fields, 5. exporting a final document collection.

Current implementation:

- `NVD_extractor.py` manages the data acquisition and export pipeline.
- It clones the NVD data feed repository, filters CVEs by year, and exports a CSV from JSON records.

This is the starting point for the project; future work should evolve it into a reproducible, documented data processing pipeline for the full project.

---

## 4. Expected data model

Each final document should represent one CVE and include a consolidated set of fields such as:

- `cve_id`
- `published_date`
- `last_modified_date`
- `severity` / `cvss_score`
- `severity_level` / `base_severity`
- `vector_string`
- `cwe`
- `affected_products`
- `vendor`
- `description`
- `summary`
- `details`
- `references`
- `exploit_related_fields`
- `source`
- `source_url`

The final document must be suitable for indexing and retrieval in a search engine.

---

## 5. Milestone 1 scope

The first milestone focuses on the data pipeline and characterization.

Required tasks:

- search repositories for datasets
- select convenient subsets
- assess data source quality and authority
- perform exploratory data analysis
- build and document a reproducible processing pipeline
- characterize the final collection
- define the conceptual model of the domain
- identify information needs for subsequent retrieval tasks

At minimum, the team should produce:

- a documented data acquisition workflow
- a filtering strategy
- a normalization/merge strategy for multiple sources
- a final CSV/JSON collection for indexing
- an exploratory analysis summary

---

## 6. Working conventions

### Coding principles

- Prefer reproducible scripts over manual steps.
- Keep all data-processing logic explicit and traceable.
- Avoid hardcoded paths that break portability across machines.
- Make scripts idempotent where possible.
- Add explanatory comments for non-trivial transformations.
- Use clear variable names and functions.

### Data pipeline rules

- Keep a clear separation between:
  - fetching raw data
  - filtering and sampling
  - normalization and enrichment
  - export to final dataset
- Log the exact source, date, and filtering criteria used.
- Document the subset selected per year and the sampling policy.
- Maintain traceability from raw NVD JSON to final retrieval corpus.

### Data quality expectations

- validate missing values
- assess duplicate entries
- harmonize inconsistent field names
- handle null/empty fields consistently
- ensure all records contain at least a valid CVE identifier and main text fields

---

## 7. Repository workflow

### Local setup

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Run the current extraction script

```bash
python NVD_extractor.py
```

### Expected output

The script currently:

- clones the NVD feeds repository
- filters CVEs by year range
- keeps a random subset per year
- exports a CSV from JSON records

This provides a working baseline, but the project should evolve toward:

- linked dataset enrichment
- richer schema construction
- filtering based on quality and relevance
- final corpus generation for Solr indexing

---

## 8. Milestone evolution

### Milestone 1: Data preparation

Focus on:

- selecting and combining relevant sources
- extracting and normalizing rich CVE metadata
- building a clean documents collection
- maintaining a reproducible pipeline

### Milestone 2: Information retrieval

Focus on:

- indexing the final collection with Solr
- identifying indexable components
- defining queries and evaluation scenarios
- comparing at least two retrieval setups

### Milestone 3: Final search system

Focus on:

- improving retrieval quality
- implementing a semantic retrieval approach
- comparing lexical and semantic strategies
- adding a final user-facing search interface if appropriate

---

## 9. Quality bar for the project

A successful project should demonstrate:

- clear topic motivation and research relevance
- properly justified data sources
- robust processing pipeline
- meaningful document model
- realistic information needs
- evaluation of retrieved results
- a final system that can answer practical cybersecurity queries

---

## 10. Contribution guidance

All group members should contribute to:

- dataset selection
- processing pipeline design
- schema design and document modeling
- retrieval implementation
- evaluation and report writing
- presentation and discussion

No single member should own the project alone. The process must remain collaborative and reproducible.

---

## 11. Recommended next steps

The next improvements for this repository should include:

1. Create a more explicit data cleaning and normalization stage.
2. Merge NVD and GitHub Advisory records by CVE ID.
3. Flatten nested JSON structures into a clear document schema.
4. Generate a final corpus with text fields ready for indexing.
5. Add a small EDA report summarizing distributions, missing values, and CVSS ranges.
6. Prepare a query set for later retrieval evaluation.

---

## 12. Important reminder

This project is not just a data downloader. It is a retrieval system project grounded in real-world cybersecurity data. The most important success criterion is a well-documented, reproducible, and evidence-based pipeline that leads to a high-quality document collection for indexing and information retrieval.
