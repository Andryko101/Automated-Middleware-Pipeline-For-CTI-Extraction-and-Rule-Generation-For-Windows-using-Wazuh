# Threat Intelligence Ingestion & Rule Generation Pipeline

This project automates the ingestion of threat intelligence reports from RSS feeds, extracts Windows-specific Indicators of Compromise (IOCs) using a custom Named Entity Recognition (NER) model, and compiles them into Wazuh-compatible XML rules.

## Infrastructure & External Services
- **FreshRSS**: Acts as the 24/7 cloud "watchman" that monitors CISA, Unit 42, DFIR Report, and Red Canary feeds for newly published articles.
- **Render (`cti-freshrss.onrender.com`)**: The cloud hosting platform running the FreshRSS web instance and its PostgreSQL database. The deployment relies on persistent environment variables (`FRESHRSS_INSTALL`, `FRESHRSS_USER`) to automatically bypass the setup wizard upon container restarts or wake-ups.

## Required Software & Dependencies
- **Python**: 3.10+
- **Scrapy**: Web scraping framework for targeted threat intel spiders.
- **spaCy**: NLP engine for extracting threat actors, IPs, registry keys, and file paths.
- **google_reader**: API wrapper to authenticate and sync unread RSS items from FreshRSS.
- **Twisted**: Asynchronous networking engine to run Scrapy programmatically.
- **Custom NLP Model**: A locally trained spaCy model located in `NLP/models/model-best`.

## Project Architecture

### 1. `data_ingestion/` (The Extraction Layer)
Manages the automated fetching of threat intelligence reports triggered by the cloud radar.
- **`freshrss_sync.py`**: The main orchestrator script that authenticates with the Render FreshRSS instance, pulls unread article URLs, and dynamically routes them to the correct local Scrapy spider.
- **`reports/`**: Output directory where Scrapy spiders save extracted telemetry as structured JSON and JSONL files (e.g., `cisa_tactical_reports.jsonl`).
- **`cti_scraper/`**: The core Scrapy project folder.
  - **`spiders/`**: Contains the four individual crawlers (`cisa_spider.py`, `dfir_scraper.py`, `redcanary_spider.py`, `unit42_spider.py`).
  - **`pipelines.py` & `middlewares.py`**: Handle data processing and routing as items are scraped.
  - **`seen_urls.db`**: Local SQLite database for tracking previously scraped links to prevent duplication.

### 2. `NLP/` (The Machine Learning Layer)
Contains all components related to training and storing the custom Named Entity Recognition (NER) model.
- **`models/`**: Stores compiled spaCy models, including the production `model-best`.
- **`datasets/`**: Contains raw and pre-annotated JSON datasets used for model training.
- **`convert_to_spacy.py` / `train.spacy`**: Scripts for converting raw annotations into spaCy's binary format and initiating active learning.

### 3. `rule_generation/` (The Compilation Layer)
Parses scraped text, extracts Indicators of Compromise (IOCs), and compiles them into Wazuh-compatible XML rules.
- **`demo.py`**: An interactive script that loads a JSON report, uses the custom spaCy model alongside regex to extract hybrid entities, maps them to Sysmon Event IDs (e.g., `win.eventdata.image`), and outputs a `demo_rules.xml` file.
- **`generate_wazuh_rules.py`**: A bulk processing script designed to read concatenated JSONL files, extract entities via the version 4 model, chunk massive regex lists to prevent PCRE2 overload, and group the generated XML rules by Advisory title into `wazuh_rules.xml`.