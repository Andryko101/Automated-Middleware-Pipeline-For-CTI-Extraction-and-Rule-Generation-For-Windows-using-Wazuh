# Project Overview — CTI-to-Wazuh Detection Rule Automation

**Covers two repositories:**

| Short name | Repository (as uploaded) |
|---|---|
| **AMP** | `Automated-Middleware-Pipeline-For-CTI-Extraction-and-Rule-Generation-For-Windows-using-Wazuh` |
| **Lacuna** | `lacuna_project` |

**Companion document:** `ProjectCoordination.md` (how an agent can work inside one repo without breaking the other).

**How this was produced:** every file in both archives was inventoried and the code, docs, datasets and model metadata were read. Neither codebase was executed. Where a number comes from a repo's own documentation (for example Lacuna's test counts and measured results), it is labelled *(per handover.md)*. A handful of AMP defects were confirmed with static checks (pyflakes, dataset inspection) and are marked ✔.

---

## 1. What the project is

Both repositories pursue the same goal: **turn published cyber threat intelligence (CTI) about Windows attacks into Wazuh detection rules, automatically.**

They are two different takes on it, built separately:

- **AMP** is a working prototype of the *front half* plus a quick rule compiler. It watches four vendor feeds, scrapes new articles, extracts indicators with a custom-trained spaCy NER model, and writes Wazuh XML rules that match specific IPs, domains and process names (IOC-style rules). Python only, no tests, one README.
- **Lacuna** is a staged, documented, tested *architecture* for the whole path: triage → entity extraction → MITRE ATT&CK mapping (with an honest fallback when unsure) → Sigma rule → Wazuh XML → validation against historical telemetry → promote or hold for human review. Python for Stages 0–2, Rust for Stages 3–4 (binding decision ADR-0001). Its NLP stages currently run on interim stand-ins because its development sandbox could not reach HuggingFace.

**Today the two repos are not connected in code.** There is no shared import, file format or schema. They are complementary:

| AMP has what Lacuna lacks | Lacuna has what AMP lacks |
|---|---|
| Live feed ingestion (FreshRSS + 4 Scrapy spiders) | ATT&CK mapping with confidence gate and fallback |
| 1,553 labelled NER tasks (871 entity annotations) | Sigma generation and a Sigma→Wazuh translator |
| A trained spaCy NER model (dev F1 ≈ 0.85) | A validation harness with a false-positive-rate promotion gate |
| Real scraped corpus (~21k text blocks) | Tests, CI, typed schemas, ADR log, evaluation plan |

### Side by side

| | AMP | Lacuna |
|---|---|---|
| Language / stack | Python: Scrapy, spaCy 3.8, `google_reader`, `tldextract`, Twisted | Python 3.11 (pydantic, httpx, ChromaDB) + Rust (tokio, serde, reqwest, regex) |
| Input sources | FreshRSS (hosted on Render) → CISA, The DFIR Report, Red Canary, Unit 42 | NVD, CISA KEV, generic RSS/Atom, local sample reports |
| What it emits | Wazuh rules matching **indicators** (IPs, domains, process names) | Wazuh rules matching **techniques** (curated Sigma templates), staged not active |
| ATT&CK awareness | Hard-coded: 7 offensive tools → technique IDs | 474-technique Windows corpus, similarity search, confidence gate |
| Safety gate before deployment | None | FPR replay + promotion gate; held rules go to a review queue |
| Quality gates | None (no tests, CI, or dependency manifest) | ruff, mypy `--strict`, pytest, pip-audit; cargo fmt/clippy/test/audit; CI workflow |
| Docs | One README | Architecture, ADRs, data schema, evaluation plan, todo, handover, session notes |
| Size | ~35 MB unpacked (mostly datasets and model files) | ~4.1k lines Python (incl. tests), ~2.6k lines Rust in `src/` |

### How they relate today

```
AMP (all Python, one process)
  FreshRSS ─► Scrapy spiders ─► reports/*.jsonl ─► spaCy NER + regex ─► IOC sanitising ─► Wazuh XML
  (Render)    (4 vendors)       {title,url,text}    5 labels            allow/block lists   IP / domain / process rules

Lacuna (Python → Rust)
  sources ─► Stage 0 ─► Stage 1 ─► Stage 2 ──JSONL──► Stage 3 ─────────────► Stage 4 ─────────────► promote
             triage     extract    ATT&CK map  (one   Sigma ► Wazuh XML      replay vs ClickHouse    or hold for
             (real)     (rule-     (TF-IDF +   file   (10 techniques +       baseline, FPR < 2%      human review
                        based)     fallback)   hop)   6 fallback templates)  (synthetic baseline)
```

Natural seams between them (none built yet, all described in `ProjectCoordination.md`): AMP's scraped reports could feed Lacuna's Stage 0, AMP's spaCy model could become a Stage 1 extractor, and AMP's labelled data could supply Lacuna's missing training and evaluation set.

---

## 2. What is implemented

### 2.1 AMP

**Flow.** `data_ingestion/freshrss_sync.py` logs in to FreshRSS, fetches up to 10 unread items, skips URLs already in `seen_urls.db`, routes each URL to a spider by domain, runs the spiders, marks items read in FreshRSS, then calls `rule_generation.demo.run_interactive_demo()`, which reads `data_ingestion/reports/*.jsonl`, extracts entities, and writes `rule_generation/demo_rules.xml`.

| Component | Location | State |
|---|---|---|
| Feed watcher / orchestrator | `data_ingestion/freshrss_sync.py` | Implemented. Credentials hard-coded (see §4). |
| Four spiders | `data_ingestion/cti_scraper/spiders/` | CISA, DFIR Report, Red Canary, Unit 42. Each keeps only text blocks containing Windows keywords. Red Canary spider is broken ✔ (see §4). |
| Scrapy pipelines | `cti_scraper/pipelines.py` | Windows keyword filter and a SQLite seen-URL recorder. |
| Scraped corpus | `data_ingestion/reports/` | 5 `.jsonl` files, 21,266 lines total (one text block per line), plus two CISA `.json` files. |
| Dataset tooling | `NLP/convert_to_spacy.py`, `active_learning.py`, `merge_datasets.py`; `fix.py` at root | Label Studio export → spaCy `DocBin`; model-assisted pre-annotation for Label Studio; export merging; a whitespace-boundary checker (hard-coded to one file). |
| Labelled datasets | `NLP/datasets/` | Versions v2 → v5 (v5: 1,553 tasks, 871 annotations), three unannotated pre-annotation files, plus per-project exports. |
| Trained model | `NLP/models/model-best`, `model-last` | spaCy `tok2vec` + `ner`. 5 labels. Details below. |
| Rule compiler (current) | `rule_generation/demo.py` | Hybrid spaCy + regex extraction, defang normalisation, private-IP filtering, public-suffix domain validation, allowlists, LOLBin exclusion, severity tiers. Emits IP, domain, offensive-tool and generic-process rules. |
| Rule compiler (earlier) | `rule_generation/generate_wazuh_rules.py` | Stale; produces no usable output (see §4). |
| Committed rule output | `rule_generation/*.xml` | `demo_rules.xml` (10 rules), `cisa_wazuh_rules.xml` (5), `cisa_wazuh_rules_v2.xml` (20), `wazuh_rules.xml` (empty file). |

**Model quality** (from the model's own `meta.json`, on its dev split):

| Label | F1 | Labelled examples in v5 |
|---|---:|---:|
| Process_Name | 0.945 | 433 |
| Domain_URL | 0.960 | 69 |
| IP_Address | 0.900 | 40 |
| File_Path | 0.687 | 220 |
| Command_Line | 0.529 | 107 |
| Registry_Key | 0.0 (not in the model's label set) | 1 |
| Threat_Actor | 0.0 (not in the model's label set) | 1 |
| **Overall** | **0.847** (P 0.840, R 0.855) | |

`model-last` scores 0.834 overall. `generate_wazuh_rules.py` calls `model-best` the "Version 4 model"; nothing in the repo records which dataset version produced the committed weights.

**Rule shapes `demo.py` emits** (all `pcre2` field matches gated on `<if_group>sysmon_event1</if_group>` or `sysmon_event3`):

| Rule | Wazuh ID | Level | Matches |
|---|---|---:|---|
| Malicious IPs | 100005 | 12 | `win.eventdata.destinationIp` |
| Malicious domains | 100004 | 12 | `win.eventdata.destinationHostname` (anchored) |
| 7 known offensive tools (mimikatz, psexec, psexesvc, rclone, anydesk, netscan, adfind) | 100010+ | 8–12 | `win.eventdata.image` plus a hard-coded technique ID |
| Everything else that is a process name | 100002 | 10 | `win.eventdata.image` |

### 2.2 Lacuna

Status below is **per its own `handover.md`**: Phases 0–5 complete plus CI; Phase 6 onward not started.

| Stage | Location | State | Real or interim |
|---|---|---|---|
| Schemas (5 contracts) | `pipeline/schemas/`, `docs/data-schema.md` | Done. ADR-0005 and the promotion gate are enforced as validators. | Real |
| **Stage 0** Triage | `pipeline/triage/` | HTML strip, English heuristic, hash dedup, Windows-relevance allowlist, CVSS (NVD) and EPSS (FIRST.org) lookups, no-CVE heuristic, four connectors (NVD, KEV, RSS, local files). | Real; network paths tested only against mocked HTTP |
| **Stage 1** Extraction | `pipeline/extraction/` | `RuleBasedExtractor` (regex plus a 23-name malware dictionary), labelled-data loader/validator, P/R/F1 harness, fine-tuning script, `TransformerNERExtractor`. | Rule-based is real. Transformer path written but **never run** (HuggingFace unreachable, only 10 labelled examples). The F1 = 1.0 on `seed.jsonl` is not meaningful: the examples were written while building the regexes. |
| **Stage 2** ATT&CK mapping | `pipeline/mapping/`, `data/attck/techniques.json` | 474 real Windows techniques from MITRE STIX data, ChromaDB collection, confidence-gated `TechniqueMapper`, fallback primitives, tactic- and technique-level evaluation. | Embedding is an **interim TF-IDF** stand-in, not a neural model. Threshold is 0.45, not the 0.75 in `Architecture.md`. |
| **Handoff** Python → Rust | `middleware/src/handoff.rs` | Reads one `MappedTechniqueRecord` per JSONL line; writes `<id>.rule_bundle.json` and `<id>.validation_report.json`; a bad line does not abort the batch. | Real. **No Python code writes this JSONL yet.** |
| **Stage 3** Rule generation | `sigma_gen.rs`, `wazuh_adapter.rs` | Curated Sigma template library: 10 techniques (T1053.005, T1547.001, T1003.001, T1218.011, T1059.001, T1047, T1550.002, T1558.003, T1055, T1105) plus the 6 fallback primitives. Anything else yields an inert, never-matching placeholder rule. Sigma→Wazuh XML matches `win.system.eventID` plus `win.eventdata.*` directly (no `if_group`). | Real; never loaded into a live Wazuh manager |
| **Stage 4** Validation | `validation.rs`, `logtest_replay.rs`, `clickhouse_client.rs` | Replays generated XML conditions against a ClickHouse baseline, computes FPR, applies the gate (FPR < 2% and syntax valid → promoted, else held). Empty baseline is a loud error. `middleware review` lists held rules. | **Interim**: not the real `wazuh-logtest`; baseline is 1,918 *synthetic* events over 90 days |
| Dev tools | `examples/inspect_rule.rs`, `examples/generate_baseline.rs` | Print Sigma/XML for any technique; populate ClickHouse with the synthetic baseline. | Real |
| CI | `.github/workflows/ci.yml` | Python job (ruff, mypy strict, pytest, pip-audit) and Rust job (fmt, clippy `-D warnings`, build, test, cargo-audit) fanned into `ci-success`. | Python gates verified; Rust fmt/clippy/audit never run locally |
| Docs and ADRs | `docs/`, `handover.md`, `session.md` | Five ADRs; architecture; evaluation plan; phased todo. | — |

**Measured results** *(per handover.md)*:

- Tests: 126 Python, 40 Rust, all passing. No test needs live network or a live ClickHouse.
- Mapping against a 12-example gold set: technique-level P 1.00 / R 0.20 / F1 0.333, tactic-level F1 0.444, fallback rate 83.3%. Precision is perfect because the mapper only commits when sure. Recall is low because of the TF-IDF embedding.
- Validation across the 10 curated techniques: 9 promoted (FPR 0.00%–1.15%), **T1055 held at 2.87%** against the 2% gate. The handover presents this as the gate working as designed.
- Two real bugs were found and fixed by running generated rules rather than trusting the generator (a doubled `(?i)` flag, and a T1055 wildcard escaped into a pattern that could never match).

---

## 3. What is yet to be implemented

### 3.1 AMP

Nothing here is planned in a roadmap (AMP has no todo or roadmap document); these are gaps measured against the stated goal and against Lacuna's capabilities.

- Fix the verified defects in §4.
- A dependency manifest (`requirements.txt` or `pyproject.toml`), a test suite, and CI. Currently dependencies exist only as a list in the README.
- Move credentials out of source into environment variables.
- Connect scrape output to the rule compiler automatically. Scrapy writes to `output_data/<spider>.jsonl` but the compiler reads `data_ingestion/reports/*.jsonl`; the committed files there have different names, so a manual copy step exists today.
- Compile rules for labels the model already produces (`File_Path`, `Command_Line`); `demo.py` only compiles IPs, domains and process names.
- Registry-key and threat-actor extraction (one labelled example each; the model cannot predict them).
- Any ATT&CK mapping beyond the 7 hard-coded tools.
- Rule validation, false-positive measurement, staging and review (none exists).
- Dataset hygiene: de-duplicate, seed the train/dev split, split by article, re-evaluate (see §4).

### 3.2 Lacuna

From `todo.md` and `handover.md`:

- **Phase 6, integration and end-to-end testing** (next up): a driver that takes raw CTI in and produces a `RuleBundle` plus `ValidationReport` out; `scripts/run_pipeline_e2e.sh` is an empty file today. Three attack-simulation scenarios run through the real code. Measure latency against the 15-minute target. Note: password spray (T1110) has no curated template, so it would correctly produce the inert placeholder.
- **Phase 7, evaluation:** choose the baseline comparator (community Wazuh ruleset recommended), run the full metric suite against it.
- **Phase 8, documentation and defense prep:** update `Architecture.md` for as-built deviations (it still says threshold 0.75 and neural embeddings), write results, rehearse demo.
- **Outstanding Phase 2 work:** 100–200 labelled sentences (10 exist), fine-tune and evaluate a real NER model, record F1 against the ≥ 0.70 target.
- **Outstanding Phase 3 work:** swap TF-IDF for a neural embedding, re-calibrate the threshold from scratch, grow the 12-example gold set, re-run evaluation.
- **Outstanding Phase 1 work:** hand-collect 20–30 real reports to validate the relevance filter and heuristic (2 sample reports exist, one of them Linux).
- **Testbed (not provisioned):** the two-node VirtualBox lab with real Wazuh Manager, Wazuh Agent and Sysmon. `testbed/sysmon-config.xml` and `scripts/*.sh` are empty placeholder files. Until it exists, generated rules have never been loaded into a real Wazuh, and the baseline is synthetic.
- Broaden the template library beyond 10 techniques (everything else is inert by design).
- Make the 6 fallback-primitive strings a shared closed vocabulary rather than literals duplicated across Python and Rust.
- Stretch goals (only after Phase 7): second Sigma backend, review dashboard.

### 3.3 Across the two repos

- Any code-level connection between them (candidate seams: scraped reports → Stage 0, spaCy model → Stage 1, labelled data → Lacuna's evaluation set).
- A decision on IOC rules (§5, decision 1).
- Agreement on shared Wazuh rule-ID ranges and rule-gating conventions (§4).

---

## 4. Findings worth knowing before touching either repo

### AMP defects

| # | Finding | Evidence |
|---|---|---|
| A1 | **Hard-coded FreshRSS credentials and URL** committed in source. README names a different host (`cti-freshrss.onrender.com`) than the code (`freshrss-ijkt.onrender.com`). Treat the committed password as exposed. | `freshrss_sync.py` lines 20–22; `testing_freshrss_connection.py` |
| A2 | Red Canary spider references an undefined name `containers`, so `parse_report` raises `NameError` at its end. ✔ | `redcanary_spider.py:65` (pyflakes) |
| A3 | `"taskeng.exe""explorer.exe"` is missing a comma, producing one bogus entry `taskeng.exeexplorer.exe`, so `taskeng.exe` is not excluded as a LOLBin. ✔ | `demo.py:49` |
| A4 | `generate_wazuh_rules.py` reads a Label Studio export as if text were at the top level (it is under `data.text`) and loads the model by a relative path, so it extracts nothing. Committed `wazuh_rules.xml` is empty. ✔ | script plus `v4_master_dataset.json` structure |
| A5 | Unit 42 spider's constructor swallows `target_url`, so a FreshRSS-triggered crawl scrapes the whole feed instead of one article. | `unit42_spider.py` |
| A6 | Every CISA record in `cisa_tactical_reports.json` has an empty title (565 of 565). ✔ | file inspection |
| A7 | Seen-URL tracking is relative to the working directory: three separate `seen_urls.db` files exist (0, 135 and 68 rows). Deduplication depends on where you run from. ✔ | `find` plus SQLite |
| A8 | `freshrss_sync.py` imports `rule_generation.demo` at the top, and `demo.py` loads the model and calls `exit(1)` at import time on failure. | both files |
| A9 | The CISA spider disables `robots.txt` and the project sends a browser User-Agent. Confirm this is acceptable for the intended use. | spider and `settings.py` |

### AMP dataset and model caveats

- **258 of 1,553 tasks (16.6%) in v5 are exact duplicate texts** ✔, and `convert_to_spacy.py` shuffles without a seed and splits by task. Duplicates can land on both sides of the split, and the dev score cannot be reproduced exactly. 1,191 tasks carry no `source_url`, so splitting by article is not possible for most of the data.
- 1,013 of 1,553 tasks (65%) contain no entities at all ✔. Useful as negatives, but they dominate the set.
- Two labelled spans do not match their text and 12 are whitespace-padded ✔ (the converter's `alignment_mode="contract"` silently absorbs these).
- `Command_Line` labels are inconsistent in shape: some are whole command lines, some are single cmdlets such as `Get-VHD`. Many IOCs are labelled in defanged form (`45.227.254[.]124`).
- The model's `meta.json` lists `Threat_Actor` and `Registry_Key` in its scores but not in its label set. Treat both as unsupported.

### Lacuna notes

- **Rule-ID range:** Lacuna derives IDs as `110000 + hash % 9000` (110000–118999); two distinct rules can collide within that range. AMP uses 100002, 100004, 100005 and 100010+. No overlap today, but nothing reserves the ranges.
- **Rule-gating convention differs:** AMP gates on `<if_group>sysmon_event1</if_group>`; Lacuna deliberately avoids `if_group` (group names vary by Wazuh version) and matches `win.system.eventID` directly. Neither has been loaded into a real Wazuh manager.
- **Lockfile inconsistency:** `.gitignore` lists `Cargo.lock` and `handover.md` says it is not committed, yet one is in the archive. It has 84 packages and no `url` or `idna` entries, which `reqwest` (added in Phase 5) pulls in, so it predates Phase 5.
- **Empty placeholders:** `README.md`, `LICENSE`, `scripts/*.sh`, `testbed/sysmon-config.xml` and `testbed/snapshots/README.md` are zero bytes. `testbed/virtualbox/` and `testbed/wazuh-manager/` listed in `projectStructure.md` do not exist.
- **Doc drift:** `Architecture.md` still states threshold 0.75; code uses 0.45. `handover.md` refers to a `wazuh_gen.rs` that does not exist (the primitive templates live in `sigma_gen.rs`).
- **IOCs do not survive Stage 2→3.** `MappedTechniqueRecord` carries no entities. Extracted process names, domains and IPs influence only the similarity query and which fallback primitive is chosen. They never reach a rule. This is a deliberate design decision in Lacuna and the root of the AMP/Lacuna difference in what rules mean.

---

## 5. Open decisions for the project owner

Agents working in either repo should **not** resolve these on their own:

1. **IOC rules.** Should indicator-matching rules (AMP's model) exist inside the Lacuna pipeline? Supporting them means changing Lacuna's frozen contracts (a new record type or new fields carrying entities to Stage 3). Until decided, the two rule families stay separate.
2. **Canonical dataset.** Which AMP dataset file is the training and evaluation source of truth? By name, `v5_fixed_relabelled_master_dataset.json` looks like the latest, but the repo does not say.
3. **Entity confidence.** spaCy's default NER gives no per-entity score, while Lacuna's `ExtractedEntity.confidence` is required. Fixed 1.0 with a documented meaning, or beam-scored confidence.
4. **Taxonomy gaps.** AMP's `Threat_Actor` has no Lacuna entity type (and must not be mapped to `malware_name`). Add a type to the schema, or drop it.
5. **Model distribution.** Lacuna gitignores model artifacts and says to track them via releases. Decide where AMP's model ships from.
6. **Credentials.** Rotate the exposed FreshRSS password and decide whether the hosted FreshRSS instance stays in use.
