# plan.md — AMP: CTI → Wazuh Rule Pipeline

> **Purpose.** Single source of truth for *where the project is* and *what gets built next*.
> Update the status boxes and the change log (§12) at the end of every working session.
>
> **Scope.** This plan covers the **AMP** repo (`Automated-Middleware-Pipeline-For-CTI-Extraction-and-Rule-Generation-For-Windows-using-Wazuh`).
> The sibling **Lacuna** repo (`lacuna_project`) is described in `Project_overview.md` / `ProjectCoordination.md`, but it was **not** uploaded, so nothing about Lacuna below has been verified. Treat Lacuna facts as "per the docs".
>
> **Status labels:** `[x]` done · `[~]` partly done / needs rework · `[ ]` not started · `⚠` needs owner decision · **PROPOSED** = my recommendation, not yet agreed.

---

## 1. Goal and success criteria

**Goal.** Turn published Windows-focused threat intelligence (CISA, The DFIR Report, Red Canary, Unit 42) into Wazuh detection rules automatically, with a human review step before anything is deployed.

**MVP is done when** one command takes a newly published article and produces:
1. scraped text with a stable, documented format,
2. extracted indicators with provenance (which article, which model version),
3. a *valid* Wazuh rule file that loads on a real Wazuh manager and fires on a test event,
4. a staged/held decision with a measured false-positive check against benign Sysmon telemetry,
5. a reproducible run from a clean checkout, with no secrets in git.

Today, items 1 and 5 are partly met, item 3 is unverified, and items 2 and 4 do not exist (§3).

---

## 2. How this plan was produced (and its limits)

- Read all of `Project_overview.md` and `ProjectCoordination.md`.
- Unpacked the AMP repo (106 entries) and read the orchestrator, all spiders, pipelines, settings, `demo.py`, `generate_wazuh_rules.py`, the converter/merge/active-learning scripts, `config.cfg`, and the model `meta.json`.
- Ran **static checks only**: `pyflakes`, dataset/report inspection with Python, XML well-formedness, SQLite row counts.
- **Not run:** Scrapy, spaCy, the model, the FreshRSS sync, any Wazuh instance. No network. So "works" below means "the code reads as if it works", not "I ran it".

### 2.1 Claims from the docs that I re-checked

| Claim (doc) | Result |
|---|---|
| A2: Red Canary spider uses undefined `containers` | **Confirmed** (pyflakes, `redcanary_spider.py:65`) |
| A3: missing comma → `"taskeng.exe""explorer.exe"` | **Confirmed** (`demo.py:49`; `explorer.exe` is excluded separately, `taskeng.exe` is not) |
| A1: hard-coded FreshRSS URL/user/password | **Confirmed** (`freshrss_sync.py:20–22`; host differs from README) |
| A5: Unit 42 spider ignores `target_url` | **Confirmed** (start URL is the whole feed) |
| A7: three `seen_urls.db` files | **Confirmed**: 0 rows (repo root), 135 (`data_ingestion/`), 68 (`cti_scraper/`) |
| A8: model loaded + `exit(1)` at import of `demo.py` | **Confirmed** by reading; `freshrss_sync.py` imports it at top |
| v5-fixed dataset: 1,553 tasks, 258 duplicate texts, 871 annotations, 1,013 negatives, 362 with `source_url` | **Confirmed** (label counts match the doc exactly) |
| Model dev F1 0.847; per-label scores | **Confirmed** from `meta.json` |
| 2 spans don't match their text | **Confirmed** |
| "12 whitespace-padded spans" | **Not reproduced.** My check compared the stored span text to the text slice and found 0 padded. Re-check before relying on the number. |
| A6: all CISA records have empty titles | Spot-checked only (first line of `cisa_tactical_reports.jsonl` has `title: ""`). Not fully re-counted. |

### 2.2 New findings not in the docs

| # | Finding | Why it matters |
|---|---|---|
| **N1** | **Four of the five committed "JSONL" report files are not JSONL.** `raw_cisa/dfir/redcanary/unit42_reports.jsonl` are pretty-printed JSON arrays. Parsing line-by-line, **0 lines parse in all four**. `demo.py` does `json.loads(line)` with `except JSONDecodeError: continue`, so it **silently skips them** and effectively reads only `cisa_tactical_reports.jsonl`. | The rule compiler has only ever seen CISA data from this directory. The scripts `generate_wazuh_rules.py` / `active_learning.py` carry their own "concatenated JSON" parser, which is how the files were consumed before. |
| **N2** | **Real record counts are lower than the docs state.** The docs say ~21k text blocks (21,266 *physical lines*). Parsed records: CISA-tactical 1,469 · raw_cisa 302 · raw_dfir 1,293 · raw_redcanary 781 · raw_unit42 1,584 = **5,429 records** across at most 141 distinct article URLs (94 + 10 + 12 + 10 + 15). | Sizing, sampling, and "P1 is one block per line" (contract in the coordination doc) are wrong for 4 of 5 files. Any C1 connector must handle both layouts or normalise first. |
| **N3** | **Generated rule files have no `<group>` wrapper** (`demo_rules.xml`, `cisa_wazuh_rules.xml`); only `cisa_wazuh_rules_v2.xml` has one. Wazuh rule files are normally a `<group name="…">` containing rules. *Not loaded into a manager by me, so this is a "confirm on a real manager" item, not a proven failure.* | The current compiler output may not load as-is. |
| **N4** | **Rule IDs collide across committed files.** All four rule files use IDs in 100001–100020; `demo_rules.xml` uses 100002, 100004, 100005, 100010–100016, all of which also appear in the two CISA files. Loading more than one together would duplicate IDs. | Needs an ID allocation scheme (§6, D7). |
| **N5** | **The compiler produces one aggregate rule per type** (all IPs → rule 100005, all domains → 100004, …) from *every entity in every report*, with a fixed ID, overwriting `demo_rules.xml` on every run. No per-article grouping, no source URL, no timestamp, no model version, no expiry. | A single bad indicator contaminates the whole regex; rules cannot be traced, reviewed, or retired individually. |
| **N6** | **`freshrss_sync.py` marks items "read" regardless of crawl outcome.** `processed_item_ids` is appended at dispatch time, then everything is marked read after `process.start()` with no success check. | A failed scrape (e.g. the Red Canary `NameError`) permanently drops the article from the unread queue. |
| **N7** | **`cisa_wazuh_rules_v2.xml` contains prose-length "patterns"** (a rule description of `CISA Intel Match: ...` and a file-path regex containing whole sentences). It is legacy output of `generate_wazuh_rules.py`. | Must not be deployed; archive or delete (owner's call). |
| **N8** | **Scrapy `FEEDS` has `overwrite: True` and writes to `output_data/<spider>.jsonl`, while the compiler reads `data_ingestion/reports/*.jsonl`.** Each run replaces the previous run's output, and nothing moves it to where the compiler looks. | The "automatic" flow is not actually wired end to end (manual copy today). |
| **N9** | **The model has no provenance.** `meta.json`: name `pipeline`, version `0.0.0`, empty description. `config.cfg`: no static vectors (`include_static_vectors = false`), `tok2vec` width 96 trained from scratch on ~1.2k texts. The converter shuffles with no seed, though `config.cfg` has `seed = 0`. | Can't reproduce or compare model versions; small-data model is fragile out of domain. |
| **N10** | `settings.py` sets `ROBOTSTXT_OBEY = True` globally (twice), but the CISA spider overrides it to `False` and all requests use a Chrome User-Agent. | Confirm this is intended and acceptable for the target sites (A9). |

---

## 3. Where we are (current state)

### 3.1 Pipeline as built

```
FreshRSS (Render)                       ← credentials hard-coded (A1)
   │  unread item URLs
   ▼
freshrss_sync.py ─► routes by domain ─► 4 Scrapy spiders (cisa_tactical, dfir, redcanary, unit42)
                                          │  Windows-keyword filter, SQLite seen-URL (cwd-relative)
                                          ▼
                                   output_data/<spider>.jsonl      (overwritten each run, N8)
                                          ✗ manual copy
                                   data_ingestion/reports/*.jsonl  (4 of 5 files unreadable line-wise, N1)
                                          ▼
                       rule_generation/demo.py: spaCy NER + regex + sanitising/allow-lists
                                          ▼
                       rule_generation/demo_rules.xml  (aggregate IOC rules, no <group>, fixed IDs)
```

### 3.2 Component status

| Component | Status | Notes |
|---|---|---|
| FreshRSS watcher / orchestrator | `[~]` | Works by design; secrets in source (A1); marks read on failure (N6); cwd-dependent DB (A7). |
| CISA spider | `[~]` | Functional; ignores robots.txt (N10); all titles empty (A6). |
| DFIR Report spider | `[~]` | Not individually examined beyond structure; same cwd-DB pattern. |
| Red Canary spider | `[ ]` broken | `NameError` at end of `parse_report` (A2). |
| Unit 42 spider | `[~]` | Crawls whole feed instead of one article (A5). |
| Scrapy pipelines | `[~]` | Windows filter + seen-URL recorder; `CtiScraperPipeline.process_item` has the wrong signature (unused, dead code). |
| Report corpus | `[~]` | 5,429 records but 4/5 files not valid JSONL (N1, N2). |
| NER dataset tooling | `[~]` | Unseeded split, duplicates leak across train/dev (258 dup texts), `contract` alignment hides bad spans. |
| Labelled data (v2→v5) | `[~]` | 1,553 tasks, 871 annotations, 65% negatives; `Command_Line` shape inconsistent; `Registry_Key` and `Threat_Actor` have 1 example each. Canonical file undecided ⚠. |
| NER model (`model-best`) | `[~]` | Dev F1 0.847 (Process 0.945, Domain 0.960, IP 0.900, File 0.687, Command 0.529). Score is optimistic because of duplicate leakage. No model card. |
| Rule compiler (`demo.py`) | `[~]` | Sensible sanitising (defang, private-IP filter, PSL domain check, allow/block lists, LOLBin exclusion) but see N3–N5, A3, A8. |
| Legacy compiler (`generate_wazuh_rules.py`) | `[ ]` dead | Reads wrong JSON path, relative model path; committed `wazuh_rules.xml` is empty (A4). |
| Tests / CI / dependency manifest | `[ ]` | None. Dependencies exist only in the README prose. |
| Rule validation / FP measurement / staging | `[ ]` | Nothing exists. |
| Real Wazuh manager test | `[ ]` | No evidence any rule file was ever loaded into a manager. |
| ATT&CK mapping | `[~]` | Seven hard-coded tools only. |
| Docs | `[~]` | One README, with wrong FreshRSS host and an inaccurate description of `demo.py` input handling. |

---

## 4. Guiding principles (from `ProjectCoordination.md`, trimmed)

1. **Stay in this repo.** Interact with Lacuna only via documented files.
2. **Contracts change doc-first.** Published surface: report line keys `title`/`source_url`/`text`, model label names, Label Studio export shape, model directory layout, spaCy version `>=3.8.16,<3.9.0`.
3. **Loud failures over silent skips.** (N1 is exactly the failure mode this prevents.)
4. **Never fabricate over a gap.** No guessed technique IDs, confidences, or rule logic.
5. **No secrets in git.** No new bulk data without approval. **Never overwrite dataset/model versions in place**: add new versioned files/dirs.
6. **Verify before claiming.** Say what was run and what wasn't.
7. **Leave a handoff note** every session (§11).

---

## 5. Phase roadmap

Effort: **S** < ½ day · **M** 1–2 days · **L** > 2 days. Phases 0–2 are independent of Lacuna and of the pending decisions except where marked ⚠.

### Phase 0 — Safety and reproducibility *(do first)*

| ID | Task | Size | Done when |
|---|---|---|---|
| 0.1 | ⚠ **Rotate the FreshRSS password** and treat the committed one as exposed (it is also in git history). | S | Old credential no longer works. *Owner action; agent must not rotate.* |
| 0.2 | Move `FRESHRSS_URL`, user, password to environment variables; fail loudly if unset; fix README host mismatch. Update `testing_freshrss_connection.py` the same way. | S | `grep` for the old password/host finds nothing in the tree. |
| 0.3 | Create `requirements.txt` (or `pyproject.toml`) pinned from a **working** environment: `scrapy`, `twisted`, `itemadapter`, `spacy>=3.8.16,<3.9.0`, `google_reader`, `tldextract`, `requests`. | S | Fresh venv + `pip install -r` + `python -c "import spacy; spacy.load('NLP/models/model-best')"` succeeds. |
| 0.4 | Expand `.gitignore`: `__pycache__/`, `*.pyc`, `*.db`, `output_data/`, local env files. Remove committed `.pyc` and the three `seen_urls.db` from tracking (**ask first** about deleting; they are small but are state). | S | `git status` clean after a run. |
| 0.5 | Single location for state: one configurable data dir (`CTI_DATA_DIR`, default `./var`) holding `seen_urls.db` and scrape output; all spiders/pipelines/orchestrator use it. | M | Running from any cwd gives the same result; one DB file. (Fixes A7, part of N8.) |

### Phase 1 — Make the existing pipeline correct

| ID | Task | Size | Done when |
|---|---|---|---|
| 1.1 | Fix A2 (`containers` NameError in Red Canary spider). | S | Spider runs against a saved HTML fixture without raising. |
| 1.2 | Fix A3 (comma in `LOLBINS_DUAL_USE`) and add a unit test that `taskeng.exe` is excluded. | S | Test passes. |
| 1.3 | Fix A5: Unit 42 spider honours `target_url` (single-article mode) like the CISA spider. | S | `scrapy crawl unit42 -a target_url=…` yields only that article (fixture test). |
| 1.4 | Fix A8: lazy-load the model (function/singleton) so importing `demo.py` has no side effects and no `exit()`. | S | `import rule_generation.demo` works without the model present; error raised only at use, with a clear message. |
| 1.5 | Fix N6: only mark a FreshRSS item read after its spider finished successfully (use Scrapy signals or item counts per URL). | M | Forced spider failure leaves the item unread. |
| 1.6 | **Report format normalisation (N1/N2):** add a loader `load_reports(dir)` that accepts both true JSONL and pretty-printed JSON arrays, **fails loudly** on a file it cannot parse, and reports per-file record counts. Write a *new* normalised copy under a new name; do not rewrite the committed raw files. | M | Loader returns 5,429 records from the committed set; compiler prints per-file counts. |
| 1.7 | Wire scrape output to the compiler (N8): spiders write to the data dir; compiler reads from the same place; set `overwrite: False` (append) or timestamped files. | M | One command scrapes then compiles with no manual copy. |
| 1.8 | Decide fate of legacy artifacts: `generate_wazuh_rules.py`, `wazuh_rules.xml` (empty), `cisa_wazuh_rules*.xml` (N7), `fix.py`. ⚠ Recommendation: move to `archive/` with a README note; do not delete without approval. | S | Nothing deployable is left that is known-bad. |

### Phase 2 — Data and model hygiene

| ID | Task | Size | Done when |
|---|---|---|---|
| 2.1 | ⚠ Owner names the **canonical dataset** (D2). Record it in the model card and in this file. | S | Decision logged in §6. |
| 2.2 | Build a **new** versioned dataset (e.g. `v6_*`): de-duplicate identical texts; fix the 2 mismatched spans; re-check the whitespace-padding claim; normalise `Command_Line` guidance (full command line vs cmdlet) and write a short labelling guide. | M | Script + log of counts dropped/fixed; original files untouched. |
| 2.3 | Reproducible split: seeded shuffle; **group by article** where `source_url` exists (362 tasks) and by text hash otherwise. Replace `alignment_mode="contract"` silent absorption with logged counts. | M | Two runs produce identical `train.spacy`/`dev.spacy` hashes. |
| 2.4 | Retrain into a **new** model dir (e.g. `models/model-v6`) with a model card: dataset file, spaCy version, date, seed, dev scores per label, known weaknesses. Document the training command (currently inferred, not in repo). | M | `meta.json` has a real name/version; model card committed. |
| 2.5 | Add `Registry_Key` examples (target ≥ 50) and decide on `Threat_Actor`. Extending the label set is a **contract change** once published; announce it. ⚠ | L | Registry-key F1 measured on held-out set. |
| 2.6 | Compare old vs new model on the *same* leakage-free dev set. | S | Honest delta recorded; expect the old 0.847 to drop. |

### Phase 3 — Tests and CI

| ID | Task | Size | Done when |
|---|---|---|---|
| 3.1 | Offline spider tests against saved HTML fixtures (one per vendor). | M | `pytest` passes with no network. |
| 3.2 | Unit tests for sanitisers: `normalize_defanged`, `sanitize_and_validate_ip`, `clean_and_validate_domain`, `sanitize_process_name` (table-driven from real false positives seen in output). | M | Cases include private IPs, citation domains, file-extension "domains", defanged input. |
| 3.3 | **Contract tests** from the coordination doc golden samples: P1 report line, P3 Label Studio task, model label set equals `{Command_Line, Domain_URL, File_Path, IP_Address, Process_Name}`. | S | Failing a label rename breaks CI. |
| 3.4 | Rule-output tests: generated XML is well-formed, wrapped in `<group>`, IDs inside the AMP range, no duplicate IDs, regex compiles under PCRE2 (e.g. via `pcre2`/`regex` library as a proxy). | M | Tests pass. |
| 3.5 | CI (GitHub Actions): ruff, pytest, pip-audit on every push. Model-dependent tests marked/skipped when weights are absent. | M | Green badge from a clean checkout. |

### Phase 4 — Rule compiler v2 and real validation

| ID | Task | Size | Done when |
|---|---|---|---|
| 4.1 | **Per-article rule files** instead of one aggregate: `<group name="cti_<source>_<article-slug>">` with source URL, extraction date, and model version in a comment/metadata; one rule per indicator class per article. | L | Every rule traces to an article; a single article can be removed cleanly. |
| 4.2 | **ID allocation** within the AMP range (D7): deterministic IDs from a persisted registry (not hash-modulo, so collisions are impossible). | M | No collisions across runs; registry file is versioned. |
| 4.3 | **Indicator lifecycle:** first-seen/last-seen, optional expiry (IOCs go stale; IPs get reassigned). ⚠ Owner chooses TTL policy. | M | Expired indicators drop out on the next compile. |
| 4.4 | Extend indicator hygiene: CDN/shared-hosting and sinkhole domains, well-known cloud IP ranges, dedup against allow-lists; keep the existing LOLBin exclusions. | M | Test list of known-benign indicators produces no rules. |
| 4.5 | Rules for `File_Path` and `Command_Line` labels. **PROPOSED:** only after 4.6 exists, because path/command-line regexes are the highest false-positive risk and the Command_Line model F1 is 0.53. | L | Gated on measured FPR. |
| 4.6 | **Testbed + validation gate (PROPOSED):** a Wazuh manager + Windows agent with Sysmon (VM or container). Load generated rules; run `wazuh-logtest` with (a) synthetic malicious events built from each rule's indicators and (b) a benign Sysmon baseline; compute FPR; classify each rule file `staged` / `held_for_review`. Nothing auto-deploys. | L | Rules demonstrably fire on positive events and stay silent on the baseline; results stored per rule file. |
| 4.7 | Confirm gating assumptions on a real manager: `<if_group>sysmon_event1/3</if_group>`, field names `win.eventdata.image/destinationIp/destinationHostname`, `pcre2` field type, and the `<group>` wrapper (N3). | M | A written note of what loaded cleanly vs what had to change. |
| 4.8 | Review queue: a simple CLI/report listing staged and held rule files with their source article and indicators. | M | Reviewer can approve/reject per file. |
| 4.9 | Broaden ATT&CK tagging beyond the 7 hard-coded tools (**do not guess**; unmapped stays untagged or uses a generic technique, as today). Defer to Lacuna's mapper if integration (Phase 5) is approved. | M | Documented policy; no fabricated IDs. |

### Phase 5 — Lacuna integration *(blocked on owner decisions; all PROPOSED)*

Order follows `ProjectCoordination.md` §7. Each item is a contract change processed via the §6 procedure of that document, and the **other repo is never edited from here**.

| Contract | Work on the AMP side | Needs |
|---|---|---|
| **C3** labelled data → Lacuna eval set | Freeze the canonical dataset (2.1) and publish it with a data card; the converter itself lives in Lacuna. | D2 |
| **C2** spaCy model → Lacuna Stage 1 | Publish the model directory + card + label set stability promise; decide the distribution channel (releases vs git). | D3, D4, D6 |
| **C1** reports → Lacuna Stage 0 | Guarantee a stable on-disk report format (after 1.6, true JSONL with `source_url`). Fill the empty-title gap (A6) so articles are identifiable. | 1.6, A6 fix |
| **C5** one manager, two rule families | Adopt the ID ranges; run both rule sets on the Phase 4.6 testbed. | D7, 4.6 |
| **C4** IOC rules in Lacuna? | Nothing until decided. | D1 ⚠ |

### Phase 6 — Operations

| ID | Task | Size |
|---|---|---|
| 6.1 | Scheduler (cron / systemd timer / GitHub Actions) for the sync, with retries and a lock so runs don't overlap. | M |
| 6.2 | Structured logging and a per-run summary (articles found, scraped, entities per label, rules produced, rules staged/held). | M |
| 6.3 | Failure alerting (scrape failed, model failed to load, FreshRSS auth failed). | S |
| 6.4 | Packaging: one-command entry point (`python -m amp run`), documented in README, replacing the interactive-demo naming (`run_interactive_demo`). | M |
| 6.5 | README rewrite: setup, run commands (with working directory removed as a concern), architecture, data/model provenance, how to review and deploy rules. | M |

---

## 6. Decisions the owner must make ⚠

Agents should not resolve these. **Recommended default** is a suggestion only.

| ID | Decision | Recommended default |
|---|---|---|
| D1 | Do indicator (IOC) rules belong inside Lacuna's technique pipeline, or do the two rule families stay separate? | Stay separate until Phase 4 is done and measured. |
| D2 | Which dataset file is canonical? `v5_fixed_relabelled_master_dataset.json` looks newest by name, but the repo does not say. | Confirm, freeze it as baseline, and derive a new de-duplicated `v6`. |
| D3 | NER confidence: fixed `1.0` ("unscored") vs beam-scored? | Fixed `1.0`, documented. Only matters for Lacuna integration. |
| D4 | `Threat_Actor` label: drop or add to a schema? | Drop from rules; keep in the dataset; never map to `malware_name`. |
| D5 | Hosted FreshRSS on Render: keep, replace, or self-host? | Keep for now; move credentials to env; revisit when Phase 6 starts. |
| D6 | Where do model weights ship from (currently ~13 MB of two near-duplicate model dirs inside git)? | GitHub Releases or LFS for **new** versions; leave existing files untouched. |
| D7 | Rule-ID policy: AMP range 100000–109999, Lacuna 110000–118999 (Wazuh reserves 100000–120000 for custom rules, per Wazuh docs — confirm for your version). | Adopt; use a persisted ID registry. |
| D8 | robots.txt / User-Agent policy for CISA (and others). | Obey robots.txt unless there is a documented reason not to; use an honest User-Agent with a contact URL. |
| D9 | IOC lifecycle: expiry/TTL and who approves deployment. | Human approval required; default TTL to be chosen by the owner. |
| D10 | Target Wazuh version, Sysmon config, and event IDs in scope. | Pin the Wazuh version used on the testbed and record it here. |

---

## 7. Immediate next actions (in order)

1. **Rotate the FreshRSS password** (0.1, owner).
2. Env-var the credentials and add `requirements.txt` (0.2, 0.3).
3. Fix the confirmed bugs A2, A3, A5, A8 with tests (1.1–1.4).
4. Add the tolerant-but-loud report loader and rerun the compiler on all 5,429 records (1.6). Expect many more indicators than the committed `demo_rules.xml` has, which makes 4.4 and 4.6 more urgent.
5. Answer D2 so the dataset/model work (Phase 2) can start.
6. Stand up the Wazuh testbed early (4.6/4.7): it is the only way to know the rule output is valid, and it de-risks everything downstream.

---

## 8. Risks and caveats

| Risk | Mitigation |
|---|---|
| Reported F1 (0.847) is inflated by duplicate leakage and a non-article split. | Re-evaluate on a clean split (2.3, 2.6) before quoting any number. |
| Scale-up of N1 fix will surface many more IOCs, including shared infrastructure and benign domains, raising FP risk. | 4.4 hygiene + 4.6 gate + human review; no auto-deploy. |
| IOC rules go stale quickly. | Lifecycle/expiry (4.3). |
| Small model, small data, `Command_Line` F1 0.53. | Keep `Command_Line`/`File_Path` out of rules until validated (4.5). |
| Wazuh rule syntax/gating never tested live (N3, 4.7). | Testbed early. |
| Scraping legality/etiquette (N10). | D8. |
| Two repos with overlapping goals can drift. | Contract tests (3.3), shared ID ranges (D7), copy the coordination doc into both repos. |
| Evidence base: this plan rests on static inspection. | Re-baseline by actually running each piece once (Phase 0.3 gives the environment to do it) and correct this file. |

---

## 9. Quality checklist before closing any change

- [ ] Ran what was changed (state what was *not* run).
- [ ] No secrets, no new bulk data, no overwritten dataset/model versions.
- [ ] Published surface (report keys, labels, export shape, model layout, spaCy range) unchanged, or a contract note written.
- [ ] Tests added/updated; golden-sample contract tests green.
- [ ] This file updated (status boxes + §12).
- [ ] Handoff note written (§11).

---

## 10. Reference

### Run commands (currently; working directory matters until 0.5 lands)

| Task | Run from | Command |
|---|---|---|
| Whole flow | `data_ingestion/` | `python freshrss_sync.py` |
| One spider | `data_ingestion/` | `scrapy crawl cisa_tactical` (also `dfir`, `redcanary`, `unit42`); single article: `-a target_url=<url>` |
| Compile rules | any | `python rule_generation/demo.py` |
| Training data | `NLP/` | `python convert_to_spacy.py datasets/<export>.json` |
| Train (inferred, not documented in repo) | `NLP/` | `python -m spacy train config.cfg --paths.train train.spacy --paths.dev dev.spacy --output models` |
| Pre-annotate | `NLP/` | `python active_learning.py <input.jsonl> <out.json>` |

### Key facts

- **Model labels:** `Command_Line`, `Domain_URL`, `File_Path`, `IP_Address`, `Process_Name` (`Registry_Key`, `Threat_Actor` appear in metrics but are not in the label set).
- **Dev F1 (from `meta.json`):** overall 0.847 · Process_Name 0.945 · Domain_URL 0.960 · IP_Address 0.900 · File_Path 0.687 · Command_Line 0.529.
- **v5-fixed dataset:** 1,553 tasks · 1,295 unique texts · 871 annotations (Process 433, File 220, Command 107, Domain 69, IP 40, Registry 1, Threat_Actor 1) · 1,013 tasks with no entities · 362 with `source_url`.
- **Report records:** cisa_tactical 1,469 · raw_cisa 302 · raw_dfir 1,293 · raw_redcanary 781 · raw_unit42 1,584.
- **Rules `demo.py` emits:** 100005 (IPs, level 12) · 100004 (domains, level 12) · 100010+ (7 offensive tools, level 8–12) · 100002 (other processes, level 10).
- **Tracked defects (docs numbering):** A1 secrets · A2 Red Canary NameError · A3 missing comma · A4 legacy generator broken · A5 Unit 42 target_url · A6 empty CISA titles · A7 three seen-URL DBs · A8 import-time model load · A9 robots/UA. New in this file: N1–N10.

---

## 11. Handoff note template

```
## Session <date>
Changed:            <files / behaviour>
Ran (result):       <commands and outcomes>
Could not run:      <what and why>
Contracts touched:  <P1/P2/P3/C1–C5 or none>
CROSS-REPO IMPACT:  <block from ProjectCoordination.md §6, or "none">
Decisions needed:   <D-IDs>
Next agent first:   <one concrete step>
```

**Stop and ask the owner before:** resolving any ⚠ decision; renaming/adding labels; deleting or overwriting datasets or models; committing weights or bulk data; changing rule-ID ranges; rotating/removing credentials; adding a default runtime dependency; touching Lacuna.

---

## 12. Change log

| Date | Change | By |
|---|---|---|
| 2026-11-24 | Initial plan from static review of the AMP repo and the two coordination documents. Nothing executed. | Claude |
