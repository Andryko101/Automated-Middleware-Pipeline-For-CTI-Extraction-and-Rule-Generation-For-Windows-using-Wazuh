# Project Coordination — Working Independently in AMP and Lacuna

**Repositories**

| Short name | Repository | Language | Role |
|---|---|---|---|
| **AMP** | `Automated-Middleware-Pipeline-For-CTI-Extraction-and-Rule-Generation-For-Windows-using-Wazuh` | Python | Live CTI ingestion, labelled NER data, trained spaCy model, IOC-style rule compiler |
| **Lacuna** | `lacuna_project` | Python (Stages 0–2) + Rust (Stages 3–4) | Staged CTI → ATT&CK → Sigma → Wazuh pipeline with a validation gate |

**Read `Project overview.md` first** for what each repo is and what exists today.

## 0. How to use this document

An agent working in **one** repo will not be able to see the other. This file is therefore the shared memory. It is meant to be **copied verbatim into both repos** (suggested path: `docs/ProjectCoordination.md` in each). It contains everything needed to stay compatible without opening the other repo: field-level contract specs, golden samples, ownership, and a change procedure.

Every rule below carries one of three labels. Do not treat them alike.

| Label | Meaning |
|---|---|
| **EXISTING** | Enforced by code or docs in the repo today. Breaking it breaks something real. |
| **PROPOSED** | A recommended seam that is **not built**. Needs owner approval before anyone builds it. Safe to prepare for, not to assume. |
| **DECISION PENDING** | An open question for the owner. Do not resolve it unilaterally. |

**Current coupling: none.** No code, file format, schema or dependency is shared between the repos today. Anything below labelled PROPOSED describes how that could change.

---

## 1. Golden rules (apply in both repos)

1. **Stay in your repo.** Never edit, vendor, copy source from, or import code from the other repo. The only allowed interfaces are files in documented formats (§3).
2. **Contracts change doc-first.** Update the contract spec (§3 and the repo's own schema doc) *before* the code, and record the change using §6.
3. **Producers are strict, consumers are loud.** A consumer that meets unexpected input fails with a clear error naming the line/field. It never silently defaults, coerces or skips. (This is Lacuna's core convention: "loud failures over silent wrong answers".)
4. **Never fabricate over a gap.** If a technique ID, confidence, entity type or rule logic is unavailable, leave it null, drop it, or emit an explicit placeholder. Do not guess.
5. **No secrets in git.** Use environment variables. AMP currently violates this (overview finding A1); fixing it is the highest-priority safe change there.
6. **Verify before you claim.** Do not write "implemented" or "works" for anything you did not run. State what you ran and what you could not.
7. **No bulk data in git without owner approval.** Lacuna gitignores generated data and model artifacts. AMP already holds ~35 MB of datasets and models; do not add more casually.
8. **Never delete or rewrite existing dataset or model versions in place.** Add a new versioned file or directory.
9. **Leave a handoff note** (§8) for the next agent, including cross-repo impact even when it is "none".
10. **Escalate rather than improvise** on anything in §8's stop list.

---

## 2. Ownership map

| Asset | Owner | The other repo may |
|---|---|---|
| Scraped report files (`data_ingestion/reports/*.jsonl`) and their line format | AMP | read |
| spaCy pipeline `NLP/models/model-*` and its label set | AMP | load; never modify |
| Label Studio exports `NLP/datasets/*.json` | AMP | read (via a converter on the Lacuna side) |
| AMP rule compiler (`rule_generation/`) | AMP | nothing |
| The 5 record schemas (`docs/data-schema.md`, `pipeline/schemas/`, Rust mirrors) | Lacuna | nothing; AMP must not emit or depend on them |
| `EntityExtractor` protocol, `SourceConnector`/`RawIntelItem`, labelled-data JSONL format | Lacuna | nothing |
| Python→Rust handoff JSONL, staging file names, template library, the 6 fallback primitives | Lacuna | nothing |
| Lacuna ADRs (`docs/decisions.md`) | Lacuna | nothing (they are binding there, not here) |
| Wazuh rule-ID ranges | Shared | **PROPOSED:** AMP 100000–109999, Lacuna 110000–118999 (§3.6) |

---

## 3. Contract registry

| ID | Status | Producer → Consumer | What | Source of truth |
|---|---|---|---|---|
| **L1** | EXISTING | Lacuna Python → Lacuna Rust | `MappedTechniqueRecord` as JSONL | `docs/data-schema.md`, `pipeline/schemas/mapped_technique.py`, `middleware/src/sigma_gen.rs` |
| **L2** | EXISTING | Lacuna Rust → disk/review CLI | `<record_id>.rule_bundle.json`, `<record_id>.validation_report.json` | `handoff.rs`, `validation.rs` |
| **P1** | EXISTING, undocumented in AMP | AMP spiders → AMP rule compiler (and any reader) | Report line `{title, source_url, text}` | `cti_scraper/items.py`, spiders |
| **P2** | EXISTING, undocumented in AMP | AMP training → AMP compiler (and any loader) | spaCy pipeline dir and label set | `NLP/models/model-best/meta.json` |
| **P3** | EXISTING, undocumented in AMP | Label Studio → AMP training (and any converter) | Export JSON schema | `NLP/convert_to_spacy.py` |
| **C1** | PROPOSED | AMP reports → Lacuna Stage 0 | Article feed | §3.3 |
| **C2** | PROPOSED | AMP spaCy model → Lacuna Stage 1 | NER extractor | §3.4 |
| **C3** | PROPOSED | AMP labelled data → Lacuna Stage 1 evaluation | Dataset conversion | §3.5 |
| **C4** | DECISION PENDING | AMP-style IOC rules ↔ Lacuna | Whether indicator rules enter Lacuna | §3.7 |
| **C5** | PROPOSED | Both → one Wazuh manager | Rule-ID ranges and gating conventions | §3.6 |

ID legend: **L** = internal to Lacuna, **P** = published by AMP, **C** = cross-repo seam. Findings labelled A1–A9 in `Project overview.md` are AMP *defects*, a separate numbering.

Golden samples for every format are in Appendix A. Build fixtures from them so both repos test against identical shapes.

### 3.1 L1 — `MappedTechniqueRecord` JSONL (EXISTING, internal to Lacuna)

One JSON object per line, UTF-8. Fields:

| Field | Type | Rules |
|---|---|---|
| `record_id` | UUID string | Matches the upstream `CandidateIntelRecord.record_id` |
| `mapping_confidence` | float, 0.0–1.0 | |
| `technique_id` | string or `null` | **`null` if and only if `fallback_used` is `true`** (ADR-0005) |
| `technique_name` | string or `null` | Set if and only if `technique_id` is set |
| `fallback_used` | bool | |
| `behavioral_primitives` | list of strings | Must be non-empty when `fallback_used` is `true` |
| `mapping_model_version` | string | |

The six primitive strings are matched **character for character** in Rust (Appendix B). Nothing enforces this at compile time. Never edit one side without the other. A malformed line is reported and skipped by Rust; it does not abort the batch.

**Known gap:** no Python code writes this file yet. The Phase 6 agent must add a writer and a golden-file test (§7, step 0).

### 3.2 L2 — staging outputs (EXISTING)

`<record_id>.rule_bundle.json` (`record_id`, `sigma_rule_yaml`, `wazuh_rule_xml`, `generation_timestamp`, `status: "staged"`) and `<record_id>.validation_report.json` (`record_id`, `baseline_window_days`, `false_positive_rate`, `syntax_valid`, `replay_duration_ms`, `decision` ∈ `promoted | held_for_review`, `validated_at`). The promotion threshold `0.02` lives in **two** places that must change together: `pipeline/schemas/validation_report.py::FPR_PROMOTION_THRESHOLD` and `middleware/src/validation.rs::FPR_PROMOTION_THRESHOLD`.

### 3.3 C1 — AMP reports → Lacuna Stage 0 (PROPOSED)

**What AMP publishes (P1).** JSONL files; **one text block per line**, not one article per line:

```
{"title": "<str, may be empty>", "source_url": "<str>", "text": "<str>"}
```

Constraints to rely on: UTF-8; `text` is a single paragraph/list item/code block that already passed a Windows-keyword filter; `title` can be empty (all 565 records in the committed CISA JSON are); the same `source_url` repeats across many lines.

**What Lacuna consumes.** `RawIntelItem(source, source_url, raw_text, cve_id=None)` via a class implementing `SourceConnector.fetch() -> Iterator[RawIntelItem]`. Follow the pattern of `LocalSampleReportsConnector` in `pipeline/triage/ingest.py`.

**Mapping rules:**

| Lacuna field | Rule |
|---|---|
| `source_url` | the line's `source_url`. Lines without one are skipped with a loud log, never given a made-up URL |
| `raw_text` | **all lines sharing a `source_url`, joined with `\n` in file order → one `RawIntelItem` per article.** Do not emit one item per line (see below) |
| `source` | `"vendor_blog"` for all four AMP sources. `SourceType` has no advisory value; adding one is a schema change (§6) |
| `cve_id` | leave `None`; Stage 0's own extraction handles it |

**Why group by article:** Stage 0's English check needs at least 5 words and a stop-word ratio, its dedup is per document, and its relevance and CVE logic are document-level. Individual short blocks (command lines, paths) would be dropped or mis-scored.

**Caveat to carry into any results write-up:** AMP removed non-Windows blocks before Lacuna sees them, so the text is a concatenation of selected paragraphs, not the original article.

**Interface:** files on disk only. The connector takes a directory path parameter (not hard-coded) because AMP's scrape output location is itself inconsistent (overview §3.1). It must be read-only, and must never open AMP's `seen_urls.db`.

### 3.4 C2 — AMP spaCy model → Lacuna Stage 1 (PROPOSED)

**What AMP publishes (P2).** A spaCy 3.8.x pipeline directory (`tok2vec` + `ner`) with labels `Command_Line`, `Domain_URL`, `File_Path`, `IP_Address`, `Process_Name`. `meta.json` requires `spacy >=3.8.16,<3.9.0`. `Registry_Key` and `Threat_Actor` appear in its metrics but are **not** in its label set; treat both as unsupported.

**What Lacuna consumes.** A class satisfying its `EntityExtractor` protocol: a `model_version: str` attribute and `extract_entities(self, text: str) -> list[ExtractedEntity]`. It plugs into `extract_behavior_record(record, extractor)` and `extraction/evaluate.py` with no other change.

**Label mapping (all other labels are an error, not a default):**

| AMP label | Lacuna `EntityType` | Note |
|---|---|---|
| `Process_Name` | `process` | |
| `File_Path` | `file_path` | |
| `Command_Line` | `command_line_arg` | **Semantic mismatch.** AMP spans are often whole command lines (some are single cmdlets); Lacuna's baseline extracts slash-flag fragments. Evaluate this type separately. |
| `IP_Address` | `ioc` | |
| `Domain_URL` | `ioc` | |
| `Registry_Key` | `registry_path` | The model cannot predict this yet (1 training example). Keep the regex extractor for registry paths. |
| `Threat_Actor` | *(none)* | Drop it. **Never map to `malware_name`** — different concept. Needs a schema decision (§3.7). |

Lacuna types with no AMP source (`malware_name`, hash-type `ioc`) stay with `RuleBasedExtractor`. Expect a composite extractor that merges both outputs and resolves overlaps (the existing `_resolve_overlaps` logic is the model to follow).

**Mechanics that must hold:**

- Run the model on `record.cleaned_text`, because `extract_behavior_record` extracts from that string and Lacuna validates `text[span_start:span_end] == entity.text`. Use `ent.start_char` and `ent.end_char`.
- Do **not** normalise defanged IOCs (`[.]`, `hxxp`) inside the extractor; that would break the span check. Normalise downstream if ever needed.
- `ExtractedEntity.confidence` is required (0.0–1.0), but default spaCy NER gives no score. Proposed convention: `1.0`, documented as "unscored". **DECISION PENDING** (overview §5, decision 3).
- `model_version` should identify the source, for example `spacy:<dataset or model tag>`. Today AMP records no dataset-to-model link; ask the owner for a model tag.
- Import spaCy lazily, as `TransformerNERExtractor` does with `transformers`, so default installs and CI do not need it. Add it as an optional dependency group. Expect `pip-audit` to scan it; follow Lacuna's convention of reading each advisory before ignoring anything.
- The model files are large and Lacuna gitignores `pipeline/extraction/model/` ("track via releases, not git"). Take the model path from configuration (for example an environment variable); never commit weights.

### 3.5 C3 — AMP labelled data → Lacuna evaluation set (PROPOSED)

**What AMP publishes (P3).** A Label Studio export: a JSON list of tasks. Relevant paths: `task.data.text`; `task.annotations[0].result[]` where `type == "labels"`, each with `value: {start, end, text, labels: [<label>]}`. `start`/`end` are character offsets into `data.text`.

**What Lacuna consumes.** `data/labeled/*.jsonl`, one example per line, loaded by `load_labeled_examples`, which fails loudly if `text[span_start:span_end]` differs from the entity text:

```
{"text": "...", "entities": [{"text": "...", "type": "process", "span_start": 22, "span_end": 36}]}
```

**Conversion rules (a Lacuna-side script, with tests):**

1. Take the dataset path as an argument. The data stays in AMP and is not vendored into Lacuna.
2. Skip tasks with no `annotations`. Keep annotated tasks with zero results as valid negatives (about 65% of v5 are negatives).
3. **De-duplicate identical texts first** (258 of 1,553 in v5).
4. Apply the §3.4 label mapping. Drop `Threat_Actor` (1 example).
5. Fix whitespace-padded spans (12 in v5) by tightening offsets. A span whose text still does not match must fail the conversion loudly (2 in v5 do not match).
6. Split with Lacuna's seeded `train_test_split`, never with AMP's unseeded shuffle.
7. Record in the handover which dataset file was used. By name `v5_fixed_relabelled_master_dataset.json` looks newest, but this is **DECISION PENDING** (overview §5, decision 2).

**What it unlocks:** Lacuna's outstanding Phase 2 items (a labelled set far beyond 10 examples, and a real held-out F1 for `SpacyNERExtractor` versus `RuleBasedExtractor` through the same harness). Report the caveats from the overview (duplicates, short blocks, `Command_Line` shape) next to any number produced.

### 3.6 C5 — Wazuh rule IDs and gating (PROPOSED)

| | AMP | Lacuna |
|---|---|---|
| ID scheme | Fixed IDs (100002, 100004, 100005) plus counters from 100010 / 100001 | `110000 + hash(sigma_uuid) % 9000` → 110000–118999 |
| Gating | `<if_group>sysmon_event1</if_group>` / `sysmon_event3` | `win.system.eventID` field match; deliberately no `if_group` |
| Field names | `win.eventdata.image`, `destinationIp`, `destinationHostname` | `win.eventdata.*` plus `win.system.eventID` |

Proposed reservation: **AMP 100000–109999, Lacuna 110000–118999**, nothing else touched. Lacuna's hash can collide within its 9,000 slots; detecting collisions is a Lacuna-side task. Neither repo has loaded its rules into a real Wazuh manager, so neither gating convention is confirmed. Do not assume the other repo's rules will coexist with yours until someone tests both on one manager.

### 3.7 C4 — IOC rules (DECISION PENDING)

Lacuna's design deliberately drops entities after Stage 2: `MappedTechniqueRecord` carries only technique ID, name and primitives, and Stage 3 emits technique-level templates. AMP's rules match specific IPs, domains and process names. They are different rule families. **Neither agent should add IOC fields to Lacuna's contracts, or port AMP's compiler into Rust, until the owner decides.** If the owner approves, that is a schema change processed through §6, with the Python and Rust mirrors and `docs/data-schema.md` updated in one change.

---

## 4. Working in AMP on your own

### 4.1 Read order

`README.md` → `data_ingestion/freshrss_sync.py` → `cti_scraper/settings.py`, `pipelines.py`, one spider → `rule_generation/demo.py` → `NLP/convert_to_spacy.py` → `NLP/models/model-best/meta.json`.

### 4.2 Setup

Python 3.10+ per the README. **There is no dependency manifest.** Packages inferred from imports: `scrapy`, `twisted`, `itemadapter`, `spacy` (>=3.8.16,<3.9.0 per model metadata), `google_reader`, `tldextract`, `requests`. Creating a pinned `requirements.txt` from a working environment is a safe first task.

### 4.3 How to run each piece (the working directory matters)

| Task | Run from | Command | Notes |
|---|---|---|---|
| Whole flow | `data_ingestion/` | `python freshrss_sync.py` | Needs network and FreshRSS access. Writes `output_data/<spider>.jsonl` and `seen_urls.db` **relative to the cwd**, then runs the compiler |
| One spider | `data_ingestion/` | `scrapy crawl cisa_tactical` (or `dfir`, `redcanary`, `unit42`) | Single article: add `-a target_url=<url>`. `unit42` ignores it (overview finding A5); `redcanary` errors at the end (overview finding A2) |
| Compile rules only | any | `python rule_generation/demo.py` | Paths are file-relative. Reads `data_ingestion/reports/*.jsonl`, writes `rule_generation/demo_rules.xml` |
| Make training data | `NLP/` | `python convert_to_spacy.py datasets/<export>.json` | Writes `train.spacy`, `dev.spacy` to the cwd. Split is unseeded |
| Train | `NLP/` | `python -m spacy train config.cfg --paths.train train.spacy --paths.dev dev.spacy --output models` | **Inferred**: the repo does not document the training command |
| Pre-annotate | `NLP/` | `python active_learning.py <input.jsonl> <out.json>` | Model path defaults to `models/model-best`, relative |

### 4.4 AMP's published surface — keep stable

Other repos may rely on exactly these. Changing any is a contract change (§6):

1. Report line keys `title`, `source_url`, `text` (P1).
2. Label names in the model's label set (P2).
3. The Label Studio export shape (P3).
4. The location and layout of a model directory that downstream code loads.
5. The spaCy minor version a published model needs.

### 4.5 Safe to do independently (no contract impact)

- Fix defects A2–A8 listed in the overview's findings table; move credentials to environment variables; add tests, CI and a dependency manifest.
- Make `seen_urls.db` and the output paths independent of the working directory; make the scrape output land where the compiler reads.
- Add **new** de-duplicated, article-aware, seeded dataset versions and retrain into a **new** model directory, with a short model card recording dataset file, spaCy version, date and dev scores.
- Add `Registry_Key` training examples (extending the label set is a contract change once published; announce it).

### 4.6 Needs a contract note first

Renaming or removing a label; changing report line keys; changing the Label Studio project schema; moving or restructuring model directories; changing the spaCy major/minor version; changing the document-per-line granularity of reports.

### 4.7 Before you finish an AMP change

- [ ] Ran what you changed (or said plainly that you could not).
- [ ] No secrets, no new large files, no deleted or overwritten dataset or model versions.
- [ ] Published surface (§4.4) unchanged, or a §6 note written.
- [ ] A golden sample line for P1 and a label-set check exist in tests (§7, contract tests).
- [ ] Handoff note written (§8).

---

## 5. Working in Lacuna on your own

### 5.1 Mandatory read order

From the repo's own `session.md`: the owner expects these read **before touching code**, every session: `docs/Architecture.md` (especially §7 interface contracts and §8 targets) → `docs/decisions.md` (ADRs are binding) → `docs/data-schema.md` → `docs/projectStructure.md` → `docs/evaluation-plan.md` → `docs/todo.md` → `handover.md` → `session.md`.

### 5.2 Environment

Python 3.11 with Poetry (CI pins Poetry 1.8.3); a current stable Rust toolchain for `middleware/`; a reachable ClickHouse for the Rust demo and handoff modes (`LACUNA_CLICKHOUSE_URL`, default `http://127.0.0.1:8123`) with a populated baseline (`cargo run --example generate_baseline`). Set `ANONYMIZED_TELEMETRY=False` to quiet ChromaDB. The sandbox quirks in `session.md` (old Rust 1.75, pinned transitive crates, blocked HuggingFace and wazuh.com, daemons not persisting between tool calls) describe the previous agent's sandbox, not your machine. Re-check them before assuming they apply.

### 5.3 Quality gate (what CI runs)

```
cd pipeline   && poetry install --with dev
cd pipeline   && poetry run ruff check . && poetry run ruff format --check .
cd pipeline   && poetry run mypy .                 # strict
cd pipeline   && poetry run pytest -q
cd middleware && cargo fmt --all -- --check
cd middleware && cargo clippy --all-targets --all-features -- -D warnings
cd middleware && cargo build && cargo test
cd middleware && cargo audit
```

Per `handover.md`: 126 Python and 40 Rust tests passed at the last checkpoint; the Rust fmt/clippy/audit steps were never run locally by the previous agent, so expect first-run findings. Re-establish the baseline before changing anything.

### 5.4 Lockstep pairs — change both sides in the same change

| Python / docs side | Other side |
|---|---|
| `pipeline/schemas/mapped_technique.py` | `MappedTechniqueRecord` in `middleware/src/sigma_gen.rs` |
| `pipeline/schemas/validation_report.py` `FPR_PROMOTION_THRESHOLD` | `middleware/src/validation.rs` `FPR_PROMOTION_THRESHOLD` |
| `pipeline/mapping/map_technique.py` `_PRIMITIVE_BY_ENTITY_TYPE` values | `primitive_template()` match arms in `sigma_gen.rs` (and the Rust test that enumerates them) |
| `docs/data-schema.md` | `pipeline/schemas/` and the Rust structs |
| `docs/projectStructure.md` | the actual file tree |
| `handover.md` | each phase's real status |

### 5.5 Binding rules

- ADR-0001: Rust only in `middleware/`, no Node.js. ADR-0002: Sigma first, Wazuh XML is only a translation. ADR-0003: Stage 0 exists. ADR-0004: stay middleware, never build an EDR. ADR-0005: below the confidence threshold emit the fallback, never a technique ID.
- `data-schema.md` is frozen after Phase 0. A needed field goes into the doc first, then Python and Rust, in one change.
- Stage 3 never sets `status` to anything but `"staged"`. Only the Stage 4 gate can promote.
- An empty baseline is a loud error, never a `0.0` false-positive rate. An uncurated technique yields the inert placeholder rule, never a guess.
- Do not write "implemented" in `handover.md` for anything you did not run.
- Checkpoint cadence (from `session.md`): at a phase boundary run the full gate, add a phase section to `handover.md`, update `projectStructure.md` if the tree changed, clean build artefacts, and package.

### 5.6 Lacuna's published surface — keep stable

`EntityExtractor` (`model_version: str`; `extract_entities(text) -> list[ExtractedEntity]`), `RawIntelItem` and `SourceConnector.fetch()`, the labelled-data JSONL format, the five record schemas, the handoff JSONL (L1), the staging file names (L2), and the six primitive strings.

### 5.7 Where the PROPOSED integrations would land

Place them under the existing structure and update `projectStructure.md` in the same change. Suggested, not mandated:

| Contract | Suggested location |
|---|---|
| C1 article connector | `pipeline/triage/` (new module beside `ingest.py`) + a fixture in `data/sample_reports/` |
| C2 `SpacyNERExtractor` + composite | `pipeline/extraction/` (new module beside `extract.py`) |
| C3 converter | `pipeline/extraction/` (script with tests); output to `data/labeled/` |
| Python JSONL writer for L1 | to be chosen by the Phase 6 driver work; document it |

### 5.8 Gotchas

- `TfidfEmbeddingFunction` is interim. `CONFIDENCE_THRESHOLD = 0.45` is calibrated to it. After any embedding swap, re-calibrate from scratch; do not reuse 0.45.
- T1110 (password spray) and every technique outside the 10 curated ones produce the inert placeholder rule. That is correct behaviour, not a bug.
- The validation baseline is synthetic and the replay is a stand-in for `wazuh-logtest`. Do not describe results as real-telemetry validation.
- The archive contains a stale `Cargo.lock` although `.gitignore` lists it and `handover.md` says it is not committed. Do not hand-edit it; ask which way the owner wants it.
- Adding dependencies means re-running `pip-audit` and `cargo audit` and reading each finding before ignoring it.

### 5.9 Before you finish a Lacuna change

- [ ] Quality gate (§5.3) run, results stated honestly.
- [ ] Lockstep pairs (§5.4) updated together; `projectStructure.md` and `handover.md` updated.
- [ ] No contract changed without §6; no ADR violated.
- [ ] Any PROPOSED integration still marked as such unless the owner approved it.
- [ ] Handoff note written (§8).

---

## 6. Changing a contract

1. State which contract ID (§3) changes and why. If it is a DECISION PENDING item, stop and ask the owner.
2. Edit the contract text **first**: §3 here, plus the repo's own schema doc (`docs/data-schema.md` in Lacuna).
3. Edit the producer, consumer and tests in the **same change**.
4. If the change affects the *other* repo, do not touch it. Add this block to your handoff note:

```
CROSS-REPO IMPACT
Contract: <ID>            Status change: <e.g. PROPOSED → EXISTING>
What changed: <field / label / path / format>
Old → new: <exact before and after>
Other repo must: <exact steps>
Backward compatible: yes / no
Owner must sync this document into the other repo: yes
```

5. The owner copies the updated `ProjectCoordination.md` into **both** repos. Until both copies match, assume the stricter reading of each rule.

---

## 7. Suggested integration order (each step stands alone)

| Step | Where | Work | Done when |
|---|---|---|---|
| 0 | AMP | Fix overview findings A1–A8, add manifest, tests, CI | AMP runs from a clean checkout; no secrets in git |
| 0 | Lacuna | Phase 6 driver; **Python writer for L1** plus a golden JSONL file that a Rust test parses | Raw text → staged `RuleBundle` + `ValidationReport` through real code |
| 1 | Owner | Resolve overview §5 decisions 2, 3, 4, 5 | Written in both repos' handoff notes |
| 2 | Lacuna (+ AMP freezes dataset) | C3 converter | Converted JSONL loads under `load_labeled_examples`; counts and drops are logged |
| 3 | Lacuna | C2 `SpacyNERExtractor` and composite; evaluate against `RuleBasedExtractor` on the C3 split | Real held-out P/R/F1 recorded in `evaluation-plan.md` against the ≥ 0.70 target |
| 4 | Lacuna | C1 connector; run AMP's committed reports through Stages 0–2, then the handoff | Records flow end to end; relevance and fallback rates reported |
| 5 | Owner, then both | C4 decision; only if approved, schema change per §6 | Rules for IOCs have an agreed home and contract |

Steps 0 are independent. Steps 2–4 need nothing from AMP beyond files it already has.

---

## 8. Handoff notes and when to stop

Every session ends with a short note (in `handover.md` for Lacuna; a `HANDOFF.md` for AMP) containing: what you changed; what you ran and the results; what you could not run and why; contract IDs touched; the CROSS-REPO IMPACT block if any; what the next agent should do first.

**Stop and ask the owner** before: changing any DECISION PENDING item; adding or renaming an entity type, `SourceType` value or label; touching the frozen record schemas without §6; deleting or overwriting any dataset or model; committing weights or bulk data; changing a Wazuh rule-ID range; rotating or removing credentials; adding a runtime dependency to either repo's default install.

---

## Appendix A — Golden samples

**P1: AMP report line** (one block per line)

```json
{"title": "Example Advisory", "source_url": "https://example.test/advisory-1", "text": "The actor ran schtasks.exe /create /tn Updater /tr C:\\Users\\Public\\upd.exe to persist."}
```

**P3: Label Studio task** (relevant keys only)

```json
{"id": 1, "data": {"text": "The attacker executed powershell.exe with a base64-encoded command to download a payload from a remote server."},
 "annotations": [{"result": [{"from_name": "label", "to_name": "text", "type": "labels",
   "value": {"start": 22, "end": 36, "text": "powershell.exe", "labels": ["Process_Name"]}}]}]}
```

**Lacuna labelled example** (the same sentence after conversion)

```json
{"text": "The attacker executed powershell.exe with a base64-encoded command to download a payload from a remote server.", "entities": [{"text": "powershell.exe", "type": "process", "span_start": 22, "span_end": 36}]}
```

**L1: confident mapping line**

```json
{"record_id": "3f2b8c1e-6d52-4c1a-9a53-0d6c2f4e7b10", "mapping_confidence": 0.62, "technique_id": "T1053.005", "technique_name": "Scheduled Task/Job: Scheduled Task", "fallback_used": false, "behavioral_primitives": [], "mapping_model_version": "chroma-tfidf-v1"}
```

**L1: fallback line**

```json
{"record_id": "9a1d4e77-2b0c-4f3e-8d61-5c7a90e2b3f4", "mapping_confidence": 0.21, "technique_id": null, "technique_name": null, "fallback_used": true, "behavioral_primitives": ["unusual parent-child process spawn"], "mapping_model_version": "chroma-tfidf-v1"}
```

## Appendix B — Exact literals

**The six fallback primitives** (must match character for character in Python and Rust):

1. `unusual parent-child process spawn`
2. `unexpected registry run-key or persistence-key modification`
3. `unsigned binary written to a temp or user-writable directory`
4. `encoded or obfuscated command-line arguments`
5. `presence of a known malicious tool or malware family`
6. `network connection to a known-bad or newly-observed indicator`

(Default when nothing was extracted: `anomalous endpoint behavior with no further characterization available`. Python side only; confirm its Rust handling before relying on it.)

**Lacuna `EntityType`:** `process`, `registry_path`, `file_path`, `command_line_arg`, `malware_name`, `ioc`.
**Lacuna `SourceType`:** `vendor_blog`, `nvd_feed`, `kev_feed`, `forum`, `social_media`.
**Curated techniques (Stage 3 templates):** T1053.005, T1547.001, T1003.001, T1218.011, T1059.001, T1047, T1550.002, T1558.003, T1055, T1105.
**AMP model labels:** `Command_Line`, `Domain_URL`, `File_Path`, `IP_Address`, `Process_Name`.
**AMP spider names:** `cisa_tactical`, `dfir`, `redcanary`, `unit42`.

## Appendix C — Paths and variables

| Item | Value |
|---|---|
| Lacuna ClickHouse URL | env `LACUNA_CLICKHOUSE_URL`, default `http://127.0.0.1:8123`; table `baseline_events` |
| Lacuna staging dir | default `staging/`; `middleware review [dir]` lists held rules |
| Lacuna handoff run | `cargo run -- <input.jsonl> [dir]` |
| Lacuna rule inspector | `cargo run --example inspect_rule -- T1218.011` |
| AMP report directory | `data_ingestion/reports/` |
| AMP Scrapy output (as configured) | `output_data/<spider>.jsonl` relative to cwd |
| AMP model | `NLP/models/model-best` (latest dev checkpoint: `model-last`) |
| FreshRSS credentials | **currently hard-coded in AMP**; move to environment variables (names are the owner's choice) |
