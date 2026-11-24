import hashlib
import json
import os
import random
import sys
from collections import Counter
from datetime import datetime, timezone
import spacy
from spacy.tokens import DocBin
from spacy.util import filter_spans

DEFAULT_SEED = 42


def _sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def convert_label_studio_to_spacy(
    json_file_path,
    train_output="train.spacy",
    dev_output="dev.spacy",
    split_ratio=0.8,
    seed=DEFAULT_SEED,
):
    nlp = spacy.blank("en")

    with open(json_file_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    # Sort deterministically by Label Studio task ID (if available) before seeded shuffle
    data.sort(key=lambda t: t.get("id", 0))
    rng = random.Random(seed)
    rng.shuffle(data)

    split_index = int(len(data) * split_ratio)
    train_data = data[:split_index]
    dev_data = data[split_index:]

    def process_dataset(dataset, output_filename):
        db = DocBin()
        skipped_entities = 0
        valid_entities = 0
        label_counts = Counter()

        for task in dataset:
            text = task.get("data", {}).get("text", "")
            if not text:
                continue

            doc = nlp.make_doc(text)
            ents = []

            annotations = task.get("annotations", [])
            if not annotations:
                continue

            results = annotations[0].get("result", [])

            for result in results:
                if result["type"] == "labels":
                    start = result["value"]["start"]
                    end = result["value"]["end"]
                    label = result["value"]["labels"][0]

                    span = doc.char_span(start, end, label=label, alignment_mode="contract")
                    if span is None:
                        skipped_entities += 1
                    else:
                        ents.append(span)
                        valid_entities += 1
                        label_counts[label] += 1

            doc.ents = filter_spans(ents)
            db.add(doc)

        db.to_disk(output_filename)
        print(
            f"[{output_filename}] Saved {len(dataset)} records containing "
            f"{valid_entities} valid entities. (Skipped {skipped_entities} misaligned bounds)."
        )
        return {
            "records": len(dataset),
            "valid_entities": valid_entities,
            "skipped_entities": skipped_entities,
            "labels": dict(sorted(label_counts.items())),
        }

    print(f"Processing {len(data)} total Label Studio tasks (seed={seed})...")
    train_stats = process_dataset(train_data, train_output)
    dev_stats = process_dataset(dev_data, dev_output)

    manifest = {
        "created_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source_file": os.path.basename(json_file_path),
        "source_sha256": _sha256_file(json_file_path),
        "seed": seed,
        "split_ratio": split_ratio,
        "total_tasks": len(data),
        "train": train_stats,
        "dev": dev_stats,
    }
    manifest_path = os.path.join(os.path.dirname(os.path.abspath(train_output)), "dataset_manifest.json")
    with open(manifest_path, "w", encoding="utf-8") as mf:
        json.dump(manifest, mf, indent=2)
    print(f"Saved dataset provenance manifest to {manifest_path}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python convert_to_spacy.py <label_studio_export.json> [seed]")
        sys.exit(1)

    seed_arg = int(sys.argv[2]) if len(sys.argv) >= 3 else DEFAULT_SEED
    convert_label_studio_to_spacy(sys.argv[1], seed=seed_arg)