import json
import os
from datetime import datetime, timezone

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


def stamp_meta(model_dir="models/model-best", version="0.2.0"):
    meta_path = os.path.join(BASE_DIR, model_dir, "meta.json")
    manifest_path = os.path.join(BASE_DIR, "dataset_manifest.json")

    with open(meta_path, "r", encoding="utf-8") as f:
        meta = json.load(f)

    manifest = {}
    if os.path.exists(manifest_path):
        with open(manifest_path, "r", encoding="utf-8") as f:
            manifest = json.load(f)

    vec_name = meta.get("vectors", {}).get("name") or "en_core_web_md"
    sha_short = manifest.get("source_sha256", "unknown")[:12]
    seed = manifest.get("seed", 42)
    train_n = manifest.get("train", {}).get("records", "?")
    dev_n = manifest.get("dev", {}).get("records", "?")

    meta["name"] = "cti_ner_windows"
    meta["version"] = version
    meta["description"] = (
        f"Windows CTI NER ({vec_name}, seed={seed}, train={train_n}, dev={dev_n}, "
        f"corpus_sha256={sha_short}) built {datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}"
    )

    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2)
    print(f"Stamped {meta_path} -> {meta['name']} v{meta['version']}")


if __name__ == "__main__":
    stamp_meta()