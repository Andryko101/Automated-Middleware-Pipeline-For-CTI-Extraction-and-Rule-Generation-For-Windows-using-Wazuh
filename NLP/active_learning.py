import json
import spacy
import sys

def parse_concatenated_json(file_path):
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()

    decoder = json.JSONDecoder()
    idx = 0
    length = len(content)
    records = []

    while idx < length:
        # Skip inter-record whitespace, trailing commas, and boundary brackets
        while idx < length and content[idx] in " \t\r\n,[]":
            idx += 1
        if idx >= length:
            break

        try:
            obj, end_idx = decoder.raw_decode(content, idx)
            if isinstance(obj, list):
                records.extend(obj)
            elif isinstance(obj, dict):
                records.append(obj)
            idx = end_idx
        except json.JSONDecodeError:
            # Advance past unparseable characters until the next valid record
            idx += 1

    return records

def generate_pre_annotations(input_file, output_json, model_path="models/model-best"):
    print(f"Loading model from {model_path}...")
    nlp = spacy.load(model_path)

    print(f"Reading and parsing {input_file}...")
    data = parse_concatenated_json(input_file)
    print(f"Extracted {len(data)} total records from input.")

    annotated_tasks = []

    for item in data:
        text = item.get("text", "")
        if not text or not isinstance(text, str):
            continue

        doc = nlp(text)

        results = []
        for ent in doc.ents:
            results.append({
                "from_name": "label",
                "to_name": "text",
                "type": "labels",
                "value": {
                    "start": ent.start_char,
                    "end": ent.end_char,
                    "text": ent.text,
                    "labels": [ent.label_]
                }
            })

        task = {
            "data": {"text": text},
            "predictions": [{
                "model_version": "v1_baseline",
                "result": results
            }]
        }
        annotated_tasks.append(task)

    with open(output_json, 'w', encoding='utf-8') as f:
        json.dump(annotated_tasks, f, indent=4)

    print(f"Successfully generated {len(annotated_tasks)} pre-annotated tasks in {output_json}.")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python active_learning.py <input.file> <output.json>")
        sys.exit(1)

    generate_pre_annotations(sys.argv[1], sys.argv[2])