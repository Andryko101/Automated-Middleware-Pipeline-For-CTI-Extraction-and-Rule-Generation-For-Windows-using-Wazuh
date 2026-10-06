import json
import spacy
import random
import sys
from spacy.tokens import DocBin
from spacy.util import filter_spans

def convert_label_studio_to_spacy(json_file_path, train_output="train.spacy", dev_output="dev.spacy", split_ratio=0.8):
    # Initialize a blank English pipeline to use its tokenizer
    nlp = spacy.blank("en")
    
    with open(json_file_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
        
    # Shuffle the data to ensure an even distribution of examples in train/dev sets
    random.shuffle(data)
    
    split_index = int(len(data) * split_ratio)
    train_data = data[:split_index]
    dev_data = data[split_index:]
    
    def process_dataset(dataset, output_filename):
        db = DocBin()
        skipped_entities = 0
        valid_entities = 0
        
        for task in dataset:
            # Matches the <Text name="text" value="$text"/> from our XML schema
            text = task.get('data', {}).get('text', '')
            if not text:
                continue
                
            doc = nlp.make_doc(text)
            ents = []
            
            # Extract the annotations 
            annotations = task.get('annotations', [])
            if not annotations:
                continue
                
            # We assume a single completed annotation per task
            results = annotations[0].get('result', [])
            
            for result in results:
                if result['type'] == 'labels':
                    start = result['value']['start']
                    end = result['value']['end']
                    label = result['value']['labels'][0]
                    
                    # alignment_mode="contract" fixes errors where manual highlighting grabs trailing whitespace
                    span = doc.char_span(start, end, label=label, alignment_mode="contract")
                    
                    if span is None:
                        skipped_entities += 1
                    else:
                        ents.append(span)
                        valid_entities += 1
                        
            # filter_spans removes overlaps (e.g., if you accidentally tagged a path inside a command line)
            doc.ents = filter_spans(ents)
            db.add(doc)
            
        db.to_disk(output_filename)
        print(f"[{output_filename}] Saved {len(dataset)} records containing {valid_entities} valid entities. (Skipped {skipped_entities} misaligned bounds).")

    print(f"Processing {len(data)} total Label Studio tasks...")
    process_dataset(train_data, train_output)
    process_dataset(dev_data, dev_output)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python convert_to_spacy.py <label_studio_export.json>")
        sys.exit(1)
        
    convert_label_studio_to_spacy(sys.argv[1])