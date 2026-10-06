import json
import sys

def merge_json_exports(file1, file2, output_file):
    with open(file1, 'r', encoding='utf-8') as f1:
        data1 = json.load(f1)
        
    with open(file2, 'r', encoding='utf-8') as f2:
        data2 = json.load(f2)
        
    combined_data = data1 + data2
    
    with open(output_file, 'w', encoding='utf-8') as out:
        json.dump(combined_data, out, indent=4)
        
    print(f"Merged {len(data1)} and {len(data2)} tasks.")
    print(f"Successfully saved {len(combined_data)} total tasks to {output_file}.")

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python merge_datasets.py <export1.json> <export2.json> <merged_output.json>")
        sys.exit(1)
        
    merge_json_exports(sys.argv[1], sys.argv[2], sys.argv[3])