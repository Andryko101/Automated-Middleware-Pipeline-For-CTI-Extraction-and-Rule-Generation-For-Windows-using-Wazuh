import json

def check_boundaries(file_path):
    with open(file_path, 'r', encoding='utf-8') as f:
        data = json.load(f)

    issues_found = 0

    for task in data:
        task_id = task.get('id')
        
        # Label Studio stores annotations in a list
        for annotation in task.get('annotations', []):
            for result in annotation.get('result', []):
                value = result.get('value', {})
                text = value.get('text', '')
                
                if not text:
                    continue
                    
                label = value.get('labels', ['Unknown'])[0]
                
                # Check if the extracted text has leading/trailing spaces
                if text != text.strip():
                    print(f"Task ID {task_id}: Whitespace issue in [{label}] -> '{text}'")
                    issues_found += 1

    if issues_found == 0:
        print("Dataset is clean! No whitespace boundary issues detected.")
    else:
        print(f"\nTotal boundary issues to fix in Label Studio: {issues_found}")

# Run the check
check_boundaries('v5_relabeled_master_dataset.json')