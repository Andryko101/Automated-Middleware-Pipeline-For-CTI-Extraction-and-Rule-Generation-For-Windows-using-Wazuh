import spacy
import json
import re

# Load your Version 4 model
nlp = spacy.load("models/model-best")

def parse_concatenated_json(file_path):
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()

    decoder = json.JSONDecoder()
    idx = 0
    length = len(content)
    records = []

    while idx < length:
        while idx < length and content[idx] in " \t\r\n,[]":
            idx += 1
        if idx >= length:
            break
        try:
            obj, end_idx = decoder.raw_decode(content, idx)
            if isinstance(obj, dict):
                records.append(obj)
            idx = end_idx
        except json.JSONDecodeError:
            idx += 1
    return records

def escape_pcre2(text):
    safe_xml = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    cleaned = safe_xml.replace("[.]", ".").replace("hxxp://", "http://").replace("hxxps://", "https://")
    return re.escape(cleaned)

def chunk_list(lst, chunk_size):
    """Splits a list into smaller chunks to prevent Regex overload."""
    for i in range(0, len(lst), chunk_size):
        yield lst[i:i + chunk_size]

def generate_complex_rules(rule_base_id, report_title, all_entities):
    mapping = {
        "Process_Name": ("sysmon_event1", "win.eventdata.image", "T1059"),
        "Command_Line": ("sysmon_event1", "win.eventdata.commandLine", "T1059"),
        "File_Path": ("sysmon_event11", "win.eventdata.targetFilename", "T1105"),
        "Registry_Key": ("sysmon_event13", "win.eventdata.targetObject", "T1112"),
        "IP_Address": ("sysmon_event3", "win.eventdata.destinationIp", "T1071"),
        "Domain_URL": ("sysmon_event3", "win.eventdata.destinationHostname", "T1071")
    }

    grouped = {}
    for label, text in all_entities:
        if label in mapping:
            event_type, field, mitre_id = mapping[label]
            grouped.setdefault((event_type, field, mitre_id), set()).add(escape_pcre2(text))

    xml_output = []
    current_id = rule_base_id

    # Group rules by Advisory Title to provide context to the analyst
    xml_output.append(f'<!-- Rules for: {report_title} -->')

    for (event_type, field_name, mitre_id), values in grouped.items():
        # Break massive lists into chunks of 15 to keep PCRE2 performant
        for value_chunk in chunk_list(sorted(list(values)), 15):
            pattern = "|".join(value_chunk)
            xml_output.append(f'<rule id="{current_id}" level="12">')
            xml_output.append(f'  <if_group>{event_type}</if_group>')
            xml_output.append(f'  <description>CISA Intel Match: {report_title[:50]}...</description>')
            xml_output.append(f'  <mitre>')
            xml_output.append(f'    <id>{mitre_id}</id>')
            xml_output.append(f'  </mitre>')
            xml_output.append(f'  <field name="{field_name}" type="pcre2">(?i)({pattern})</field>')
            xml_output.append('</rule>\n')
            current_id += 1

    return xml_output, current_id

def process_report(jsonl_path):
    print(f"Loading and parsing {jsonl_path}...")
    records = parse_concatenated_json(jsonl_path)
    print(f"Loaded {len(records)} sections from report.\n")

    # Group entities by the specific CISA Advisory Title they came from
    reports_data = {}
    for item in records:
        title = item.get("title", "Unknown CISA Advisory")
        text = item.get("text", "")
        if text:
            doc = nlp(text)
            for ent in doc.ents:
                reports_data.setdefault(title, set()).add((ent.label_, ent.text))

    all_xml = ["<group name=\"cisa_tactical_intel\">"]
    current_rule_id = 100001

    # Generate rules per advisory
    for title, entities in reports_data.items():
        rules_xml, next_id = generate_complex_rules(current_rule_id, title, entities)
        all_xml.extend(rules_xml)
        current_rule_id = next_id

    all_xml.append("</group>")
    final_xml = "\n".join(all_xml)

    output_file = "wazuh_rules.xml"
    with open(output_file, "w", encoding='utf-8') as f:
        f.write(final_xml)
    print(f"\nRules successfully written to {output_file} (Generated {current_rule_id - 100001} modular rules)")

if __name__ == "__main__":
    process_report("v4_master_dataset.json")