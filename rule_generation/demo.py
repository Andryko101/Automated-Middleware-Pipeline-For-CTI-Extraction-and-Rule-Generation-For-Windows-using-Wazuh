import spacy
import re

print("Loading Threat Intelligence NLP Model...")
nlp = spacy.load("./models/model-best")
print("Model loaded successfully.\n")

def escape_pcre2(text):
    """Sanitizes text and defangs URLs for valid XML/PCRE2."""
    safe_xml = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    cleaned = safe_xml.replace("[.]", ".").replace("hxxp://", "http://").replace("hxxps://", "https://")
    return re.escape(cleaned)

def extract_hybrid_entities(text, doc):
    """Combines spaCy NER for context with raw Regex for structural IOCs."""
    # 1. Keep all model-predicted entities EXCEPT the faulty Domain/URL predictions
    entities = [(ent.label_, ent.text) for ent in doc.ents if ent.label_ != "Domain_URL"]
    
    # 2. Hardcode regex for structural network indicators (bypassing spaCy tokenization)
    domain_pattern = r'(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|xyz|net|org|io|gov|edu|co)\b'
    
    # 3. Define benign domains and scraper sources to ignore
    ignore_domains = {"cisa.gov", "redcanary.com", "paloaltonetworks.com", "thedfirreport.com"}
    
    for match in re.finditer(domain_pattern, text):
        domain = match.group(0)
        
        # 4. Skip if the extracted domain matches our ignore list
        if any(ignored in domain.lower() for ignored in ignore_domains):
            continue
            
        # 5. Ensure the regex doesn't duplicate something already tagged by the model
        if not any(domain in e_text for label, e_text in entities):
            entities.append(("Domain_URL", domain))
            
    return entities

def generate_demo_rules(entities):
    """Maps extracted entities to Sysmon Event IDs and generates Wazuh XML."""
    mapping = {
        "Process_Name": ("sysmon_event1", "win.eventdata.image", "T1059"),
        "Command_Line": ("sysmon_event1", "win.eventdata.commandLine", "T1059"),
        "File_Path": ("sysmon_event11", "win.eventdata.targetFilename", "T1105"),
        "Registry_Key": ("sysmon_event13", "win.eventdata.targetObject", "T1112"),
        "IP_Address": ("sysmon_event3", "win.eventdata.destinationIp", "T1071"),
        "Domain_URL": ("sysmon_event3", "win.eventdata.destinationHostname", "T1071")
    }

    # Extract Threat Actors separately to append to the rule description
    threat_actors = [escape_pcre2(text) for label, text in entities if label == "Threat_Actor"]
    actor_context = f" (Actor: {', '.join(set(threat_actors))})" if threat_actors else ""

    grouped = {}
    for label, text in entities:
        if label in mapping:
            event_type, field, mitre_id = mapping[label]
            grouped.setdefault((event_type, field, mitre_id), set()).add(escape_pcre2(text))

    xml_output = []
    current_id = 100001

    for (event_type, field_name, mitre_id), values in grouped.items():
        pattern = "|".join(sorted(list(values)))
        xml_output.append(f'<rule id="{current_id}" level="12">')
        xml_output.append(f'  <if_group>{event_type}</if_group>')
        xml_output.append(f'  <description>Threat Intel Match{actor_context}</description>')
        xml_output.append(f'  <mitre>\n    <id>{mitre_id}</id>\n  </mitre>')
        xml_output.append(f'  <field name="{field_name}" type="pcre2">(?i)({pattern})</field>')
        xml_output.append('</rule>')
        current_id += 1

    return "\n".join(xml_output)

def run_interactive_demo():
    print("==================================================")
    print("   Threat Intelligence Middleware - Live Demo     ")
    print("==================================================\n")
    
    with open("../data_ingestion/reports/cisa_tactical_reports.json","r")as file:
        text=file.read()
        if not text.strip():
            print("No text provided. Exiting.")
            return

    print("\n[1] Extracting Entities via spaCy & Regex...")
    doc = nlp(text)
    
    # Route through the hybrid extraction logic
    entities = extract_hybrid_entities(text, doc)
    
    if not entities:
        print("No entities detected in the provided text.")
        return
        
    for label, ent_text in entities:
        print(f"  -> {label.ljust(15)}: {ent_text}")

    print("\n[2] Mapping to Wazuh/Sysmon Log Primitives...")
    xml_rules = generate_demo_rules(entities)
    
    print("\n================ FINAL XML OUTPUT ================\n")
    print(xml_rules)
    print("\n==================================================")

    with open("demo_rules.xml", "w", encoding="utf-8") as output:
        output.write(xml_rules)
    print("Successfully wrote rules to demo_rules.xml")

if __name__ == "__main__":
    run_interactive_demo()