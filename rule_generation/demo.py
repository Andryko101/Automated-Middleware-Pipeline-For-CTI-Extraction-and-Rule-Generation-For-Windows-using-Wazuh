import os
import re
import glob
import html
import json
import spacy
import ipaddress
import tldextract

# Initialize Public Suffix List extractor
extract_tld = tldextract.TLDExtract(include_psl_private_domains=True)

# Resolve model path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, "..", "NLP", "models", "model-best")

print("Loading Threat Intelligence NLP Model...")
try:
    nlp = spacy.load(MODEL_PATH)
    print("Model loaded successfully.\n")
except Exception as e:
    print(f"Error loading model from {MODEL_PATH}: {e}")
    exit(1)

# ---------------------------------------------------------------------------
# Whitelists, Blacklists & Categorization Maps
# ---------------------------------------------------------------------------
ALLOWLIST_DOMAINS = {
    "microsoft.com", "cisa.gov", "nsa.gov", "cnss.gov", "nist.gov",
    "defense.gov", "specterops.io", "discordapp.com", "github.com",
    "mitre.org", "redcanary.com", "paloaltonetworks.com", "thedfirreport.com",
    "securityintelligence.com", "catbox.moe", "raw.githubusercontent.com", "cert.gov", "system.io"
}


PUBLIC_IP_ALLOWLIST = {"8.8.8.8", "8.8.4.4", "1.1.1.1", "9.9.9.9", "111.111.111.111"}

BLOCKED_FILE_EXTENSIONS = {
    "txt", "bat", "png", "tar", "zip", "jsp", "dat", "cmd", "old", "php",
    "rar", "log", "sys", "wasd", "jpg", "js", "py", "sh", "exe", "dll",
    "ps1", "dit", "jfm", "doc", "docx", "pdf", "vbs"
}

# Dual-use built-in Windows LOLBins (dropped from static level 12 rules)
LOLBINS_DUAL_USE = {
    "powershell.exe", "cmd.exe", "notepad.exe", "conhost.exe", "mstsc.exe",
    "ssh.exe", "7z.exe", "find.exe", "dir.exe", "clip.exe", "rdpclip.exe",
    "werfault.exe", "wmiprvse.exe", "w3wp.exe", "certutil.exe", "mshta.exe",
    "regsvr32.exe", "vssadmin.exe", "wmic.exe", "esentutl.exe", "ntdsutil.exe",
    "dsquery.exe", "dismhost.exe", "nltest.exe", "taskeng.exe""explorer.exe", 
    "lsass.exe", "msedge.exe", "msiexec.exe", "net.exe", 
    "reg.exe", "rundll32.exe", "runtimebroker.exe", "sc.exe", "schtasks.exe", 
    "svchost.exe", "tasklist.exe", "tracert.exe", "whoami.exe", "ping.exe",
    "attrib.exe", "bcdedit.exe", "dllhost.exe", "fontdrvhosts.exe",
    "httpd.exe", "ntoskrnl.exe", "explorer.exe"
}

# Specific Offensive Tool MITRE Technique & Severity Mapping
OFFENSIVE_TOOLS = {
    "mimikatz.exe": ("T1003.001", 12, "OS Credential Dumping - Mimikatz"),
    "psexec.exe": ("T1021.002", 10, "Service Execution - PsExec"),
    "psexesvc.exe": ("T1021.002", 10, "Service Execution - PsExec Service"),
    "rclone.exe": ("T1567.002", 10, "Exfiltration to Cloud Storage - Rclone"),
    "anydesk.exe": ("T1219", 8, "Remote Access Software - AnyDesk"),
    "netscan.exe": ("T1046", 8, "Network Service Discovery - SoftPerfect NetScan"),
    "adfind.exe": ("T1087.002", 8, "Domain Account Discovery - AdFind")
}

# ---------------------------------------------------------------------------
# Normalization & Validation Helpers
# ---------------------------------------------------------------------------
def normalize_defanged(text):
    """Converts defanged IOC syntax (e.g. 104[.]155[.]149[.]103 or hxxp://) to standard form."""
    if not text:
        return ""
    cleaned = text.replace("[.]", ".").replace("(.)", ".").replace("[dot]", ".")
    cleaned = re.sub(r"^hxxps?://", "http://", cleaned, flags=re.IGNORECASE)
    return cleaned.strip()

def sanitize_and_validate_ip(raw_string):
    cleaned = normalize_defanged(raw_string)
    cleaned = re.sub(r"^https?://", "", cleaned).split(":")[0].split("/")[0]
    try:
        ip_obj = ipaddress.ip_address(cleaned)
        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_multicast or str(ip_obj) in PUBLIC_IP_ALLOWLIST:
            return None
        return str(ip_obj)
    except ValueError:
        return None

def clean_and_validate_domain(raw_string):
    """Validates FQDNs via Public Suffix List, filtering file extensions and citation domains."""
    cleaned = normalize_defanged(raw_string)
    if not cleaned or any(c in cleaned for c in ['\\', '{', '}', '*', ' ', '[', ']', '<', '>']):
        return None

    if cleaned.startswith(('http://', 'https://')):
        parts = cleaned.split('/')
        cleaned = parts[2].split(':')[0] if len(parts) > 2 else cleaned
    else:
        cleaned = cleaned.split('/')[0].split(':')[0]

    cleaned = cleaned.strip('.').lower()

    # Reject if suffix is a file extension artifact
    ext = cleaned.split('.')[-1]
    if ext in BLOCKED_FILE_EXTENSIONS:
        return None

    # Public Suffix List check
    res = extract_tld(cleaned)
    if not res.domain or not res.suffix:
        return None

    domain_fqdn = f"{res.domain}.{res.suffix}"
    if domain_fqdn in ALLOWLIST_DOMAINS or cleaned in ALLOWLIST_DOMAINS:
        return None

    return f"{res.subdomain}.{domain_fqdn}" if res.subdomain else domain_fqdn

def sanitize_process_name(raw_string):
    """Cleans process image targets, stripping paths and dropping URLs or mangled text."""
    cleaned = normalize_defanged(raw_string)

    if any(k in cleaned.lower() for k in ['http://', 'https://', '[redacted]', ']', '{', '}', '@']):
        return None

    basename = os.path.basename(cleaned.replace('\\', '/')).lower()

    if not basename.endswith(('.exe', '.dll', '.ps1', '.bat', '.cmd')):
        return None

    # Exclude single-letter generic process names that cause overlap false positives
    if len(basename) <= 5 and basename not in {'cmd.exe', 'cl.exe'}:
        return None

    return basename

# ---------------------------------------------------------------------------
# Extraction Pipeline
# ---------------------------------------------------------------------------
def extract_hybrid_entities(text, doc):
    entities = []

    for ent in doc.ents:
        e_text = ent.text.strip()
        
        valid_ip = sanitize_and_validate_ip(e_text)
        if valid_ip:
            entities.append(("IP_Address", valid_ip))
            continue

        if ent.label_ in ("Domain_URL", "Domain") or ("." in e_text and not e_text.endswith(('.exe', '.dll', '.ps1'))):
            clean_domain = clean_and_validate_domain(e_text)
            if clean_domain:
                entities.append(("Domain_URL", clean_domain))
                continue

        if ent.label_ == "Process_Name":
            clean_proc = sanitize_process_name(e_text)
            if clean_proc and clean_proc not in LOLBINS_DUAL_USE:
                entities.append(("Process_Name", clean_proc))

    # Fallback IP Regex for defanged/raw text
    ip_pattern = r'\b(?:[0-9]{1,3}\[\.\]){3}[0-9]{1,3}\b|\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    for match in re.finditer(ip_pattern, text):
        valid_ip = sanitize_and_validate_ip(match.group(0))
        if valid_ip:
            entities.append(("IP_Address", valid_ip))

    # Fallback Domain Regex
    domain_pattern = r'(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|xyz|net|org|io|gov|edu|co)\b'
    for match in re.finditer(domain_pattern, text):
        clean_domain = clean_and_validate_domain(match.group(0))
        if clean_domain:
            entities.append(("Domain_URL", clean_domain))

    return entities

# ---------------------------------------------------------------------------
# Wazuh Rule Compiler
# ---------------------------------------------------------------------------
def generate_demo_rules(entities):
    ips = sorted(list(set([e[1] for e in entities if e[0] == "IP_Address"])))
    domains = sorted(list(set([e[1] for e in entities if e[0] == "Domain_URL"])))
    processes = sorted(list(set([e[1] for e in entities if e[0] == "Process_Name"])))

    xml_output = []

    # Rule 1: Malicious IPs
    if ips:
        ip_pcre = "|".join(re.escape(ip) for ip in ips)
        xml_output.append(f'''<rule id="100005" level="12">
  <if_group>sysmon_event3</if_group>
  <description>Threat Intel Match - Malicious IP</description>
  <mitre>
    <id>T1071</id>
  </mitre>
  <field name="win.eventdata.destinationIp" type="pcre2">^(?i)({ip_pcre})$</field>
</rule>''')

    # Rule 2: Malicious Domains (Anchored against subdomains)
    if domains:
        domain_pcre = "|".join(re.escape(d) for d in domains)
        xml_output.append(f'''<rule id="100004" level="12">
  <if_group>sysmon_event3</if_group>
  <description>Threat Intel Match - Malicious Domain</description>
  <mitre>
    <id>T1071.001</id>
  </mitre>
  <field name="win.eventdata.destinationHostname" type="pcre2">(?i)(^|\\.)({domain_pcre})$</field>
</rule>''')

    # Rule 3: Tiered Process Rules
    generic_processes = []
    rule_id_counter = 100010

    for proc in processes:
        if proc in OFFENSIVE_TOOLS:
            mitre_id, level, desc = OFFENSIVE_TOOLS[proc]
            proc_pcre = re.escape(proc)
            xml_output.append(f'''<rule id="{rule_id_counter}" level="{level}">
  <if_group>sysmon_event1</if_group>
  <description>Threat Intel Match - {desc}</description>
  <mitre>
    <id>{mitre_id}</id>
  </mitre>
  <field name="win.eventdata.image" type="pcre2">(?i)(\\\\|^){proc_pcre}$</field>
</rule>''')
            rule_id_counter += 1
        else:
            generic_processes.append(proc)

    if generic_processes:
        proc_pcre = "|".join(re.escape(p) for p in generic_processes)
        xml_output.append(f'''<rule id="100002" level="10">
  <if_group>sysmon_event1</if_group>
  <description>Threat Intel Match - Suspicious Process Execution</description>
  <mitre>
    <id>T1059</id>
  </mitre>
  <field name="win.eventdata.image" type="pcre2">(?i)(\\\\|^)({proc_pcre})$</field>
</rule>''')

    return "\n".join(xml_output)

# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------
def run_interactive_demo():
    print("==================================================")
    print("   Threat Intelligence Middleware - Bulk Demo     ")
    print("==================================================\n")

    report_pattern = os.path.join(BASE_DIR, "..", "data_ingestion", "reports", "*.jsonl")
    report_files = glob.glob(report_pattern)

    if not report_files:
        print(f"No report files found matching: {report_pattern}")
        return

    all_entities = []

    for report_file in report_files:
        print(f"Processing report file: {os.path.basename(report_file)}")
        with open(report_file, "r", encoding="utf-8") as file:
            for line in file:
                if not line.strip():
                    continue
                try:
                    item = json.loads(line)
                    text = html.unescape(item.get("text", ""))
                    if text:
                        doc = nlp(text)
                        entities = extract_hybrid_entities(text, doc)
                        all_entities.extend(entities)
                except json.JSONDecodeError:
                    continue

    if not all_entities:
        print("No valid entities detected across reports.")
        return

    print(f"\n[1] Extracted {len(all_entities)} clean, validated hybrid entities.")
    print("[2] Compiling anchored Wazuh/Sysmon rules...")

    xml_rules = generate_demo_rules(all_entities)

    print("\n================ FINAL XML OUTPUT ================\n")
    print(xml_rules)
    print("\n==================================================")

    output_path = os.path.join(BASE_DIR, "demo_rules.xml")
    with open(output_path, "w", encoding="utf-8") as output:
        output.write(xml_rules)
    print(f"Successfully wrote aggregated rules to {output_path}")

if __name__ == "__main__":
    run_interactive_demo()