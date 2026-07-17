import os
import re
import json
import uuid
import yaml

base_dir = r"C:\Users\Sunil\OneDrive\Desktop\coorelation-rules"
categories = [
    'discovery', 'command-and-control', 'credential-access', 'reconnaissance', 
    'initial-access', 'exfiltration', 'lateral-movement', 'persistence', 
    'privilege-escalation', 'stealth', 'collection', 'execution', 'impact', 'defense-impairment'
]

import glob
json_rule_dirs = glob.glob(os.path.join(base_dir, 'json_correlation_rules', '*'))
json_categories = [os.path.relpath(d, base_dir) for d in json_rule_dirs if os.path.isdir(d)]
categories.extend(json_categories)


field_mapping = {
    'Image': 'process.file.path',
    'CommandLine': 'process.cmd_line',
    'OriginalFileName': 'process.file.name',
    'ParentImage': 'unmapped.parent_image',
    'ParentCommandLine': 'unmapped.parent_cmd_line',
    'TargetObject': 'registry.key',
    'Details': 'registry.data.content',
    'DestinationPort': 'dst_endpoint.port',
    'DestinationIp': 'dst_endpoint.ip',
    'ScriptBlockText': 'unmapped.script_block_text',
    'EventID': 'event_id',
    'signature_name': 'signature_name',
    'EventType': 'unmapped.event_type'
}

def map_sigma_to_ocsf_yaml(sigma_yaml):
    lines = sigma_yaml.split('\n')
    out_lines = []
    for line in lines:
        for k, v in field_mapping.items():
            # Replace exactly the key at the start of the line or after a hyphen
            line = re.sub(rf'^(\s*-\s*){k}\b', rf'\1{v}', line)
            line = re.sub(rf'^(\s*){k}\b', rf'\1{v}', line)
        out_lines.append(line)
    return '\n'.join(out_lines)

def extract_values_from_detection(detection_yaml):
    # Very crude but effective value extractor
    # Look for patterns like: process.cmd_line|contains: 'foo'
    # or lists under it.
    extracted = {}
    lines = detection_yaml.split('\n')
    current_key = None
    
    for line in lines:
        if 'condition:' in line:
            break
        
        # Match "key: value" or "key|modifier: value"
        m = re.match(r'^\s*-?\s*([a-zA-Z0-9_\.]+)(?:\|[a-zA-Z0-9_]+)?:\s*[\'"]?([^\'"\n]+)[\'"]?', line)
        if m:
            key = m.group(1)
            val = m.group(2)
            if key not in extracted:
                extracted[key] = val
            continue
            
        # Match "key:"
        m2 = re.match(r'^\s*-?\s*([a-zA-Z0-9_\.]+)(?:\|[a-zA-Z0-9_]+)?:\s*$', line)
        if m2:
            current_key = m2.group(1)
            continue
            
        # Match list item "- 'value'"
        m3 = re.match(r'^\s*-\s*[\'"]?([^\'"\n]+)[\'"]?', line)
        if m3 and current_key:
            val = m3.group(1)
            if current_key not in extracted:
                extracted[current_key] = val
                
    return extracted

def generate_telemetry_json(uid, title, ocsf_cls, cat, test_case, expected_alert, extracted_vals, is_malformed=False, is_coercion=False, is_benign=False, time_offset=0):
    # Start with a base payload based on OCSF class
    payload = {}
    
    if ocsf_cls == "process_activity":
        payload = {
            "category_uid": 1, "class_uid": 1007, "class_name": "Process Activity", "activity_name": "Launch",
            "process": {"file": {"path": "C:\\Windows\\System32\\cmd.exe", "name": "cmd.exe"}, "cmd_line": "cmd.exe"},
            "actor": {"user": {"name": "TargetUser"}}, "unmapped": {}
        }
    elif ocsf_cls == "file_activity":
        payload = {
            "category_uid": 1, "class_uid": 1001, "class_name": "File Activity", "activity_name": "Create",
            "file": {"path": "C:\\Temp\\test.txt", "name": "test.txt"},
            "actor": {"user": {"name": "TargetUser"}}, "unmapped": {}
        }
    elif ocsf_cls == "registry_key_activity":
        payload = {
            "category_uid": 1, "class_uid": 1011, "class_name": "Registry Key Activity", "activity_name": "Create",
            "registry": {"key": "HKLM\\Software\\Test", "data": {"content": "0x0"}},
            "actor": {"user": {"name": "TargetUser"}}, "unmapped": {}
        }
    elif ocsf_cls == "network_activity":
        payload = {
            "category_uid": 4, "class_uid": 4001, "class_name": "Network Activity", "activity_name": "Traffic",
            "dst_endpoint": {"ip": "10.0.0.1", "port": 80}, "src_endpoint": {"ip": "192.168.1.100", "port": 50000},
            "unmapped": {}
        }
    else:
        payload = {
            "category_uid": 1, "class_uid": 1007, "class_name": "Process Activity", "activity_name": "Launch",
            "process": {"file": {"path": "C:\\Windows\\System32\\unknown.exe"}},
            "actor": {"user": {"name": "TargetUser"}}, "unmapped": {}
        }

    # Inject specific values for TP
    if expected_alert:
        for k, v in extracted_vals.items():
            if k == 'process.cmd_line':
                if 'process' not in payload: payload['process'] = {}
                payload['process']['cmd_line'] = f"C:\\Windows\\System32\\cmd.exe /c {v}"
            elif k == 'process.file.path':
                if 'process' not in payload: payload['process'] = {}
                if 'file' not in payload['process']: payload['process']['file'] = {}
                clean_v = v.replace('\\', '')
                payload['process']['file']['path'] = f"C:\\Temp\\{clean_v}"
            elif k == 'process.file.name':
                if 'process' not in payload: payload['process'] = {}
                if 'file' not in payload['process']: payload['process']['file'] = {}
                payload['process']['file']['name'] = v
            elif k == 'registry.key':
                if 'registry' not in payload: payload['registry'] = {}
                clean_v = v.lstrip('\\')
                payload['registry']['key'] = f"HKLM\\{clean_v}"
            elif k == 'registry.data.content':
                if 'registry' not in payload: payload['registry'] = {}
                if 'data' not in payload['registry']: payload['registry']['data'] = {}
                payload['registry']['data']['content'] = v
            elif k == 'dst_endpoint.port':
                if 'dst_endpoint' not in payload: payload['dst_endpoint'] = {}
                try: payload['dst_endpoint']['port'] = int(v)
                except: pass
            elif k == 'unmapped.script_block_text':
                payload['unmapped']['script_block_text'] = f"Invoke-Command {v}"
            elif k.startswith('unmapped.'):
                subk = k.split('unmapped.')[1]
                payload['unmapped'][subk] = v

    # Add metadata
    payload["metadata"] = {
        "test_case": test_case,
        "description": f"{title} ({test_case})",
        "expected_alert": expected_alert,
        "rule_uid": uid
    }
    payload["activity_id"] = "1" if is_coercion else 1
    payload["time"] = 1718000000 + time_offset
    
    if is_malformed and "unmapped" in payload:
        del payload["unmapped"]
        
    if is_benign and "unmapped" in payload:
        payload["unmapped"]["generic"] = "benign_test"
        
    if "unmapped" in payload and not payload["unmapped"] and not is_malformed:
        payload["unmapped"]["dummy"] = "data"
        
    return json.dumps(payload)

def get_ocsf_class(cat):
    m = {
        "process_creation": "process_activity",
        "file_creation": "file_activity",
        "file_event": "file_activity",
        "registry_set": "registry_key_activity",
        "registry_event": "registry_key_activity",
        "network_connection": "network_activity",
        "image_load": "driver_activity",
        "driver_load": "driver_activity",
        "authentication": "authentication",
        "security": "account_change",
        "ps_script": "process_activity",
        "ps_module": "process_activity",
        "sysmon_error": "process_activity"
    }
    return m.get(cat.lower(), "process_activity")

def process_file(filepath):
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()

    if 'undetectable' in content.lower() or filepath.endswith('readme.md') or filepath.endswith('readme.txt'):
        return

    # Look for Custom Sigma Rule section
    sigma_marker = None
    if "### 2. Custom Sigma Rule" in content: sigma_marker = "### 2. Custom Sigma Rule"
    elif "## Custom Sigma Rule" in content: sigma_marker = "## Custom Sigma Rule"
    elif "## 2. Custom Sigma Rule" in content: sigma_marker = "## 2. Custom Sigma Rule"
    
    if not sigma_marker:
        return
        
    sigma_split = content.split(sigma_marker)[1]
    
    needs_recompile = True
        
    if not needs_recompile:
        return
        
    yaml_blocks = re.findall(r'```yaml(.*?)```', content, re.DOTALL)
    
    sigma_rules = []
    for yb in yaml_blocks:
        if 'detection:' in yb and ('OCSF' not in yb and 'ocsf' not in yb):
            sigma_rules.append(yb)
            
    if not sigma_rules:
        return
        
    top_part = content.split(sigma_marker)[0]
    new_content = top_part + "### 2. Custom Sigma Rule\n\n"
    
    ocsf_blocks = []
    parsed_rules = []
    
    for i, s_yaml in enumerate(sigma_rules):
        new_content += f"```yaml{s_yaml}```\n\n"
        
        title_match = re.search(r'title:\s*[\'"]?([^\'"\n]+)[\'"]?', s_yaml)
        title = title_match.group(1).strip() if title_match else "Unknown Title"
        
        id_match = re.search(r'id:\s*[\'"]?([^\'"\n]+)[\'"]?', s_yaml)
        uid = id_match.group(1).strip() if id_match else str(uuid.uuid4())
        if not re.match(r'^[a-fA-F0-9\-]{36}$', uid):
            uid = str(uuid.uuid4())
            new_content = new_content.replace(f"id: {id_match.group(1) if id_match else ''}", f"id: '{uid}'")
            
        cat_match = re.search(r'category:\s*([^\n]+)', s_yaml)
        cat = cat_match.group(1).strip() if cat_match else "process_creation"
        ocsf_cls = get_ocsf_class(cat)
        
        tags = []
        if "tags:" in s_yaml:
            try:
                tags_part = s_yaml.split("tags:")[1]
                if "falsepositives:" in tags_part: tags_part = tags_part.split("falsepositives:")[0]
                if "level:" in tags_part: tags_part = tags_part.split("level:")[0]
                for line in tags_part.strip().split("\n"):
                    line = line.strip()
                    if line.startswith("-"): tags.append(line)
            except: pass
        tags_str = "\n".join(["    " + t for t in tags]) if tags else f"    - attack.technique"
        
        # EXTRACT DETECTION BLOCK
        try:
            detection_part = s_yaml.split("detection:")[1].split("fields:")[0].split("falsepositives:")[0]
        except:
            detection_part = "\n    selection:\n        activity_id: 1\n    condition: selection\n"
            
        mapped_detection = map_sigma_to_ocsf_yaml(detection_part)
        extracted_vals = extract_values_from_detection(mapped_detection)
        
        ocsf_blocks.append(f"""```yaml
title: '{title} (OCSF-Normalized)'
id: '{uid}'
status: experimental
description: 'OCSF Normalized rule for {title}'
author: Krishna Gupta
logsource:
    product: ocsf
    class: {ocsf_cls}
detection:{mapped_detection.rstrip()}
fields:
    - time
level: high
tags:
{tags_str}
```""")
        parsed_rules.append({"uid": uid, "title": title, "class": ocsf_cls, "category": cat, "extracted": extracted_vals})

    new_content += "---\n\n### 3. OCSF Normalized Rule\n\n"
    new_content += "\n\n".join(ocsf_blocks) + "\n\n"
    new_content += "---\n\n### 4. Blind Spots & Tuning (The \"Problems\")\n\n"
    new_content += "- Authorized IT administration activities.\n- Tune with allowlists for known trusted execution paths.\n\n"
    new_content += "---\n\n"
    
    tests_md = "### 5. Test Cases (Engine Pipeline Verification)\n\n"
    tests_md += "#### True Positives\n"
    for i, r in enumerate(parsed_rules, 1):
        tests_md += f"* True Positive {i}A: Standard Execution ({r['title']})\n  * The Log: Activity simulating malicious behavior.\n  * Expected Outcome: MUST trigger an alert.\n\n"
        tests_md += f"* True Positive {i}B: Malformed JSON Robustness Test ({r['title']})\n  * The Log: Simulating {i}A but intentionally omitting the `unmapped` object entirely.\n  * Expected Outcome: Engine parser should degrade gracefully. MUST trigger an alert.\n\n"
        tests_md += f"* True Positive {i}C: Schema Type Validation Failure ({r['title']})\n  * The Log: Exact match of {i}A, but `activity_id` is passed as a string `\"1\"` instead of an integer `1`.\n  * Expected Outcome: Tests if the engine's JSON parser coerces the type gracefully. MUST trigger an alert.\n\n"
        tests_md += f"* True Positive {i}D: Exact Duplicate Event ({r['title']})\n  * The Log: Exact duplicate of {i}A with the exact same timestamp.\n  * Expected Outcome: Tests deduplication window.\n\n"

    tests_md += "#### Benign / True Negatives\n"
    for i, r in enumerate(parsed_rules, 1):
        tests_md += f"* Benign {i}: Allowed Activity ({r['title']})\n  * The Log: Activity matching legitimate patterns.\n  * Expected Outcome: Matches exclusion filters. MUST NOT trigger an alert.\n\n"
        
    tests_md += "---\n\n### 6. Raw Telemetry Dataset (OCSF JSON)\n\n"
    tests_md += "#### Benign Telemetry\n```jsonl\n"
    for i, r in enumerate(parsed_rules, 1):
        tcode = f"TN-{i:02d}"
        tests_md += generate_telemetry_json(r['uid'], r['title'], r['class'], r['category'], tcode, False, r['extracted'], is_benign=True, time_offset=i*10) + "\n"
    tests_md += "```\n\n"
    
    tests_md += "#### True Positive Telemetry\n```jsonl\n"
    time_counter = 100
    for i, r in enumerate(parsed_rules, 1):
        tcode = f"TP-{i:02d}"
        tests_md += generate_telemetry_json(r['uid'], r['title'], r['class'], r['category'], tcode+"A", True, r['extracted'], time_offset=time_counter) + "\n"
        tests_md += generate_telemetry_json(r['uid'], r['title'], r['class'], r['category'], tcode+"B", True, r['extracted'], is_malformed=True, time_offset=time_counter+1) + "\n"
        tests_md += generate_telemetry_json(r['uid'], r['title'], r['class'], r['category'], tcode+"C", True, r['extracted'], is_coercion=True, time_offset=time_counter+2) + "\n"
        tests_md += generate_telemetry_json(r['uid'], r['title'], r['class'], r['category'], tcode+"D", True, r['extracted'], time_offset=time_counter) + "\n"
        time_counter += 10
    tests_md += "```\n"
    
    new_content += tests_md

    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(new_content)
    print(f"Recompiled {os.path.basename(filepath)}")

total = 0
for cat in categories:
    cat_dir = os.path.join(base_dir, cat)
    if not os.path.exists(cat_dir): continue
    for fn in os.listdir(cat_dir):
        if fn.endswith('.md'):
            process_file(os.path.join(cat_dir, fn))
            total += 1
            
print(f"Sweep complete. Scanned {total} files.")
