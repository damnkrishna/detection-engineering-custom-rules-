import os
import re
import json

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


errors = []
total_files = 0
total_jsonl = 0
passed_files = 0

for category in categories:
    cat_dir = os.path.join(base_dir, category)
    if not os.path.exists(cat_dir):
        continue
        
    for filename in os.listdir(cat_dir):
        if not filename.endswith('.md') or filename.lower().startswith('readme'): continue
        total_files += 1
        filepath = os.path.join(cat_dir, filename)
        
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
            
        if 'undetectable' in content.lower() and 'JSONL' not in content:
            continue
            
        # Extract all rule IDs from OCSF blocks
        ocsf_ids = []
        ocsf_section = ""
        if 'OCSF Normalized Rule' in content:
            ocsf_section = content.split('OCSF Normalized Rule')[1]
        elif 'OCSF Normalized' in content:
            ocsf_section = content.split('OCSF Normalized')[1]
            
        if ocsf_section:
            blocks = ocsf_section.split('```')
            for i in range(1, len(blocks), 2):
                block = blocks[i]
                id_match = re.search(r'id:\s*[\'\"]?([a-fA-F0-9\-]+)[\'\"]?', block)
                if id_match:
                    ocsf_ids.append(id_match.group(1).strip())
                    
        if not ocsf_ids:
            if 'undetectable' not in content.lower():
                errors.append(f'{category}/{filename}: No OCSF IDs found (detectable file).')
            continue
            
        # Parse JSONL lines
        jsonl_lines = []
        in_jsonl = False
        for line in content.split('\n'):
            if '```jsonl' in line.strip():
                in_jsonl = True
            elif line.strip() == '```' and in_jsonl:
                in_jsonl = False
            elif in_jsonl and '{' in line:
                jsonl_lines.append(line.strip())
                
        if not jsonl_lines:
            errors.append(f'{category}/{filename}: No JSONL payload found.')
            continue
            
        file_has_error = False
        for i, jline in enumerate(jsonl_lines):
            total_jsonl += 1
            try:
                data = json.loads(jline)
                rule_uid = data.get('metadata', {}).get('rule_uid')
                if not rule_uid:
                    errors.append(f'{category}/{filename} (JSONL Line {i+1}): Missing rule_uid in metadata.')
                    file_has_error = True
                elif rule_uid not in ocsf_ids:
                    errors.append(f'{category}/{filename} (JSONL Line {i+1}): rule_uid \'{rule_uid}\' does not match any OCSF ID in the file {ocsf_ids}.')
                    file_has_error = True
            except json.JSONDecodeError:
                errors.append(f'{category}/{filename} (JSONL Line {i+1}): Invalid JSON.')
                file_has_error = True
                
        if not file_has_error:
            passed_files += 1

if errors:
    print('Validation Failed! Errors found:')
    for e in errors: print(e)
else:
    print(f'Validation Passed! Scanned {total_files} files and verified {total_jsonl} JSONL payloads. All rule_uid mappings are mathematically perfect.')
print(f'Passed files: {passed_files}')
