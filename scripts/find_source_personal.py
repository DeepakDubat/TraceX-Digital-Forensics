import json

with open('PROJECT_CREDENTIAL_AUDIT/raw_findings.json', 'r', encoding='utf-8') as f:
    data = json.load(f)

for p in data['personal_data']:
    f = p['file']
    # exclude reports/ and PROJECT_PHASE* and BROWSER_* and FINAL_*
    if f.startswith('reports/') or f.startswith('PROJECT_') or f.startswith('BROWSER_') or f.startswith('FINAL_'):
        continue
    print(f"{f}:{p['line']} -> {p['content']}")

