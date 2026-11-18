import json

with open('PROJECT_CREDENTIAL_AUDIT/raw_findings.json', 'r', encoding='utf-8') as f:
    data = json.load(f)

for r in data['regex_secrets']:
    f = r['file']
    if f.startswith('backend/') or f.startswith('frontend/'):
        print(f"{f}:{r['line']} [{r['pattern']}] -> {r['content']}")

