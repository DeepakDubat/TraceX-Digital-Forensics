import json
from collections import defaultdict

with open('PROJECT_CREDENTIAL_AUDIT/raw_findings.json', 'r', encoding='utf-8') as f:
    data = json.load(f)

print("=== KNOWN SECRETS ===")
for s in data['known_secrets']:
    print(f"{s['file']}:{s['line']} -> {s['content']}")

print("\n=== PERSONAL DATA BREAKDOWN ===")
files_with_personal = defaultdict(list)
for p in data['personal_data']:
    files_with_personal[p['file']].append(p)

for f, items in sorted(files_with_personal.items(), key=lambda x: -len(x[1])):
    print(f"\n[ {f} ] ({len(items)} hits):")
    for it in items[:5]:
        print(f"  Line {it['line']}: {it['content']}")

print("\n=== PROVIDERS DETECTED ===")
for prov, occs in sorted(data['provider_occurrences'].items()):
    if occs:
        print(f"Provider: {prov} ({len(occs)} files)")
        for o in occs[:3]:
            print(f"  - {o['file']}")

print("\n=== REGEX POTENTIAL SECRETS (SAMPLE) ===")
# Filter out docstrings / tests / schema
filtered_regex = []
for r in data['regex_secrets']:
    f = r['file']
    if any(ignore in f for ignore in ['PROJECT_PHASE', 'tests/', 'rules/', 'PROJECT_ANALYSIS', 'PROJECT_REMEDIATION']):
        continue
    filtered_regex.append(r)

print(f"Filtered candidate secrets in core code/configs: {len(filtered_regex)}")
for r in filtered_regex[:20]:
    print(f"{r['file']}:{r['line']} [{r['pattern']}] -> {r['content']}")

