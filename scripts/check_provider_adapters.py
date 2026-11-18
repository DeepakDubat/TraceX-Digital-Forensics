import os
import re

pdir = "backend/app/integrations/osint/providers"
for f in os.listdir(pdir):
    if f.endswith(".py"):
        path = os.path.join(pdir, f)
        with open(path, "r", encoding="utf-8") as fp:
            content = fp.read()
        matches = re.findall(r"(is_configured|_get_api_key|test_connection)", content)
        if matches:
            print(f"{f}: {set(matches)}")

