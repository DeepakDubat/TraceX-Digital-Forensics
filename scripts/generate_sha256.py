import hashlib
from pathlib import Path

for target_dir in [Path("dist"), Path("release")]:
    if not target_dir.exists():
        continue
    artifacts = sorted([
        f for f in target_dir.iterdir()
        if f.is_file() and f.name not in ("SHA256SUMS.txt", "release_manifest.json")
    ])
    lines = []
    for art in artifacts:
        h = hashlib.sha256(art.read_bytes()).hexdigest().upper()
        lines.append(f"{h}  {art.name}")
        print(f"[{target_dir.name}] {art.name}: {h}")
    sha_path = target_dir / "SHA256SUMS.txt"
    sha_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"Updated {sha_path}")

