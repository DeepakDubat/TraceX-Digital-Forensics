#!/usr/bin/env python3
"""
TraceX PKI Provisioning Utility
Universal Digital Forensics & Evidence Intelligence Platform v2.0.0

Generates mutual TLS (mTLS) Root CA, Host Agent Server Certificate,
and Manager VM Client Certificate in the specified output directory.
"""

import sys
import argparse
from pathlib import Path

# Add project root to sys.path
project_root = Path(__file__).resolve().parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from backend.app.analyzers.dynamic.pki_manager import pki_manager


def main():
    parser = argparse.ArgumentParser(description="Generate TraceX mTLS certificates")
    parser.add_argument(
        "--output-dir",
        "-o",
        default="C:/ProgramData/TraceX/HostAgent/certs",
        help="Target directory to write PEM certificates and keys"
    )
    args = parser.parse_args()

    out_path = Path(args.output_dir)
    print(f"[*] Generating TraceX mTLS PKI bundle in: {out_path}")
    bundle = pki_manager.generate_full_pki_bundle(out_path)

    for name, filepath in bundle.items():
        print(f"  [+] {name}: {filepath} ({filepath.stat().st_size} bytes)")

    print("[+] PKI generation complete.")


if __name__ == "__main__":
    main()

