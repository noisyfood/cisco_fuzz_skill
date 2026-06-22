#!/usr/bin/env python3
"""Validate live Cisco driver arguments against a campaign manifest before traffic."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from live_probe_executor import validate_live_manifest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--campaign-manifest", required=True, type=Path)
    parser.add_argument("--target-host", required=True)
    parser.add_argument("--port", required=True, type=int)
    parser.add_argument("--proto", choices=["tcp", "udp"], required=True)
    parser.add_argument("--seed-dir", required=True, type=Path)
    parser.add_argument("--baseline-seed-dir", required=True, type=Path)
    parser.add_argument("--cases", required=True, type=int)
    parser.add_argument("--print-summary", action="store_true")
    args = parser.parse_args()

    manifest = validate_live_manifest(args.campaign_manifest, args)
    if args.print_summary:
        print(
            json.dumps(
                {
                    "ok": True,
                    "campaign_manifest": str(args.campaign_manifest),
                    "campaign_type": manifest.get("campaign_type"),
                    "target_host": args.target_host,
                    "proto": args.proto,
                    "port": args.port,
                    "seed_dir": str(args.seed_dir),
                    "baseline_seed_dir": str(args.baseline_seed_dir),
                    "cases": args.cases,
                },
                indent=2,
                sort_keys=True,
            )
        )
    else:
        print("live driver gate ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
