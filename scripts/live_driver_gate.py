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

from campaign_preflight import get_live_profile, get_path
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
    parser.add_argument("--mode", default="seed_replay", help="driver mode that will run after this gate")
    parser.add_argument(
        "--destructive-action",
        action="append",
        default=[],
        help="destructive action this run may perform; repeat for multiple actions",
    )
    parser.add_argument("--print-summary", action="store_true")
    args = parser.parse_args()

    manifest = validate_live_manifest(args.campaign_manifest, args)
    live_profile = get_live_profile(manifest)
    requested_actions = args.destructive_action or []
    if requested_actions:
        if live_profile != "destructive_lab":
            raise SystemExit("--destructive-action requires live_profile=destructive_lab")
        allowed_actions = get_path(manifest, "destructive_lab.allowed_destructive_actions")
        if not isinstance(allowed_actions, list):
            raise SystemExit("destructive_lab.allowed_destructive_actions must be a list")
        allowed = {str(action) for action in allowed_actions}
        unknown = [action for action in requested_actions if action not in allowed]
        if unknown:
            raise SystemExit(
                "requested destructive action is not allowed by manifest: " + ", ".join(sorted(set(unknown)))
            )
        if get_path(manifest, "destructive_lab.destructive_actions_authorized") is not True:
            raise SystemExit("destructive_lab.destructive_actions_authorized must be true")

    if args.print_summary:
        print(
            json.dumps(
                {
                    "ok": True,
                    "campaign_manifest": str(args.campaign_manifest),
                    "campaign_type": manifest.get("campaign_type"),
                    "live_profile": live_profile,
                    "target_host": args.target_host,
                    "proto": args.proto,
                    "port": args.port,
                    "mode": args.mode,
                    "destructive_actions": requested_actions,
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
