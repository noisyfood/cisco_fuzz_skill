#!/usr/bin/env python3
"""Conservative live-device baseline/replay executor for TCP/UDP protocols.

This is not a fuzzer. It replays seed files at low rate after the skill
preflight has approved a live Cisco campaign, or in explicit lab mode.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import socket
import sys
import time
from ipaddress import ip_address
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from campaign_preflight import get_path, validate_manifest


def now() -> float:
    return time.time()


def load_seeds(seed_dir: Path) -> list[tuple[str, bytes]]:
    seeds: list[tuple[str, bytes]] = []
    for path in sorted(seed_dir.iterdir()):
        if not path.is_file():
            continue
        data = path.read_bytes()
        if data:
            seeds.append((path.name, data))
    if not seeds:
        raise SystemExit(f"no non-empty seed files in {seed_dir}")
    return seeds


def send_tcp(host: str, port: int, payload: bytes, timeout: float) -> tuple[str, bytes, float]:
    start = now()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(payload)
            try:
                response = sock.recv(65535)
                return "response", response, now() - start
            except socket.timeout:
                return "timeout_after_send", b"", now() - start
    except socket.timeout:
        return "connect_timeout", b"", now() - start
    except ConnectionResetError:
        return "connection_reset", b"", now() - start
    except ConnectionRefusedError:
        return "connection_refused", b"", now() - start
    except OSError as exc:
        return f"oserror:{exc.__class__.__name__}", str(exc).encode(), now() - start


def send_udp(host: str, port: int, payload: bytes, timeout: float) -> tuple[str, bytes, float]:
    start = now()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        try:
            sock.sendto(payload, (host, port))
            response, _ = sock.recvfrom(65535)
            return "response", response, now() - start
        except socket.timeout:
            return "timeout", b"", now() - start
        except OSError as exc:
            return f"oserror:{exc.__class__.__name__}", str(exc).encode(), now() - start


def classify(response: bytes) -> dict[str, object]:
    return {
        "response_len": len(response),
        "response_sha256_16": hashlib.sha256(response).hexdigest()[:16] if response else "",
        "response_prefix_hex": response[:32].hex(),
    }


def write_jsonl(path: Path, obj: dict[str, object]) -> None:
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(obj, sort_keys=True) + "\n")


def resolve_existing(path: Path) -> Path:
    return path.expanduser().resolve()


def host_is_loopback(host: str) -> bool:
    try:
        return ip_address(host).is_loopback
    except ValueError:
        return host in {"localhost", "ip6-localhost"}


def host_is_private_or_loopback(host: str) -> bool:
    try:
        addr = ip_address(host)
    except ValueError:
        return host in {"localhost", "ip6-localhost"}
    return addr.is_loopback or addr.is_private


def allowed_port_matches(entry: object, proto: str, port: int) -> bool:
    proto = proto.lower()
    port_text = str(port)
    if isinstance(entry, str):
        normalized = entry.strip().lower().replace(" ", "")
        return normalized in {
            f"{proto}/{port_text}",
            f"{port_text}/{proto}",
            f"{proto}:{port_text}",
            f"{port_text}:{proto}",
        }
    if isinstance(entry, dict):
        entry_proto = str(entry.get("proto") or entry.get("protocol") or "").lower()
        entry_port = str(entry.get("port") or "")
        return entry_proto == proto and entry_port == port_text
    return False


def validate_live_manifest(manifest_path: Path, args: argparse.Namespace) -> dict[str, object]:
    manifest_obj = json.loads(manifest_path.read_text(encoding="utf-8"))
    missing = validate_manifest(manifest_obj)
    if missing:
        raise SystemExit("campaign manifest failed preflight validation: " + ", ".join(missing))
    if manifest_obj.get("campaign_type") != "cisco_live":
        raise SystemExit("--campaign-manifest must have campaign_type=cisco_live")

    manifest_host = str(get_path(manifest_obj, "device.ip_or_hostname"))
    if manifest_host != args.target_host:
        raise SystemExit(f"target host {args.target_host!r} does not match manifest device {manifest_host!r}")

    allowed_ports = get_path(manifest_obj, "device.allowed_ports_protocols")
    if not isinstance(allowed_ports, list) or not any(allowed_port_matches(entry, args.proto, args.port) for entry in allowed_ports):
        raise SystemExit(f"{args.proto}/{args.port} is not listed in manifest device.allowed_ports_protocols")

    max_cases = get_path(manifest_obj, "live_safety.max_first_contact_cases")
    if not isinstance(max_cases, (int, float)) or args.cases > int(max_cases):
        raise SystemExit(f"--cases {args.cases} exceeds manifest live_safety.max_first_contact_cases {max_cases}")

    manifest_baseline = Path(str(get_path(manifest_obj, "live_safety.baseline_seed_dir")))
    if resolve_existing(manifest_baseline) != resolve_existing(args.baseline_seed_dir):
        raise SystemExit(
            "--baseline-seed-dir does not match manifest live_safety.baseline_seed_dir "
            f"({args.baseline_seed_dir} != {manifest_baseline})"
        )

    manifest_seeds = Path(str(get_path(manifest_obj, "live_safety.fuzz_seed_dir")))
    if resolve_existing(manifest_seeds) != resolve_existing(args.seed_dir):
        raise SystemExit(
            "--seed-dir does not match manifest live_safety.fuzz_seed_dir "
            f"({args.seed_dir} != {manifest_seeds})"
        )

    return manifest_obj


def run_baseline(
    baseline_seeds: list[tuple[str, bytes]],
    sender,
    host: str,
    port: int,
    timeout: float,
    out_dir: Path,
) -> set[str]:
    statuses: set[str] = set()
    baseline_path = out_dir / "baseline.jsonl"
    responses_dir = out_dir / "baseline_responses"
    responses_dir.mkdir(exist_ok=True)
    for idx, (seed_name, payload) in enumerate(baseline_seeds):
        status, response, elapsed = sender(host, port, payload, timeout)
        response_path = responses_dir / f"{idx:06d}.bin"
        response_path.write_bytes(response)
        record: dict[str, object] = {
            "baseline_id": f"{idx:06d}",
            "seed": seed_name,
            "payload_len": len(payload),
            "payload_sha256": hashlib.sha256(payload).hexdigest(),
            "status": status,
            "elapsed": round(elapsed, 6),
            "response_path": str(response_path),
        }
        record.update(classify(response))
        write_jsonl(baseline_path, record)
        statuses.add(status)
    return statuses


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--campaign-manifest",
        type=Path,
        help="validated cisco_live campaign manifest; required unless --lab-mode is set",
    )
    parser.add_argument(
        "--lab-mode",
        action="store_true",
        help="allow loopback validation without a cisco_live campaign manifest",
    )
    parser.add_argument(
        "--allow-lab-network",
        action="store_true",
        help="with --lab-mode, allow RFC1918/private lab addresses; never use for real Cisco campaigns",
    )
    parser.add_argument(
        "--allow-extended-campaign",
        action="store_true",
        help="allow more than 10 cases; only for explicitly approved lab campaigns",
    )
    parser.add_argument("--target-host", required=True)
    parser.add_argument("--port", required=True, type=int)
    parser.add_argument("--proto", choices=["tcp", "udp"], required=True)
    parser.add_argument("--seed-dir", required=True, type=Path)
    parser.add_argument("--baseline-seed-dir", type=Path, required=True)
    parser.add_argument("--out-dir", required=True, type=Path)
    parser.add_argument("--cases", type=int, default=5, help="maximum seed files to replay from --seed-dir")
    parser.add_argument("--delay", type=float, default=0.25)
    parser.add_argument("--timeout", type=float, default=2.0)
    parser.add_argument("--stop-on-timeout", action="store_true")
    parser.add_argument("--stop-on-reset", action="store_true")
    parser.add_argument("--health-probe-note", required=True, help="approved health probes to run around this campaign")
    parser.add_argument("--stop-condition-note", required=True, help="approved campaign stop conditions")
    args = parser.parse_args()

    if args.cases < 1:
        raise SystemExit("--cases must be at least 1")
    if args.cases > 10 and not args.allow_extended_campaign:
        raise SystemExit("--cases > 10 requires --allow-extended-campaign")
    if args.lab_mode:
        if not args.allow_lab_network and not host_is_loopback(args.target_host):
            raise SystemExit("--lab-mode without --allow-lab-network only permits loopback targets")
        if args.allow_lab_network and not host_is_private_or_loopback(args.target_host):
            raise SystemExit("--allow-lab-network only permits loopback or private lab addresses")
    if not args.lab_mode:
        if not args.campaign_manifest:
            raise SystemExit("--campaign-manifest is required unless --lab-mode is set")
        manifest_obj = validate_live_manifest(args.campaign_manifest, args)
        authorization = manifest_obj.get("authorization", {})
        required_auth = [
            "user_authorized_campaign",
            "no_state_changing_ops_without_explicit_approval",
            "no_shell_without_explicit_approval",
            "no_debugger_without_explicit_approval",
        ]
        missing_auth = [name for name in required_auth if authorization.get(name) is not True]
        if missing_auth:
            raise SystemExit(f"campaign manifest authorization is incomplete: {', '.join(missing_auth)}")

    args.out_dir.mkdir(parents=True, exist_ok=True)
    cases_dir = args.out_dir / "cases"
    responses_dir = args.out_dir / "responses"
    cases_dir.mkdir(exist_ok=True)
    responses_dir.mkdir(exist_ok=True)

    seeds = load_seeds(args.seed_dir)
    run_manifest = {
        "campaign_manifest": str(args.campaign_manifest) if args.campaign_manifest else None,
        "lab_mode": args.lab_mode,
        "target_host": args.target_host,
        "port": args.port,
        "proto": args.proto,
        "seed_dir": str(args.seed_dir),
        "baseline_seed_dir": str(args.baseline_seed_dir) if args.baseline_seed_dir else None,
        "cases": args.cases,
        "delay": args.delay,
        "timeout": args.timeout,
        "health_probe_note": args.health_probe_note,
        "stop_condition_note": args.stop_condition_note,
        "mode": "seed_replay",
        "started_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
    }
    (args.out_dir / "run_manifest.json").write_text(json.dumps(run_manifest, indent=2, sort_keys=True) + "\n")

    results_path = args.out_dir / "results.jsonl"
    anomalies_path = args.out_dir / "anomalies.jsonl"
    sender = send_tcp if args.proto == "tcp" else send_udp

    baseline_statuses = run_baseline(
        load_seeds(args.baseline_seed_dir),
        sender,
        args.target_host,
        args.port,
        args.timeout,
        args.out_dir,
    )
    if not baseline_statuses:
        raise SystemExit("baseline seed run produced no statuses")

    for idx, (seed_name, payload) in enumerate(seeds[: args.cases]):
        case_id = f"{idx:06d}"
        case_path = cases_dir / f"{case_id}.bin"
        case_path.write_bytes(payload)

        status, response, elapsed = sender(args.target_host, args.port, payload, args.timeout)
        response_path = responses_dir / f"{case_id}.bin"
        response_path.write_bytes(response)

        record: dict[str, object] = {
            "case_id": case_id,
            "seed": seed_name,
            "payload_len": len(payload),
            "payload_sha256": hashlib.sha256(payload).hexdigest(),
            "status": status,
            "elapsed": round(elapsed, 6),
            "case_path": str(case_path),
            "response_path": str(response_path),
            "replay_source": seed_name,
        }
        record.update(classify(response))
        write_jsonl(results_path, record)

        anomaly = False
        reason = ""
        if status not in baseline_statuses:
            anomaly = True
            reason = "new_status_class"
        if args.stop_on_timeout and "timeout" in status:
            anomaly = True
            reason = reason or "timeout"
        if args.stop_on_reset and "reset" in status:
            anomaly = True
            reason = reason or "reset"

        if anomaly:
            record["anomaly_reason"] = reason
            write_jsonl(anomalies_path, record)
            print(f"stopping on anomaly case={case_id} reason={reason} status={status}", flush=True)
            return 2

        print(f"{case_id} {status} len={len(response)} elapsed={elapsed:.3f}s", flush=True)
        time.sleep(args.delay)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
