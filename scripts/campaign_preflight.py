#!/usr/bin/env python3
"""Validate a Cisco fuzzing campaign manifest before any target interaction."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


VALID_TYPES = {"local_training", "cisco_offline", "cisco_live"}
OFFLINE_TARGET_KINDS = {"binary_only", "source_harness", "analysis_only"}


COMMON_REQUIRED = [
    "campaign_type",
    "output.campaign_dir",
]

LOCAL_REQUIRED = [
    "local_training.target.path",
    "local_training.target.input_format",
    "local_training.target.reproducer_template",
    "local_training.allowed_dependency_installs",
    "local_training.instrumentation_mode",
    "local_training.initial_seed_dir",
    "authorization.user_authorized_campaign",
]

CISCO_OFFLINE_REQUIRED = [
    "device.ip_or_hostname",
    "device.allowed_interfaces_or_vrf",
    "device.allowed_ports_protocols",
    "device.credentials_policy",
    "device.safety_scope",
    "shell_debug.shell_available",
    "shell_debug.access_method",
    "shell_debug.gdbserver_allowed",
    "shell_debug.core_collection_allowed",
    "offline_execution.target_kind",
    "reverse_engineering.firmware_or_extraction_root",
    "reverse_engineering.main_binaries",
    "reverse_engineering.ida_mcp_available",
    "reverse_engineering.symbols_or_base_addresses",
    "authorization.user_authorized_campaign",
]

BINARY_ONLY_REQUIRED = [
    "offline_execution.target_elf",
    "offline_execution.architecture",
    "offline_execution.loader",
    "offline_execution.library_root",
    "offline_execution.required_env",
    "offline_execution.license_or_authorization",
    "offline_execution.qemu_helper",
    "offline_execution.qemu_helper_arch",
]

CISCO_LIVE_REQUIRED = [
    "device.ip_or_hostname",
    "device.allowed_interfaces_or_vrf",
    "device.allowed_ports_protocols",
    "device.credentials_policy",
    "device.safety_scope",
    "shell_debug.shell_available",
    "shell_debug.access_method",
    "shell_debug.gdbserver_allowed",
    "shell_debug.core_collection_allowed",
    "shell_debug.privileged_actions_require_human_approval",
    "reverse_engineering.firmware_or_extraction_root",
    "reverse_engineering.main_binaries",
    "reverse_engineering.ida_mcp_available",
    "reverse_engineering.symbols_or_base_addresses",
    "recovery.maintenance_window",
    "recovery.oob_console",
    "recovery.reload_or_power_authority",
    "recovery.config_backup_status",
    "recovery.recovery_owner",
    "live_safety.baseline_seed_dir",
    "live_safety.fuzz_seed_dir",
    "live_safety.health_probe_plan",
    "live_safety.stop_conditions",
    "live_safety.max_first_contact_cases",
    "authorization.user_authorized_campaign",
    "authorization.no_state_changing_ops_without_explicit_approval",
    "authorization.no_shell_without_explicit_approval",
    "authorization.no_debugger_without_explicit_approval",
]


def get_path(obj: dict[str, Any], dotted: str) -> Any:
    cur: Any = obj
    for part in dotted.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


def is_filled(value: Any) -> bool:
    if value is None:
        return False
    if isinstance(value, str):
        return bool(value.strip()) and value.strip().upper() not in {"TODO", "REQUIRED", "UNKNOWN"}
    if isinstance(value, (list, dict)):
        return bool(value)
    if isinstance(value, bool):
        return value is True
    if isinstance(value, (int, float)):
        return value > 0
    return True


def validate_required(manifest: dict[str, Any], fields: list[str]) -> list[str]:
    return [field for field in fields if not is_filled(get_path(manifest, field))]


def normalize_arch(value: Any) -> str:
    arch = str(value or "").strip().lower().replace("-", "_")
    arch = arch.replace(" ", "")
    aliases = {
        "amd64": "x86_64",
        "x64": "x86_64",
        "x86_64": "x86_64",
        "x8664": "x86_64",
        "i386": "i386",
        "i486": "i386",
        "i586": "i386",
        "i686": "i386",
        "x86": "i386",
        "aarch64": "aarch64",
        "arm64": "aarch64",
        "arm": "arm",
        "armhf": "arm",
        "mips": "mips",
        "mipsel": "mipsel",
        "mips64": "mips64",
        "mips64el": "mips64el",
    }
    return aliases.get(arch, arch)


def validate_fuzzer_mode(manifest: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    mode = str(get_path(manifest, "fuzzer.mode") or get_path(manifest, "local_training.fuzzer_mode") or "")
    lower = mode.lower()
    if not is_filled(mode):
        errors.append("fuzzer.mode must name pylibafl or Rust LibAFL as the campaign fuzzer")
        return errors
    if "afl-fuzz" in lower:
        errors.append("fuzzer.mode must not select afl-fuzz; use pylibafl or Rust LibAFL")
    if "pylibafl" not in lower and "libafl" not in lower:
        errors.append("fuzzer.mode must name pylibafl or Rust LibAFL as the campaign fuzzer")
    if "live_probe_executor" in lower or "local_cli_mutation_fuzzer" in lower:
        errors.append("fuzzer.mode must not select smoke/probe helpers as the campaign fuzzer")
    return errors


def validate_binary_only(manifest: dict[str, Any]) -> list[str]:
    errors = validate_required(manifest, BINARY_ONLY_REQUIRED)
    target_arch = normalize_arch(get_path(manifest, "offline_execution.architecture"))
    qemu_arch = normalize_arch(get_path(manifest, "offline_execution.qemu_helper_arch"))
    sanitizer_arch = normalize_arch(get_path(manifest, "offline_execution.sanitizer_helper_arch"))

    if target_arch and qemu_arch and target_arch != qemu_arch:
        errors.append("offline_execution.qemu_helper_arch must match offline_execution.architecture")

    sanitizer_helper_raw = str(get_path(manifest, "offline_execution.sanitizer_helper") or "").strip()
    sanitizer_helper = sanitizer_helper_raw.lower()
    if sanitizer_helper not in {"", "none", "unavailable", "not_applicable", "not applicable"}:
        if not is_filled(get_path(manifest, "offline_execution.sanitizer_helper_arch")):
            errors.append("offline_execution.sanitizer_helper_arch is required when sanitizer_helper is set")
        elif target_arch and sanitizer_arch and target_arch != sanitizer_arch:
            errors.append("offline_execution.sanitizer_helper_arch must match offline_execution.architecture")

    persistent_mode = str(get_path(manifest, "offline_execution.persistent_mode") or "").strip().lower()
    if persistent_mode in {"yes", "true", "enabled", "required"}:
        errors.extend(
            validate_required(
                manifest,
                [
                    "offline_execution.persistent_loop_address",
                    "offline_execution.persistent_address_provenance",
                    "offline_execution.persistent_stability_plan",
                ],
            )
        )
    return errors


def validate_manifest(manifest: dict[str, Any]) -> list[str]:
    missing = validate_required(manifest, COMMON_REQUIRED)
    missing.extend(validate_fuzzer_mode(manifest))
    campaign_type = get_path(manifest, "campaign_type")
    if campaign_type not in VALID_TYPES:
        missing.append("campaign_type must be one of: " + ", ".join(sorted(VALID_TYPES)))
        return missing

    if campaign_type == "local_training":
        missing.extend(validate_required(manifest, LOCAL_REQUIRED))
    elif campaign_type == "cisco_offline":
        missing.extend(validate_required(manifest, CISCO_OFFLINE_REQUIRED))
        target_kind = str(get_path(manifest, "offline_execution.target_kind") or "").strip().lower()
        if target_kind and target_kind not in OFFLINE_TARGET_KINDS:
            missing.append("offline_execution.target_kind must be binary_only, source_harness, or analysis_only")
        elif target_kind == "binary_only":
            missing.extend(validate_binary_only(manifest))
    elif campaign_type == "cisco_live":
        missing.extend(validate_required(manifest, CISCO_LIVE_REQUIRED))
        first_contact = get_path(manifest, "live_safety.max_first_contact_cases")
        if isinstance(first_contact, (int, float)) and first_contact > 10:
            missing.append("live_safety.max_first_contact_cases must be <= 10 for first contact")

    return missing


def resolve_from_workspace(path_text: str, workspace: Path) -> Path:
    path = Path(path_text).expanduser()
    if not path.is_absolute():
        path = workspace / path
    return path.resolve()


def is_under(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def has_nonempty_file(path: Path) -> bool:
    return any(child.is_file() and child.stat().st_size > 0 for child in path.iterdir())


def validate_paths(manifest: dict[str, Any], workspace: Path, create_dirs: bool) -> list[str]:
    errors: list[str] = []

    campaign_dir = resolve_from_workspace(str(get_path(manifest, "output.campaign_dir")), workspace)
    if not is_under(campaign_dir, workspace):
        errors.append("output.campaign_dir must be under the current workspace")
    if not create_dirs and not campaign_dir.is_dir():
        errors.append("output.campaign_dir must exist unless --create-dirs is used")

    campaign_type = get_path(manifest, "campaign_type")
    if campaign_type == "local_training":
        target_kind = str(get_path(manifest, "local_training.target.kind") or "existing_file")
        target = resolve_from_workspace(str(get_path(manifest, "local_training.target.path")), workspace)
        if target_kind in {"existing_file", "existing_binary"}:
            if not target.is_file():
                errors.append("local_training.target.path must be an existing file")
        elif target_kind in {"source_build", "planned_harness"}:
            source_path_text = get_path(manifest, "local_training.target.source_path")
            if not is_filled(source_path_text):
                errors.append("local_training.target.source_path is required for source_build/planned_harness")
            else:
                source_path = resolve_from_workspace(str(source_path_text), workspace)
                if not is_under(source_path, workspace):
                    errors.append("local_training.target.source_path must be under the current workspace")
                elif not source_path.exists():
                    errors.append("local_training.target.source_path must exist for source_build/planned_harness")
            build_output_text = get_path(manifest, "local_training.target.build_output") or get_path(
                manifest, "local_training.target.path"
            )
            build_output = resolve_from_workspace(str(build_output_text), workspace)
            if not is_under(build_output, campaign_dir):
                errors.append("local_training.target.build_output must be under output.campaign_dir")
        else:
            errors.append("local_training.target.kind must be existing_file, existing_binary, source_build, or planned_harness")

        seed_dir = resolve_from_workspace(str(get_path(manifest, "local_training.initial_seed_dir")), workspace)
        if not is_under(seed_dir, workspace):
            errors.append("local_training.initial_seed_dir must be under the current workspace")
        elif not seed_dir.is_dir():
            errors.append("local_training.initial_seed_dir must be an existing directory")
        elif not has_nonempty_file(seed_dir):
            errors.append("local_training.initial_seed_dir must contain at least one non-empty seed file")

    if campaign_type == "cisco_live":
        for field in ("live_safety.baseline_seed_dir", "live_safety.fuzz_seed_dir"):
            seed_dir = resolve_from_workspace(str(get_path(manifest, field)), workspace)
            if not is_under(seed_dir, workspace):
                errors.append(f"{field} must be under the current workspace")
            elif not seed_dir.is_dir():
                errors.append(f"{field} must be an existing directory")
            elif not has_nonempty_file(seed_dir):
                errors.append(f"{field} must contain at least one non-empty seed file")

    if campaign_type == "cisco_offline":
        firmware_root = resolve_from_workspace(str(get_path(manifest, "reverse_engineering.firmware_or_extraction_root")), workspace)
        if not firmware_root.exists():
            errors.append("reverse_engineering.firmware_or_extraction_root must exist")
        target_kind = str(get_path(manifest, "offline_execution.target_kind") or "").strip().lower()
        if target_kind == "binary_only":
            target_elf = resolve_from_workspace(str(get_path(manifest, "offline_execution.target_elf")), workspace)
            if not target_elf.is_file():
                errors.append("offline_execution.target_elf must be an existing real ELF file")
            library_root = resolve_from_workspace(str(get_path(manifest, "offline_execution.library_root")), workspace)
            if not library_root.exists():
                errors.append("offline_execution.library_root must exist")
            qemu_helper_text = str(get_path(manifest, "offline_execution.qemu_helper") or "")
            if "/" in qemu_helper_text or qemu_helper_text.startswith("."):
                qemu_helper = resolve_from_workspace(qemu_helper_text, workspace)
                if not qemu_helper.is_file():
                    errors.append("offline_execution.qemu_helper must exist when given as a path")
            sanitizer_helper_raw = str(get_path(manifest, "offline_execution.sanitizer_helper") or "").strip()
            sanitizer_helper = sanitizer_helper_raw.lower()
            if sanitizer_helper not in {"", "none", "unavailable", "not_applicable", "not applicable"}:
                if "/" in sanitizer_helper_raw or sanitizer_helper_raw.startswith("."):
                    sanitizer_path = resolve_from_workspace(sanitizer_helper_raw, workspace)
                    if not sanitizer_path.is_file():
                        errors.append("offline_execution.sanitizer_helper must exist when given as a path")

    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--create-dirs", action="store_true")
    args = parser.parse_args()

    try:
        manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    except Exception as exc:
        print(f"preflight failed: cannot read manifest: {exc}", file=sys.stderr)
        return 2

    missing = validate_manifest(manifest)
    if not missing:
        missing.extend(validate_paths(manifest, Path.cwd().resolve(), args.create_dirs))
    if missing:
        print("preflight failed: required fields are missing or unapproved", file=sys.stderr)
        for item in missing:
            print(f"- {item}", file=sys.stderr)
        print("stop: do not scan, fuzz, access shell, attach debugger, or send target traffic", file=sys.stderr)
        return 2

    campaign_dir = resolve_from_workspace(str(get_path(manifest, "output.campaign_dir")), Path.cwd().resolve())
    if args.create_dirs:
        for name in [
            "seeds",
            "cases",
            "responses",
            "health",
            "anomalies",
            "crashes",
            "minimized",
            "reports",
        ]:
            (campaign_dir / name).mkdir(parents=True, exist_ok=True)

    print(f"preflight ok: {manifest['campaign_type']} campaign -> {campaign_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
