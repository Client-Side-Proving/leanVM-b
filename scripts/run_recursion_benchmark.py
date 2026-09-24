#!/usr/bin/env python3
"""Search and validate a recursive STARK aggregation configuration from a JSON query."""

from __future__ import annotations

import argparse
import ctypes
import csv
import hashlib
import json
import math
import os
import platform
import random
import statistics
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Sequence


SCHEMA_VERSION = 1
RUNNER_VERSION = 4
BOUNDARY_REPEAT_FIX_FROM_RUNNER_BLAKE2S = "01d82e9e84da738929afadd3666b093c1de78eafbfbe6ce90151bf059393d35f"
NATIVE_RUSTFLAGS = "-C target-cpu=native"
TIERS = {
    "screening": {"parent_samples": 3, "roots": 6, "fresh_runs": 1},
    "standard": {"parent_samples": 10, "roots": 30, "fresh_runs": 1},
    "publication": {"parent_samples": 10, "roots": 100, "fresh_runs": 3},
}

SCHEMA2_CANDIDATE_FIELDS = [
    "candidate_attempt_id",
    "workload_adapter",
    "tree_depth",
    "hash",
    "inputs_per_root",
    "block_period_seconds",
    "derived_average_inputs_per_second",
    "leaf_log_inv_rate",
    "required_root_log_inv_rate",
    "actual_root_log_inv_rate",
    "phase",
    "performance_workers",
    "efficiency_workers",
    "proving_processes",
    "tier",
    "completed_roots",
    "completed_inputs",
    "leaf_preparation_seconds",
    "leaf_cache_hits",
    "leaf_cache_misses",
    "max_serialized_input_to_root_seconds",
    "median_serialized_input_to_root_seconds",
    "max_root_interval_seconds_diagnostic",
    "preparation_peak_rss_bytes",
    "timed_proving_peak_rss_bytes",
    "post_run_verification_peak_rss_bytes",
    "peak_rss_bytes",
    "max_serialized_root_proof_bytes",
    "median_native_root_in_memory_verification_seconds",
    "max_native_root_in_memory_verification_seconds",
    "median_native_root_deserialization_seconds",
    "max_native_root_deserialization_seconds",
    "median_native_root_roundtrip_verification_seconds",
    "max_native_root_roundtrip_verification_seconds",
    "median_native_root_validation_seconds",
    "max_native_root_validation_seconds",
    "all_roots_verified_against_expected",
    "all_job_costs_directly_measured",
    "pass",
    "terminal_status",
    "failure_reason",
    "program_identity",
    "plan_path",
    "executed_plan_digest",
    "baseline_plan_digest",
    "parent_costs_blake2s",
    "query_sha256",
    "binary_sha256",
    "source_fingerprint",
    "runner_blake2s",
    "adapter_config_blake2s",
]

SCHEMA2_ROOT_FIELDS = [
    "candidate_id",
    "root_index",
    "status",
    "scheduled_burst_unix_seconds",
    "fixture_start_index",
    "fixture_count",
    "fixture_indices_digest",
    "expected_withdrawal_count",
    "expected_withdrawal_list_digest",
    "inputs_per_root",
    "leaf_log_inv_rate",
    "requested_root_log_inv_rate",
    "actual_root_log_inv_rate",
    "completed_roots",
    "completed_inputs",
    "burst_arrival_seconds",
    "queue_delay_seconds",
    "serialized_input_to_root_seconds",
    "serialization_seconds",
    "root_proof_ready_unix_seconds",
    "root_serialized_unix_seconds",
    "root_interval_seconds",
    "proving_and_verification_seconds",
    "native_root_in_memory_verification_seconds",
    "native_root_deserialization_seconds",
    "native_root_roundtrip_verification_seconds",
    "native_root_validation_seconds",
    "preparation_peak_rss_bytes",
    "timed_proving_peak_rss_bytes",
    "post_run_verification_peak_rss_bytes",
    "observed_peak_rss_bytes",
    "serialized_root_proof_bytes",
    "withdrawal_list_digest",
    "parse_ok",
    "in_memory_verify_ok",
    "roundtrip_verify_ok",
    "error",
    "executed_plan_digest",
    "baseline_plan_digest",
]

SCHEMA2_CAPACITY_FIELDS = [
    "stable_tuple_id",
    "workload_adapter",
    "workload_adapter_schema_version",
    "adapter_config_digest",
    "program_identity",
    "role",
    "measurement_phases",
    "arity",
    "child_log_inv_rate",
    "parent_log_inv_rate",
    "performance_workers",
    "workload_shape_fingerprint",
    "ordered_child_claim_counts",
    "child_shapes",
    "parent_shape",
    "sample_count",
    "median_service_seconds",
    "maximum_rss_bytes",
    "output_bytes",
    "directly_measured",
    "workload_case_ids",
    "workload_case_blake2s",
]


class RamLimitExceeded(RuntimeError):
    def __init__(self, peak_rss_bytes: int):
        super().__init__(f"prover RAM limit exceeded at {peak_rss_bytes} bytes")
        self.peak_rss_bytes = peak_rss_bytes


NATIVE_ROOT_TIMING_FIELDS = (
    ("in_memory_verification", "native_in_memory_verification_seconds"),
    ("deserialization", "native_deserialization_seconds"),
    ("roundtrip_verification", "native_roundtrip_verification_seconds"),
    ("validation", "native_validation_seconds"),
)


def summarize_native_root_timings(roots: Sequence[dict[str, Any]]) -> dict[str, float | None]:
    """Summarize each separately timed native root-validation operation."""
    summary: dict[str, float | None] = {}
    for label, source_field in NATIVE_ROOT_TIMING_FIELDS:
        values = [float(root[source_field]) for root in roots if root.get(source_field) is not None]
        summary[f"median_native_root_{label}_seconds"] = statistics.median(values) if values else None
        summary[f"max_native_root_{label}_seconds"] = max(values, default=None)
    return summary


def native_root_timing_fields(root: dict[str, Any]) -> dict[str, Any]:
    """Map adapter timing names to the root artifact schema."""
    return {
        f"native_root_{label}_seconds": root.get(source_field)
        for label, source_field in NATIVE_ROOT_TIMING_FIELDS
    }


def percentile_nearest_rank(values: Sequence[float], fraction: float) -> float:
    """Return the nearest-rank percentile used by the benchmark report."""
    if not values:
        raise ValueError("a percentile needs at least one value")
    if not 0 < fraction <= 1:
        raise ValueError("percentile fraction must be in (0, 1]")
    ordered = sorted(values)
    rank = max(1, math.ceil(len(ordered) * fraction))
    return ordered[rank - 1]


def root_grouped_percentile_upper_bound(
    root_groups: Sequence[Sequence[float]],
    fraction: float = 0.99,
    confidence: float = 0.95,
    samples: int = 2_000,
    seed: int = 0x524F_4F54,
) -> float:
    """Bootstrap a percentile while keeping all input latencies from one root together."""
    groups = [list(group) for group in root_groups if group]
    if not groups:
        raise ValueError("a grouped confidence bound needs at least one nonempty root")
    rng = random.Random(seed)
    estimates = []
    for _ in range(samples):
        selected = [groups[rng.randrange(len(groups))] for _ in groups]
        values = [value for group in selected for value in group]
        estimates.append(percentile_nearest_rank(values, fraction))
    return percentile_nearest_rank(estimates, confidence)


def linear_slope(points: Sequence[tuple[float, float]]) -> float:
    if len(points) < 2:
        return 0.0
    x_mean = statistics.fmean(point[0] for point in points)
    y_mean = statistics.fmean(point[1] for point in points)
    denominator = sum((x - x_mean) ** 2 for x, _ in points)
    if denominator == 0:
        return 0.0
    return sum((x - x_mean) * (y - y_mean) for x, y in points) / denominator


def backlog_slope_interval(
    points: Sequence[tuple[float, float]],
    warmup_fraction: float = 0.20,
    confidence: float = 0.95,
    samples: int = 1_000,
    seed: int = 0x4241_434B,
) -> dict[str, float]:
    """Estimate backlog growth and a moving-block bootstrap confidence interval."""
    if len(points) < 4:
        return {
            "slope_inputs_per_second": 0.0,
            "lower_confidence_bound": 0.0,
            "upper_confidence_bound": 0.0,
            "warmup_seconds": 0.0,
            "observation_seconds": 0.0,
        }
    ordered = sorted(points)
    start = ordered[0][0]
    end = ordered[-1][0]
    warmup_seconds = (end - start) * warmup_fraction
    observed = [(x, y) for x, y in ordered if x >= start + warmup_seconds]
    if len(observed) < 4:
        observed = ordered
        warmup_seconds = 0.0
    slope = linear_slope(observed)
    fitted_origin = statistics.fmean(y - slope * x for x, y in observed)
    residuals = [y - (fitted_origin + slope * x) for x, y in observed]
    block = max(2, round(math.sqrt(len(residuals))))
    rng = random.Random(seed)
    bootstrapped = []
    for _ in range(samples):
        sample_residuals = []
        while len(sample_residuals) < len(residuals):
            block_start = rng.randrange(len(residuals))
            for offset in range(block):
                sample_residuals.append(residuals[(block_start + offset) % len(residuals)])
                if len(sample_residuals) == len(residuals):
                    break
        synthetic = [
            (point[0], fitted_origin + slope * point[0] + residual)
            for point, residual in zip(observed, sample_residuals)
        ]
        bootstrapped.append(linear_slope(synthetic))
    alpha = 1.0 - confidence
    return {
        "slope_inputs_per_second": slope,
        "lower_confidence_bound": percentile_nearest_rank(bootstrapped, alpha / 2),
        "upper_confidence_bound": percentile_nearest_rank(bootstrapped, 1 - alpha / 2),
        "warmup_seconds": warmup_seconds,
        "observation_seconds": observed[-1][0] - observed[0][0],
    }


def overload_recovery(points: Sequence[tuple[float, float]], phases: Sequence[dict[str, Any]]) -> dict[str, Any] | None:
    phase_start = 0.0
    overloads = []
    for phase in phases:
        phase_end = phase_start + float(phase["duration_seconds"])
        if float(phase["rate_multiplier"]) > 1.0:
            overloads.append((phase_start, phase_end))
        phase_start = phase_end
    if not overloads or not points:
        return None
    overload_start, recovery_start = overloads[-1]
    baseline = next((value for seconds, value in reversed(points) if seconds <= overload_start), 0.0)
    recovered_at = next(
        (seconds for seconds, value in points if seconds >= recovery_start and value <= baseline),
        None,
    )
    return {
        "overload_start_seconds": overload_start,
        "recovery_start_seconds": recovery_start,
        "baseline_backlog_inputs": baseline,
        "recovered": recovered_at is not None,
        "recovery_seconds": None if recovered_at is None else recovered_at - recovery_start,
    }


def process_rss_bytes(processes: Sequence[subprocess.Popen[str]]) -> int:
    live = [process for process in processes if process.poll() is None]
    if not live:
        return 0
    if sys.platform.startswith("linux"):
        page_size = os.sysconf("SC_PAGE_SIZE")
        total = 0
        for process in live:
            try:
                fields = Path(f"/proc/{process.pid}/statm").read_text(encoding="utf-8").split()
                total += int(fields[1]) * page_size
            except (FileNotFoundError, IndexError, ValueError):
                continue
        return total
    if sys.platform == "darwin":
        class ProcTaskInfo(ctypes.Structure):
            _fields_ = [
                ("virtual_size", ctypes.c_uint64),
                ("resident_size", ctypes.c_uint64),
                ("total_user", ctypes.c_uint64),
                ("total_system", ctypes.c_uint64),
                ("threads_user", ctypes.c_uint64),
                ("threads_system", ctypes.c_uint64),
                ("policy", ctypes.c_int32),
                ("faults", ctypes.c_int32),
                ("pageins", ctypes.c_int32),
                ("cow_faults", ctypes.c_int32),
                ("messages_sent", ctypes.c_int32),
                ("messages_received", ctypes.c_int32),
                ("syscalls_mach", ctypes.c_int32),
                ("syscalls_unix", ctypes.c_int32),
                ("context_switches", ctypes.c_int32),
                ("thread_count", ctypes.c_int32),
                ("running_threads", ctypes.c_int32),
                ("priority", ctypes.c_int32),
            ]

        libproc = ctypes.CDLL("/usr/lib/libproc.dylib")
        total = 0
        for process in live:
            info = ProcTaskInfo()
            received = libproc.proc_pidinfo(
                process.pid,
                4,
                0,
                ctypes.byref(info),
                ctypes.sizeof(info),
            )
            if received == ctypes.sizeof(info):
                total += info.resident_size
        return total
    completed = subprocess.run(
        ["ps", "-o", "rss=", "-p", ",".join(str(process.pid) for process in live)],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return sum(int(line) * 1024 for line in completed.stdout.splitlines() if line.strip())


def distribute(total: int, parts: int) -> list[int]:
    quotient, remainder = divmod(total, parts)
    return [quotient + int(index < remainder) for index in range(parts)]


def initial_counts(limit: int, include_zero: bool = False) -> list[int]:
    values = {0} if include_zero else set()
    if limit > 0:
        values.add(1)
        power = 1
        while power < limit:
            values.add(power)
            power *= 2
        values.add(limit)
    return sorted(values)


def topology_key(topology: dict[str, Any]) -> tuple[int, int, int]:
    return topology["performance_workers"], topology["efficiency_workers"], topology["processes"]


def make_topology(performance_workers: int, efficiency_workers: int, processes: int) -> dict[str, Any]:
    if processes < 1 or performance_workers < processes or efficiency_workers < 0:
        raise ValueError("each proving process needs at least one performance worker")
    p_split = distribute(performance_workers, processes)
    e_split = distribute(efficiency_workers, processes)
    return {
        "performance_workers": performance_workers,
        "efficiency_workers": efficiency_workers,
        "processes": processes,
        "worker_allocations": [
            {"performance_workers": p, "efficiency_workers": e}
            for p, e in zip(p_split, e_split)
        ],
    }


def initial_topologies(hardware: dict[str, Any]) -> list[dict[str, Any]]:
    topologies = {}
    p_values = initial_counts(hardware["performance_workers"])
    e_values = initial_counts(hardware.get("efficiency_workers", 0), include_zero=True)
    process_values = initial_counts(hardware.get("proving_processes", 1))
    for performance in p_values:
        for efficiency in e_values:
            for processes in process_values:
                if processes <= performance:
                    topology = make_topology(performance, efficiency, processes)
                    topologies[topology_key(topology)] = topology
    return list(topologies.values())


def neighboring_topologies(winner: dict[str, Any], hardware: dict[str, Any]) -> list[dict[str, Any]]:
    candidates = {}
    for performance in range(
        max(1, winner["performance_workers"] - 1),
        min(hardware["performance_workers"], winner["performance_workers"] + 1) + 1,
    ):
        for efficiency in range(
            max(0, winner["efficiency_workers"] - 1),
            min(hardware.get("efficiency_workers", 0), winner["efficiency_workers"] + 1) + 1,
        ):
            for processes in range(
                max(1, winner["processes"] - 1),
                min(hardware.get("proving_processes", 1), winner["processes"] + 1) + 1,
            ):
                if processes <= performance:
                    topology = make_topology(performance, efficiency, processes)
                    candidates[topology_key(topology)] = topology
    return list(candidates.values())


def topology_preserves_root_policy(query: dict[str, Any], topology: dict[str, Any]) -> bool:
    if topology["processes"] == 1:
        return True
    if query["root_lifecycle"] == "rolling":
        return False
    return not (
        query["root_policy"]["kind"] == "periodic"
        and query["root_policy"].get("empty_tick", "skip") == "reuse_previous_root"
    )


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def append_jsonl(path: Path, value: Any) -> None:
    with path.open("a", encoding="utf-8") as output:
        output.write(json.dumps(value, separators=(",", ":")) + "\n")


def write_rows_csv(path: Path, fields: Sequence[str], rows: Sequence[dict[str, Any]]) -> None:
    with path.open("w", newline="", encoding="utf-8") as output:
        writer = csv.DictWriter(output, fieldnames=fields)
        writer.writeheader()
        writer.writerows({field: row.get(field) for field in fields} for row in rows)


def aggregate_schema2_capacity_records(records: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
    """Aggregate measured parent samples by their complete proof-shape identity."""
    grouped: dict[str, list[dict[str, Any]]] = {}
    for record in records:
        configuration = record.get("configuration", {})
        identity = {
            "workload_adapter": record.get("workload_adapter"),
            "workload_adapter_schema_version": record.get("workload_adapter_schema_version"),
            "adapter_config_digest": record.get("adapter_config_digest"),
            "program_identity": record.get("program_identity"),
            "role": record.get("role"),
            "arity": configuration.get("arity"),
            "child_log_inv_rate": configuration.get("child_log_inv_rate"),
            "parent_log_inv_rate": configuration.get("parent_log_inv_rate"),
            "performance_workers": record.get("performance_workers", configuration.get("performance_workers")),
            "workload_shape_fingerprint": record.get("workload_shape_fingerprint"),
        }
        stable_tuple_id = hashlib.blake2s(
            json.dumps(identity, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        grouped.setdefault(stable_tuple_id, []).append(record)

    aggregates = []
    for stable_tuple_id, group in sorted(grouped.items()):
        first = group[0]
        configuration = first.get("configuration", {})
        samples = [
            float(value)
            for record in group
            for value in record.get("aggregation_seconds", [])
        ]
        aggregates.append({
            "stable_tuple_id": stable_tuple_id,
            "workload_adapter": first.get("workload_adapter"),
            "workload_adapter_schema_version": first.get("workload_adapter_schema_version"),
            "adapter_config_digest": first.get("adapter_config_digest"),
            "program_identity": first.get("program_identity"),
            "role": first.get("role"),
            "measurement_phases": json.dumps(sorted({
                record.get("measurement_phase") for record in group if record.get("measurement_phase")
            })),
            "arity": configuration.get("arity"),
            "child_log_inv_rate": configuration.get("child_log_inv_rate"),
            "parent_log_inv_rate": configuration.get("parent_log_inv_rate"),
            "performance_workers": first.get("performance_workers", configuration.get("performance_workers")),
            "workload_shape_fingerprint": first.get("workload_shape_fingerprint"),
            "ordered_child_claim_counts": json.dumps(first.get("ordered_child_claim_counts")),
            "child_shapes": json.dumps(first.get("child_shapes", [first.get("child_shape")]), sort_keys=True),
            "parent_shape": json.dumps(first.get("parent_shape"), sort_keys=True),
            "sample_count": len(samples),
            "median_service_seconds": statistics.median(samples) if samples else None,
            "maximum_rss_bytes": max((int(record.get("observed_peak_rss_bytes", 0)) for record in group), default=0),
            "output_bytes": max((int(record.get("proof_bytes", 0)) for record in group), default=0),
            "directly_measured": bool(samples) and all(record.get("verified") is True for record in group),
            "workload_case_ids": json.dumps(sorted({
                record.get("workload_case_id") for record in group if record.get("workload_case_id")
            })),
            "workload_case_blake2s": json.dumps(sorted({
                record.get("workload_case_blake2s") for record in group if record.get("workload_case_blake2s")
            })),
        })
    return aggregates


def write_schema2_capacity_artifacts(output_dir: Path, records: Sequence[dict[str, Any]]) -> None:
    aggregates = aggregate_schema2_capacity_records(records)
    write_json(
        output_dir / "capacity.json",
        {"schema_version": 2, "parent_jobs": list(records), "aggregates": aggregates},
    )
    write_rows_csv(output_dir / "capacity.csv", SCHEMA2_CAPACITY_FIELDS, aggregates)


def native_environment(performance_workers: int, efficiency_workers: int) -> dict[str, str]:
    environment = os.environ.copy()
    rustflags = environment.get("RUSTFLAGS", "").strip()
    if NATIVE_RUSTFLAGS not in rustflags:
        environment["RUSTFLAGS"] = f"{rustflags} {NATIVE_RUSTFLAGS}".strip()
    environment["LEANVM_NUM_PERFORMANCE_THREADS"] = str(performance_workers)
    environment["LEANVM_NUM_EFFICIENCY_THREADS"] = str(efficiency_workers)
    environment.pop("LEANVM_NUM_THREADS", None)
    environment.pop("RAYON_NUM_THREADS", None)
    return environment


def build_binary(workspace: Path, timeout_seconds: float | None = None) -> Path:
    environment = native_environment(1, 0)
    subprocess.run(
        ["cargo", "build", "--release", "--bin", "leanvm-b"],
        cwd=workspace,
        env=environment,
        check=True,
        timeout=timeout_seconds,
    )
    executable = "leanvm-b.exe" if os.name == "nt" else "leanvm-b"
    return workspace / "target" / "release" / executable


def source_fingerprint(workspace: Path, excluded_root: Path | None = None) -> dict[str, Any]:
    """Hash the commit, tracked diff, and relevant untracked files used by a benchmark run."""
    def git_output(arguments: Sequence[str]) -> bytes:
        return subprocess.run(
            ["git", *arguments], cwd=workspace, check=True, capture_output=True
        ).stdout

    commit = git_output(["rev-parse", "HEAD"]).decode().strip()
    tracked_diff = git_output(["diff", "--binary", "HEAD", "--", "."])
    untracked_paths = git_output(["ls-files", "--others", "--exclude-standard", "-z"]).split(b"\0")
    untracked = []
    excluded_root = excluded_root.resolve() if excluded_root is not None else None
    for encoded in untracked_paths:
        if not encoded:
            continue
        relative = Path(os.fsdecode(encoded))
        path = (workspace / relative).resolve()
        if excluded_root is not None and (path == excluded_root or excluded_root in path.parents):
            continue
        if relative.name == ".DS_Store" or "target" in relative.parts:
            continue
        if not path.is_file():
            continue
        untracked.append({
            "path": relative.as_posix(),
            "blake2s": hashlib.blake2s(path.read_bytes()).hexdigest(),
        })
    material = {
        "git_commit": commit,
        "tracked_diff_blake2s": hashlib.blake2s(tracked_diff).hexdigest(),
        "untracked": sorted(untracked, key=lambda item: item["path"]),
    }
    material["digest"] = hashlib.blake2s(
        json.dumps(material, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return material


def xmss_signature_counts(query: dict[str, Any]) -> list[int]:
    if query["workload"]["adapter"] != "xmss":
        raise ValueError("this checkout currently provides only the XMSS workload adapter")
    config = query["workload"]["adapter_config"]
    counts = set()
    if "signatures_per_child" in config:
        counts.add(int(config["signatures_per_child"]))
    for entry in config.get("signature_distribution", []):
        counts.add(int(entry["signatures"]))
    for source in query["arrivals"].get("sources", []):
        variant = source.get("workload_variant", {})
        if "signatures_per_child" in variant:
            counts.add(int(variant["signatures_per_child"]))
    if not counts or min(counts) < 1:
        raise ValueError("XMSS adapter configuration needs positive signatures per child")
    return sorted(counts)


def capacity_signer_starts(query: dict[str, Any], child_count: int, signatures: int) -> list[int]:
    config = query["workload"]["adapter_config"]
    relationship = config.get("signer_relationship", "disjoint")
    if relationship == "disjoint":
        return [index * signatures for index in range(child_count)]
    if relationship == "repeated":
        return [0] * child_count
    if relationship == "trace":
        starts = [int(value) for value in config.get("signer_starts", [])]
        if len(starts) < child_count:
            raise ValueError(
                f"XMSS signer_starts needs at least {child_count} entries for an isolated parent measurement"
            )
        return starts[:child_count]
    raise ValueError(f"unsupported XMSS signer_relationship: {relationship}")


def measure_job_costs(
    binary: Path,
    query: dict[str, Any],
    allocation: dict[str, int],
    repeat: int,
    output_dir: Path,
    raw_path: Path,
    failures: list[dict[str, Any]],
    case_arities: Sequence[int] | None = None,
    case_child_rates: Sequence[int] | None = None,
    case_parent_rates: Sequence[int] | None = None,
    artifact_suffix: str | None = None,
) -> Path:
    key = f"p{allocation['performance_workers']}-e{allocation['efficiency_workers']}-n{repeat}"
    if artifact_suffix:
        key = f"{key}-{artifact_suffix}"
    cost_path = output_dir / f"job-costs-{key}.json"
    checkpoint_path = output_dir / f"parent-job-records-{key}.jsonl"
    signature_counts = xmss_signature_counts(query)
    grouped: dict[tuple[int, int, int], list[dict[str, Any]]] = {}
    completed: set[tuple[int, int, int, int]] = set()
    if checkpoint_path.exists():
        for line in checkpoint_path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            entry = json.loads(line)
            case = (
                int(entry["signatures_per_child"]),
                int(entry["child_count"]),
                int(entry["child_log_inv_rate"]),
                int(entry["parent_log_inv_rate"]),
            )
            completed.add(case)
            if entry["status"] == "success":
                grouped.setdefault((case[1], case[2], case[3]), []).append(entry["record"])
            else:
                failures.append(entry["failure"])
    environment = native_environment(allocation["performance_workers"], allocation["efficiency_workers"])
    parent_rates = list(case_parent_rates or query["search"].get("parent_log_inv_rates", [1, 2, 3, 4]))
    child_rates = list(
        case_child_rates
        or sorted(set(query["workload"]["leaf_log_inv_rates"]) | set(parent_rates))
    )
    arities = list(case_arities or query["search"].get("arities", list(range(2, 17))))
    total_cases = len(signature_counts) * len(child_rates) * len(parent_rates) * len(arities)
    completed_cases = 0
    for signatures in signature_counts:
        for child_rate in child_rates:
            for parent_rate in parent_rates:
                for child_count in arities:
                    completed_cases += 1
                    case = (signatures, child_count, child_rate, parent_rate)
                    if case in completed:
                        continue
                    print(
                        f"parent job {completed_cases}/{total_cases}: "
                        f"{allocation['performance_workers']} performance workers, "
                        f"{allocation['efficiency_workers']} efficiency workers, "
                        f"{child_count} children, WHIR 1/{1 << child_rate} to 1/{1 << parent_rate}",
                        file=sys.stderr,
                        flush=True,
                    )
                    run_id = f"job-p{allocation['performance_workers']}-e{allocation['efficiency_workers']}-{time.time_ns()}"
                    command = [
                        str(binary),
                        "--repeat",
                        str(repeat),
                        "--cooldown",
                        "0",
                        "recursion-capacity-case",
                        "--arity",
                        str(child_count),
                        "--xmss-per-child",
                        str(signatures),
                        "--child-log-inv-rate",
                        str(child_rate),
                        "--parent-log-inv-rate",
                        str(parent_rate),
                        "--signer-starts",
                        ",".join(map(str, capacity_signer_starts(query, child_count, signatures))),
                        "--run-id",
                        run_id,
                    ]
                    process = subprocess.Popen(
                        command,
                        env=environment,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                    )
                    observed_peak_rss, ram_terminated = monitor_combined_rss(
                        [process], int(query["hardware_limits"]["prover_ram_bytes"])
                    )
                    stdout, stderr = process.communicate()
                    if ram_terminated or process.returncode:
                        failure = {
                            "worker_allocation": allocation,
                            "signatures_per_child": signatures,
                            "child_count": child_count,
                            "child_log_inv_rate": child_rate,
                            "parent_log_inv_rate": parent_rate,
                            "observed_peak_rss_bytes": observed_peak_rss,
                            "ram_terminated": ram_terminated,
                            "returncode": process.returncode,
                            "error": stderr.strip() or ("prover RAM limit exceeded" if ram_terminated else "no diagnostic"),
                        }
                        failures.append(failure)
                        append_jsonl(raw_path, {"record_type": "parent_job_failure", **failure})
                        append_jsonl(
                            checkpoint_path,
                            {
                                "status": "failure",
                                "signatures_per_child": signatures,
                                "child_count": child_count,
                                "child_log_inv_rate": child_rate,
                                "parent_log_inv_rate": parent_rate,
                                "failure": failure,
                            },
                        )
                        continue
                    lines = [line for line in stdout.splitlines() if line.strip()]
                    if len(lines) != 1:
                        failure = {
                            "worker_allocation": allocation,
                            "signatures_per_child": signatures,
                            "child_count": child_count,
                            "child_log_inv_rate": child_rate,
                            "parent_log_inv_rate": parent_rate,
                            "observed_peak_rss_bytes": observed_peak_rss,
                            "ram_terminated": False,
                            "returncode": process.returncode,
                            "error": f"parent job emitted {len(lines)} JSON records instead of one",
                        }
                        failures.append(failure)
                        append_jsonl(raw_path, {"record_type": "parent_job_failure", **failure})
                        append_jsonl(
                            checkpoint_path,
                            {
                                "status": "failure",
                                "signatures_per_child": signatures,
                                "child_count": child_count,
                                "child_log_inv_rate": child_rate,
                                "parent_log_inv_rate": parent_rate,
                                "failure": failure,
                            },
                        )
                        continue
                    record = json.loads(lines[0])
                    append_jsonl(
                        raw_path,
                        {
                            "record_type": "parent_job",
                            "worker_allocation": allocation,
                            "workload": query["workload"],
                            "record": record,
                        },
                    )
                    append_jsonl(
                        checkpoint_path,
                        {
                            "status": "success",
                            "signatures_per_child": signatures,
                            "child_count": child_count,
                            "child_log_inv_rate": child_rate,
                            "parent_log_inv_rate": parent_rate,
                            "record": record,
                        },
                    )
                    grouped.setdefault((child_count, child_rate, parent_rate), []).append(record)
    costs = []
    for (child_count, child_rate, parent_rate), records in sorted(grouped.items()):
        representative = max(records, key=lambda record: record["summary"]["mean_service_seconds"])
        service_seconds = max(record["summary"]["mean_service_seconds"] for record in records)
        peak_rss = max(record["summary"]["peak_rss_bytes"] for record in records)
        output_bytes = max(record["sizes"]["full_aggregate_bytes"] for record in records)
        costs.append(
            {
                "child_count": child_count,
                "child_log_inv_rate": child_rate,
                "parent_log_inv_rate": parent_rate,
                "service_seconds": service_seconds,
                "peak_rss_bytes": peak_rss,
                "output_bytes": output_bytes,
                "directly_measured": False,
                "model_scope": (
                    "isolated parent job measured with generated XMSS leaf proof shapes; "
                    "directly_measured=false means the cost was not validated with the candidate's "
                    "exact upper-level child proof shapes; exact upper-level jobs are recorded by "
                    "application runs"
                ),
                "statement_relationship": query["workload"]["adapter_config"].get(
                    "signer_relationship", "disjoint"
                ),
                "sample_count": sum(len(record["aggregation_samples"]) for record in records),
                "mean_cpu_seconds": representative["summary"]["mean_cpu_seconds"],
                "mean_effective_cpu_cores": representative["summary"]["mean_effective_cpu_cores"],
                "child_preparation_seconds": max(record["child_preparation_seconds"] for record in records),
                "child_deserialization_seconds": None,
                "parent_serialization_seconds": max(record["parent_serialization_seconds"] for record in records),
                "child_shape": representative["child_shape"],
                "parent_shape": representative["parent_shape"],
                "whir_schedule": representative["parent_whir"],
            }
        )
    write_json(cost_path, costs)
    return cost_path


def model_job_costs_for_allocation(
    base_cost_path: Path,
    calibration_cost_path: Path,
    base_allocation: dict[str, int],
    target_allocation: dict[str, int],
    output_dir: Path,
) -> Path:
    base_costs = json.loads(base_cost_path.read_text(encoding="utf-8"))
    calibration_costs = json.loads(calibration_cost_path.read_text(encoding="utf-8"))
    base_by_key = {
        (cost["child_count"], cost["child_log_inv_rate"], cost["parent_log_inv_rate"]): cost
        for cost in base_costs
    }
    calibration_by_key = {
        (cost["child_count"], cost["child_log_inv_rate"], cost["parent_log_inv_rate"]): cost
        for cost in calibration_costs
    }
    pair_scaling: dict[tuple[int, int], dict[str, Any]] = {}
    rate_pairs = sorted({(key[1], key[2]) for key in base_by_key})
    for child_rate, parent_rate in rate_pairs:
        comparisons = []
        for key, target in calibration_by_key.items():
            if key[1:] != (child_rate, parent_rate) or key not in base_by_key:
                continue
            base = base_by_key[key]
            comparisons.append(
                {
                    "child_count": key[0],
                    "speedup": base["service_seconds"] / max(target["service_seconds"], sys.float_info.epsilon),
                    "rss_ratio": target["peak_rss_bytes"] / max(base["peak_rss_bytes"], 1),
                }
            )
        if not comparisons:
            raise ValueError(
                f"adaptive parent measurement has no thread-scaling calibration for WHIR "
                f"1/{1 << child_rate} to 1/{1 << parent_rate}"
            )
        pair_scaling[(child_rate, parent_rate)] = {
            "speedup": statistics.median(item["speedup"] for item in comparisons),
            "rss_ratio": max(item["rss_ratio"] for item in comparisons),
            "calibration_arities": [item["child_count"] for item in comparisons],
        }

    modeled = []
    for key, base in sorted(base_by_key.items()):
        direct_calibration = calibration_by_key.get(key)
        scaling = pair_scaling[key[1:]]
        if direct_calibration is not None:
            cost = dict(direct_calibration)
            cost_source = "thread-scaling calibration measurement"
        else:
            cost = dict(base)
            cost["service_seconds"] = base["service_seconds"] / max(
                scaling["speedup"], sys.float_info.epsilon
            )
            cost["peak_rss_bytes"] = math.ceil(base["peak_rss_bytes"] * scaling["rss_ratio"])
            cost_source = "one-thread geometry scaled by measured thread speedup"
        cost["directly_measured"] = False
        cost["model_scope"] = (
            f"{cost_source}; directly_measured=false means the cost was not validated with the "
            "candidate's exact upper-level child proof shapes; used to choose end-to-end "
            "candidates, which are executed directly"
        )
        cost["thread_scaling_calibration"] = {
            "base_allocation": base_allocation,
            "target_allocation": target_allocation,
            **scaling,
        }
        modeled.append(cost)

    key = (
        f"p{target_allocation['performance_workers']}-"
        f"e{target_allocation['efficiency_workers']}-adaptive"
    )
    output_path = output_dir / f"job-costs-{key}.json"
    write_json(output_path, modeled)
    return output_path


def model_job_costs_from_calibration(
    calibration_cost_path: Path,
    query: dict[str, Any],
    target_allocation: dict[str, int],
    output_dir: Path,
) -> Path:
    calibration_costs = json.loads(calibration_cost_path.read_text(encoding="utf-8"))
    by_pair: dict[tuple[int, int], list[dict[str, Any]]] = {}
    for cost in calibration_costs:
        by_pair.setdefault((cost["child_log_inv_rate"], cost["parent_log_inv_rate"]), []).append(cost)
    modeled = []
    child_rates = sorted(
        set(query["workload"]["leaf_log_inv_rates"])
        | set(query["search"]["parent_log_inv_rates"])
    )
    for child_rate in child_rates:
        for parent_rate in query["search"]["parent_log_inv_rates"]:
            references = by_pair.get((child_rate, parent_rate), [])
            if not references:
                raise ValueError(
                    f"calibration-only parent model has no measurement for WHIR "
                    f"1/{1 << child_rate} to 1/{1 << parent_rate}"
                )
            reference = max(references, key=lambda cost: cost["child_count"])
            reference_arity = int(reference["child_count"])
            for child_count in query["search"]["arities"]:
                if child_count == reference_arity:
                    service_seconds = reference["service_seconds"]
                    source = "thread calibration measurement"
                else:
                    service_seconds = reference["service_seconds"] * child_count / reference_arity
                    source = "linear child-count estimate from thread calibration"
                modeled.append(
                    {
                        "child_count": child_count,
                        "child_log_inv_rate": child_rate,
                        "parent_log_inv_rate": parent_rate,
                        "service_seconds": service_seconds,
                        "peak_rss_bytes": reference["peak_rss_bytes"],
                        "output_bytes": reference["output_bytes"],
                        "directly_measured": False,
                        "model_scope": (
                            f"{source}; directly_measured=false means the cost was not validated "
                            "with the candidate's exact upper-level child proof shapes; used only "
                            "to choose directly executed end-to-end candidates"
                        ),
                        "calibration_child_count": reference_arity,
                        "target_allocation": target_allocation,
                    }
                )
    key = (
        f"p{target_allocation['performance_workers']}-"
        f"e{target_allocation['efficiency_workers']}-calibration-only"
    )
    output_path = output_dir / f"job-costs-{key}.json"
    write_json(output_path, modeled)
    return output_path


def terminate_processes(processes: Sequence[subprocess.Popen[str]]) -> None:
    for process in processes:
        if process.poll() is None:
            process.terminate()
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline and any(process.poll() is None for process in processes):
        time.sleep(0.05)
    for process in processes:
        if process.poll() is None:
            process.kill()


def monitor_combined_rss(
    processes: Sequence[subprocess.Popen[str]], ram_limit_bytes: int, interval_seconds: float = 0.05
) -> tuple[int, bool]:
    peak_rss = 0
    while any(process.poll() is None for process in processes):
        peak_rss = max(peak_rss, process_rss_bytes(processes))
        if peak_rss > ram_limit_bytes:
            terminate_processes(processes)
            return peak_rss, True
        time.sleep(interval_seconds)
    return peak_rss, False


def run_exact_replication(
    binary: Path,
    query_path: Path,
    query: dict[str, Any],
    topology: dict[str, Any],
    cost_paths: Sequence[Path],
    arrival_rate: float,
    leaf_rate: int,
    root_target: int,
    replication: int,
    raw_path: Path,
) -> dict[str, Any]:
    process_count = topology["processes"]
    if not topology_preserves_root_policy(query, topology):
        return {
            "records": [],
            "peak_combined_rss_bytes": 0,
            "ram_terminated": False,
            "error": "this root policy requires one proving process because one root is not split across processes",
        }
    global_root_target = max(root_target, process_count)
    processes: list[subprocess.Popen[str]] = []
    commands = []
    barrier_context = tempfile.TemporaryDirectory(prefix="recursion-barrier-", dir=raw_path.parent)
    barrier_dir = Path(barrier_context.name)
    for worker_index, (allocation, costs) in enumerate(zip(topology["worker_allocations"], cost_paths)):
        run_id = f"load-r{replication}-w{worker_index}-{time.time_ns()}"
        command = [
            str(binary),
            "recursion-benchmark-case",
            "--query",
            str(query_path),
            "--costs",
            str(costs),
            "--arrival-rate",
            str(arrival_rate),
            "--leaf-log-inv-rate",
            str(leaf_rate),
            "--root-target",
            str(global_root_target),
            "--run-id",
            run_id,
            "--root-shard-index",
            str(worker_index),
            "--root-shard-count",
            str(process_count),
            "--barrier-dir",
            str(barrier_dir),
        ]
        commands.append(command)
        processes.append(
            subprocess.Popen(
                command,
                env=native_environment(allocation["performance_workers"], allocation["efficiency_workers"]),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
        )
    ram_limit = int(query["hardware_limits"]["prover_ram_bytes"])
    peak_rss = 0
    ram_terminated = False
    preparation_error = None
    while True:
        peak_rss = max(peak_rss, process_rss_bytes(processes))
        if peak_rss > ram_limit:
            ram_terminated = True
            terminate_processes(processes)
            break
        if all((barrier_dir / f"ready-{index}").exists() for index in range(process_count)):
            start_unix_seconds = time.time() + 0.25
            (barrier_dir / "start").write_text(f"{start_unix_seconds:.9f}\n", encoding="utf-8")
            remaining_peak, terminated = monitor_combined_rss(processes, ram_limit)
            peak_rss = max(peak_rss, remaining_peak)
            ram_terminated |= terminated
            break
        exited = [index for index, process in enumerate(processes) if process.poll() is not None]
        if exited:
            preparation_error = f"worker(s) {exited} exited before all proving processes were ready"
            terminate_processes(processes)
            break
        time.sleep(0.05)
    records = []
    errors = [preparation_error] if preparation_error else []
    for worker_index, (process, command) in enumerate(zip(processes, commands)):
        stdout, stderr = process.communicate()
        if process.returncode:
            errors.append(
                f"worker {worker_index} exited with {process.returncode}: {stderr.strip() or 'no diagnostic'}"
            )
            continue
        lines = [line for line in stdout.splitlines() if line.strip()]
        if len(lines) != 1:
            errors.append(f"worker {worker_index} emitted {len(lines)} JSON records instead of one")
            continue
        record = json.loads(lines[0])
        record["worker_index"] = worker_index
        records.append(record)
        append_jsonl(
            raw_path,
            {
                "record_type": "application_run",
                "topology": topology,
                "replication": replication,
                "record": record,
            },
        )
    barrier_context.cleanup()
    return {
        "records": records,
        "peak_combined_rss_bytes": peak_rss,
        "ram_terminated": ram_terminated,
        "error": "; ".join(errors) if errors else None,
    }


def combine_backlog(records: Sequence[dict[str, Any]]) -> list[tuple[float, float]]:
    events = []
    if not records:
        return events
    origin = min(record["measured_started_unix_seconds"] for record in records)
    for record in records:
        offset = record["measured_started_unix_seconds"] - origin
        previous = 0
        for point in record["backlog"]:
            value = int(point["inputs"])
            events.append((offset + float(point["seconds"]), value - previous))
            previous = value
    events.sort()
    backlog = 0
    points = []
    for seconds, change in events:
        backlog += change
        points.append((seconds, float(backlog)))
    return points


def combined_rolling_bandwidth(
    records: Sequence[dict[str, Any]], field: str, rolling_window_seconds: float
) -> float:
    if not records:
        return 0.0
    if not all(field in record["proof_bandwidth"] for record in records):
        legacy_field = f"maximum_rolling_{'ingress' if field == 'ingress_events' else 'egress'}_bytes_per_second"
        return sum(record["proof_bandwidth"][legacy_field] for record in records)
    origin = min(record["measured_started_unix_seconds"] for record in records)
    events = sorted(
        (
            record["measured_started_unix_seconds"] - origin + float(event[0]),
            float(event[1]),
        )
        for record in records
        for event in record["proof_bandwidth"][field]
    )
    start = 0
    total = 0.0
    peak = 0.0
    for end, (seconds, byte_count) in enumerate(events):
        total += byte_count
        while seconds - events[start][0] > rolling_window_seconds:
            total -= events[start][1]
            start += 1
        peak = max(peak, total / rolling_window_seconds)
    return peak


def combine_replications(
    replications: Sequence[dict[str, Any]],
    query: dict[str, Any],
    requested_rate: float,
    topology: dict[str, Any],
    leaf_rate: int,
    tier: str,
) -> dict[str, Any]:
    records = [record for replication in replications for record in replication["records"]]
    roots = []
    latencies = []
    root_groups = []
    root_intervals = []
    boundary_field = (
        "proof_completion_seconds"
        if query.get("deadlines", {}).get("boundary", "serialized") == "proof_produced"
        else "serialization_completion_seconds"
    )
    for replication_index, replication in enumerate(replications):
        replication_roots = []
        for record in replication["records"]:
            start = record["measured_started_unix_seconds"]
            for root in record["root_samples"]:
                copy = dict(root)
                copy["worker_index"] = record["worker_index"]
                copy["replication"] = replication_index
                copy["completion_unix_seconds"] = start + root[boundary_field]
                replication_roots.append(copy)
                root_groups.append(root["input_to_root_seconds"])
                latencies.extend(root["input_to_root_seconds"])
        replication_roots.sort(key=lambda root: root["completion_unix_seconds"])
        root_intervals.extend(
            right["completion_unix_seconds"] - left["completion_unix_seconds"]
            for left, right in zip(replication_roots, replication_roots[1:])
        )
        roots.extend(replication_roots)
    roots.sort(key=lambda root: (root["replication"], root["completion_unix_seconds"]))
    tick_lateness = [root["tick_lateness_seconds"] for root in roots if root["tick_lateness_seconds"] is not None]
    prediction_pairs = [
        (
            float(root["tree"]["estimated_service_seconds"]),
            sum(float(job["service_seconds"]) for job in root.get("parent_jobs", [])),
        )
        for root in roots
        if root.get("parent_jobs")
    ]
    if prediction_pairs:
        prediction = {
            "root_count": len(prediction_pairs),
            "mean_modeled_service_seconds": statistics.fmean(pair[0] for pair in prediction_pairs),
            "mean_measured_service_seconds": statistics.fmean(pair[1] for pair in prediction_pairs),
            "mean_absolute_percentage_error": statistics.fmean(
                abs(modeled - measured) / max(measured, sys.float_info.epsilon)
                for modeled, measured in prediction_pairs
            ),
        }
    else:
        prediction = None
    def steady_completed_rate(record: dict[str, Any]) -> float:
        completed = sorted(record["root_samples"], key=lambda root: root[boundary_field])
        if len(completed) < 2:
            return record["completed_inputs"] / max(record["elapsed_seconds"], sys.float_info.epsilon)
        warmup = max(1, len(completed) // 5)
        observed = completed[warmup:]
        if len(observed) < 2:
            observed = completed
        interval = observed[-1][boundary_field] - observed[0][boundary_field]
        inputs = sum(root["input_count"] for root in observed[1:])
        return inputs / max(interval, sys.float_info.epsilon)

    replication_rates = [
        sum(steady_completed_rate(record) for record in replication["records"])
        for replication in replications
    ]
    completed_rate = statistics.fmean(replication_rates) if replication_rates else 0.0
    completion_ratios = [rate / requested_rate for rate in replication_rates]
    completion_ratio = min(completion_ratios, default=0.0)
    replication_backlogs = [combine_backlog(replication["records"]) for replication in replications]
    backlog_runs = [(points, backlog_slope_interval(points)) for points in replication_backlogs if points]
    if backlog_runs:
        displayed_backlog_points, selected_backlog = max(
            backlog_runs,
            key=lambda item: item[1]["lower_confidence_bound"],
        )
    else:
        displayed_backlog_points = []
        selected_backlog = {
            "slope_inputs_per_second": 0.0,
            "lower_confidence_bound": 0.0,
            "upper_confidence_bound": 0.0,
            "warmup_seconds": 0.0,
            "observation_seconds": 0.0,
        }
    backlog_results = [result for _, result in backlog_runs]
    backlog = dict(selected_backlog)
    backlog["fresh_runs"] = backlog_results
    maximum_latency = max(latencies, default=None)
    p99 = percentile_nearest_rank(latencies, 0.99) if latencies and tier != "screening" else None
    p99_upper = None
    if tier == "publication" and root_groups:
        p99_upper = root_grouped_percentile_upper_bound(root_groups)
    average_ingress = max(
        (sum(record["proof_bandwidth"]["average_ingress_bytes_per_second"] for record in replication["records"])
         for replication in replications),
        default=0.0,
    )
    exact_ingress_event_count = sum(
        record["proof_bandwidth"].get("exact_ingress_event_count", 0) for record in records
    )
    conservatively_sized_ingress_event_count = sum(
        record["proof_bandwidth"].get("conservatively_sized_ingress_event_count", 0) for record in records
    )
    average_egress = max(
        (sum(record["proof_bandwidth"]["average_egress_bytes_per_second"] for record in replication["records"])
         for replication in replications),
        default=0.0,
    )
    rolling_window = float(query["network"].get("rolling_window_seconds", 1.0))
    rolling_ingress = max(
        (combined_rolling_bandwidth(replication["records"], "ingress_events", rolling_window)
         for replication in replications),
        default=0.0,
    )
    rolling_egress = max(
        (combined_rolling_bandwidth(replication["records"], "egress_events", rolling_window)
         for replication in replications),
        default=0.0,
    )
    result = {
        "requested_input_rate": requested_rate,
        "completed_input_rate": completed_rate,
        "completion_rate_ratio": completion_ratio,
        "fresh_run_completed_input_rates": replication_rates,
        "leaf_log_inv_rate": leaf_rate,
        "workload": records[0].get("workload") if records else None,
        "raw_run_ids": [record.get("run", {}).get("run_id") for record in records if record.get("run")],
        "topology": topology,
        "fresh_runs": len(replications),
        "completed_roots": len(roots),
        "completed_inputs": sum(record["completed_inputs"] for record in records),
        "all_roots_verified": bool(records) and all(record["all_roots_verified"] for record in records),
        "stopped_reasons": sorted({record["stopped_reason"] for record in records if record["stopped_reason"]}),
        "worker_errors": [replication["error"] for replication in replications if replication["error"]],
        "ram_terminated": any(replication["ram_terminated"] for replication in replications),
        "peak_combined_rss_bytes": max(
            (replication["peak_combined_rss_bytes"] for replication in replications), default=0
        ),
        "input_to_root_p99_seconds": p99,
        "input_to_root_p99_upper_95_seconds": p99_upper,
        "maximum_input_to_root_seconds": maximum_latency,
        "maximum_root_interval_seconds": max(root_intervals, default=None),
        "maximum_tick_lateness_seconds": max(tick_lateness, default=None),
        "cost_model_comparison": prediction,
        "backlog": backlog,
        "backlog_points": [
            {"seconds": seconds, "inputs": inputs} for seconds, inputs in displayed_backlog_points
        ],
        "final_backlog_inputs": displayed_backlog_points[-1][1] if displayed_backlog_points else 0,
        "overload_recovery": overload_recovery(displayed_backlog_points, query["arrivals"].get("phases", [])),
        "maximum_backlog_inputs": max(
            (value for points in replication_backlogs for _, value in points), default=0
        ),
        "average_ingress_bytes_per_second": average_ingress,
        "exact_ingress_event_count": exact_ingress_event_count,
        "conservatively_sized_ingress_event_count": conservatively_sized_ingress_event_count,
        "average_egress_bytes_per_second": average_egress,
        "maximum_rolling_ingress_bytes_per_second": rolling_ingress,
        "maximum_rolling_egress_bytes_per_second": rolling_egress,
        "root_samples": roots,
        "effective_cpu_cores": max(
            (sum(record["effective_cpu_cores"] for record in replication["records"])
             for replication in replications),
            default=0.0,
        ),
    }
    result["constraints"] = evaluate_constraints(result, query, tier)
    result["passes"] = all(item["passes"] for item in result["constraints"])
    return result


def constraint(name: str, measured: Any, limit: Any, passes: bool, detail: str) -> dict[str, Any]:
    return {"name": name, "measured": measured, "limit": limit, "passes": bool(passes), "detail": detail}


def evaluate_constraints(result: dict[str, Any], query: dict[str, Any], tier: str) -> list[dict[str, Any]]:
    deadlines = query.get("deadlines", {})
    network = query["network"]
    constraints = [
        constraint(
            "Every completed root verifies",
            result["all_roots_verified"],
            True,
            result["all_roots_verified"] and not result["stopped_reasons"] and not result["worker_errors"],
            "The native verifier checks each completed root.",
        ),
        constraint(
            "Completed input rate follows offered input rate",
            result["completion_rate_ratio"],
            "0.99 to 1.01",
            0.99 <= result["completion_rate_ratio"] <= 1.01,
            "Completed inputs per second divided by offered inputs per second.",
        ),
        constraint(
            "Backlog does not show statistically significant growth",
            result["backlog"]["lower_confidence_bound"],
            "<= 0 inputs/s",
            result["backlog"]["lower_confidence_bound"] <= 0,
            "Passes when the lower end of the 95% confidence interval for backlog growth is not positive.",
        ),
        constraint(
            "Prover RAM",
            result["peak_combined_rss_bytes"],
            query["hardware_limits"]["prover_ram_bytes"],
            not result["ram_terminated"]
            and result["peak_combined_rss_bytes"] <= query["hardware_limits"]["prover_ram_bytes"],
            "Maximum combined resident memory sampled across all proving processes.",
        ),
        constraint(
            "Average proof ingress",
            result["average_ingress_bytes_per_second"],
            network["ingress_budget_bytes_per_second"],
            result["average_ingress_bytes_per_second"] <= network["ingress_budget_bytes_per_second"],
            "Only incoming proof bytes that cross into the measured node.",
        ),
        constraint(
            "Rolling proof ingress",
            result["maximum_rolling_ingress_bytes_per_second"],
            network["ingress_budget_bytes_per_second"],
            result["maximum_rolling_ingress_bytes_per_second"] <= network["ingress_budget_bytes_per_second"],
            f"Maximum over a {network.get('rolling_window_seconds', 1)} second window.",
        ),
        constraint(
            "Average proof egress",
            result["average_egress_bytes_per_second"],
            network["egress_budget_bytes_per_second"],
            result["average_egress_bytes_per_second"] <= network["egress_budget_bytes_per_second"],
            "Counts one serialized proof for each configured recipient.",
        ),
        constraint(
            "Rolling proof egress",
            result["maximum_rolling_egress_bytes_per_second"],
            network["egress_budget_bytes_per_second"],
            result["maximum_rolling_egress_bytes_per_second"] <= network["egress_budget_bytes_per_second"],
            f"Maximum over a {network.get('rolling_window_seconds', 1)} second window.",
        ),
    ]
    p99_limit = deadlines.get("p99_input_to_root_seconds")
    if p99_limit is not None:
        if tier == "screening":
            measured = result["maximum_input_to_root_seconds"]
            name = "Largest observed input-to-root latency in the screening run"
            detail = "Screening compares the largest observed latency with the deadline and makes no p99 claim."
        else:
            measured = (
                result["input_to_root_p99_upper_95_seconds"]
                if tier == "publication"
                else result["input_to_root_p99_seconds"]
            )
            name = "99th-percentile input-to-root deadline"
            detail = "p99 is the nearest-rank 99th percentile of observed input latencies. Publication uses its one-sided 95% upper confidence bound."
        constraints.append(
            constraint(
                name,
                measured,
                p99_limit,
                measured is not None and measured <= p99_limit,
                detail,
            )
        )
    interval_limit = deadlines.get("max_root_interval_seconds")
    if interval_limit is not None:
        measured = result["maximum_root_interval_seconds"]
        constraints.append(
            constraint(
                "Maximum time between completed roots",
                measured,
                interval_limit,
                measured is not None and measured <= interval_limit,
                "Largest observed interval between deadline-boundary completion timestamps.",
            )
        )
    tick_limit = deadlines.get("max_tick_lateness_seconds")
    if tick_limit is not None:
        measured = result["maximum_tick_lateness_seconds"]
        constraints.append(
            constraint(
                "Maximum scheduled-root lateness",
                measured,
                tick_limit,
                measured is not None and measured <= tick_limit,
                "Largest completion delay after a configured periodic root tick.",
            )
        )
    return constraints


def run_candidate(
    binary: Path,
    query_path: Path,
    query: dict[str, Any],
    topology: dict[str, Any],
    cost_paths: Sequence[Path],
    arrival_rate: float,
    leaf_rate: int,
    tier: str,
    raw_path: Path,
) -> dict[str, Any]:
    settings = TIERS[tier]
    replications = [
        run_exact_replication(
            binary,
            query_path,
            query,
            topology,
            cost_paths,
            arrival_rate,
            leaf_rate,
            settings["roots"],
            replication,
            raw_path,
        )
        for replication in range(settings["fresh_runs"])
    ]
    return combine_replications(replications, query, arrival_rate, topology, leaf_rate, tier)


def discovery_rates(low: float, high: float, points: int = 5) -> list[float]:
    if low == high:
        return [low]
    if points < 2:
        raise ValueError("rate discovery needs at least two points")
    ratio = high / low
    return [low * ratio ** (index / (points - 1)) for index in range(points)]


def search_rate(
    binary: Path,
    query_path: Path,
    query: dict[str, Any],
    topology: dict[str, Any],
    cost_paths: Sequence[Path],
    leaf_rate: int,
    tier: str,
    raw_path: Path,
) -> list[dict[str, Any]]:
    search = query["search"]
    low = float(search["min_arrival_rate"])
    high = float(search["max_arrival_rate"])
    precision = float(search.get("rate_precision_fraction", 0.02 if tier == "publication" else 0.05))
    if tier == "publication":
        precision = min(precision, 0.02)
    tested: dict[float, dict[str, Any]] = {}

    def test(rate: float) -> dict[str, Any]:
        key = round(rate, 12)
        if key not in tested:
            tested[key] = run_candidate(
                binary, query_path, query, topology, cost_paths, rate, leaf_rate, tier, raw_path
            )
        return tested[key]

    for rate in discovery_rates(low, high):
        test(rate)
    passing_results = [result for result in tested.values() if result["passes"]]
    if not passing_results:
        return sorted(tested.values(), key=lambda result: result["requested_input_rate"])
    passing = max(result["requested_input_rate"] for result in passing_results)
    higher_failures = sorted(
        result["requested_input_rate"]
        for result in tested.values()
        if not result["passes"] and result["requested_input_rate"] > passing
    )
    if not higher_failures:
        return sorted(tested.values(), key=lambda result: result["requested_input_rate"])
    failing = higher_failures[0]
    while (failing - passing) / max(passing, sys.float_info.epsilon) > precision:
        midpoint = (passing + failing) / 2
        result = test(midpoint)
        if result["passes"]:
            passing = midpoint
        else:
            failing = midpoint
    return sorted(tested.values(), key=lambda result: result["requested_input_rate"])


def result_reasons(result: dict[str, Any]) -> str:
    return "; ".join(item["name"] for item in result["constraints"] if not item["passes"]) or "passes all supplied limits"


def winner_sort_key(result: dict[str, Any]) -> tuple[float, int, int, int]:
    total_workers = result["topology"]["performance_workers"] + result["topology"]["efficiency_workers"]
    return (
        result["requested_input_rate"],
        -result["peak_combined_rss_bytes"],
        -total_workers,
        -result["topology"]["processes"],
    )


def trace_mean_rate(query: dict[str, Any]) -> float | None:
    if query["arrivals"]["kind"] != "trace":
        return None
    events = query["arrivals"].get("events", [])
    if len(events) < 2 or events[-1]["seconds"] <= events[0]["seconds"]:
        return None
    return (len(events) - 1) / (events[-1]["seconds"] - events[0]["seconds"])


def write_candidate_csv(path: Path, candidates: Sequence[dict[str, Any]]) -> None:
    fields = [
        "requested_input_rate",
        "completed_input_rate",
        "passes",
        "performance_workers",
        "efficiency_workers",
        "processes",
        "leaf_whir_code_rate",
        "completed_roots",
        "p99_input_to_root_seconds",
        "p99_upper_95_seconds",
        "maximum_root_interval_seconds",
        "peak_combined_rss_bytes",
        "effective_cpu_cores",
        "average_ingress_bytes_per_second",
        "average_egress_bytes_per_second",
        "reasons",
    ]
    with path.open("w", newline="", encoding="utf-8") as output:
        writer = csv.DictWriter(output, fieldnames=fields)
        writer.writeheader()
        for result in candidates:
            writer.writerow(
                {
                    "requested_input_rate": result["requested_input_rate"],
                    "completed_input_rate": result["completed_input_rate"],
                    "passes": result["passes"],
                    "performance_workers": result["topology"]["performance_workers"],
                    "efficiency_workers": result["topology"]["efficiency_workers"],
                    "processes": result["topology"]["processes"],
                    "leaf_whir_code_rate": f"1/{1 << result['leaf_log_inv_rate']}",
                    "completed_roots": result["completed_roots"],
                    "p99_input_to_root_seconds": result["input_to_root_p99_seconds"],
                    "p99_upper_95_seconds": result["input_to_root_p99_upper_95_seconds"],
                    "maximum_root_interval_seconds": result["maximum_root_interval_seconds"],
                    "peak_combined_rss_bytes": result["peak_combined_rss_bytes"],
                    "effective_cpu_cores": result["effective_cpu_cores"],
                    "average_ingress_bytes_per_second": result["average_ingress_bytes_per_second"],
                    "average_egress_bytes_per_second": result["average_egress_bytes_per_second"],
                    "reasons": result_reasons(result),
                }
            )


def write_capacity_csv(output_dir: Path) -> None:
    fields = [
        "cost_file",
        "performance_workers",
        "efficiency_workers",
        "child_count",
        "child_whir_code_rate",
        "parent_whir_code_rate",
        "maximum_mean_service_seconds_across_child_signature_counts",
        "mean_cpu_seconds",
        "mean_effective_cpu_cores",
        "child_preparation_seconds",
        "child_deserialization_seconds",
        "parent_serialization_seconds",
        "sample_count",
        "peak_rss_bytes",
        "output_bytes",
        "target_security_bits",
    ]
    with (output_dir / "capacity.csv").open("w", newline="", encoding="utf-8") as output:
        writer = csv.DictWriter(output, fieldnames=fields)
        writer.writeheader()
        for path in sorted(output_dir.glob("job-costs-p*-e*-n*.json")):
            parts = path.stem.split("-")
            performance = int(parts[2][1:])
            efficiency = int(parts[3][1:])
            for cost in json.loads(path.read_text(encoding="utf-8")):
                writer.writerow(
                    {
                        "cost_file": path.name,
                        "performance_workers": performance,
                        "efficiency_workers": efficiency,
                        "child_count": cost["child_count"],
                        "child_whir_code_rate": f"1/{1 << cost['child_log_inv_rate']}",
                        "parent_whir_code_rate": f"1/{1 << cost['parent_log_inv_rate']}",
                        "maximum_mean_service_seconds_across_child_signature_counts": cost["service_seconds"],
                        "mean_cpu_seconds": cost.get("mean_cpu_seconds"),
                        "mean_effective_cpu_cores": cost.get("mean_effective_cpu_cores"),
                        "child_preparation_seconds": cost.get("child_preparation_seconds"),
                        "child_deserialization_seconds": cost.get("child_deserialization_seconds"),
                        "parent_serialization_seconds": cost.get("parent_serialization_seconds"),
                        "sample_count": cost.get("sample_count"),
                        "peak_rss_bytes": cost["peak_rss_bytes"],
                        "output_bytes": cost["output_bytes"],
                        "target_security_bits": cost.get("whir_schedule", {}).get("target_security_bits"),
                    }
                )


def detected_hardware() -> dict[str, Any]:
    description = f"{platform.system()} {platform.release()}, {platform.machine()}, {os.cpu_count()} logical CPUs"
    if platform.system() == "Darwin":
        completed = subprocess.run(
            ["sysctl", "-n", "machdep.cpu.brand_string"], check=False, capture_output=True, text=True
        )
        if completed.stdout.strip():
            description = f"{completed.stdout.strip()}; {description}"
    return {"description": description, "platform": platform.platform(), "logical_cpus": os.cpu_count()}


def validate_query_shape(query: dict[str, Any]) -> None:
    required = ["schema_version", "workload", "arrivals", "root_policy", "root_lifecycle", "hardware_limits", "network", "search"]
    missing = [name for name in required if name not in query]
    if missing:
        raise ValueError(f"query is missing required fields: {', '.join(missing)}")
    if query["schema_version"] == 2:
        validate_schema2_query_shape(query)
        return
    if query["schema_version"] != SCHEMA_VERSION:
        raise ValueError(f"query schema_version must be {SCHEMA_VERSION} or 2")
    if query["workload"].get("proof_source", {}).get("kind") != "generated":
        raise ValueError("the current XMSS workload adapter supports generated leaf proofs only")
    if query["root_policy"].get("empty_tick") == "adapter_proof":
        raise ValueError("the current XMSS workload adapter cannot produce a root for an empty periodic tick")
    if query["search"]["max_arrival_rate"] < query["search"]["min_arrival_rate"]:
        raise ValueError("maximum arrival rate must be at least the minimum")
    parent_measurement_mode = query["search"].get("parent_measurement_mode", "full")
    if parent_measurement_mode not in {"full", "adaptive"}:
        raise ValueError("search parent_measurement_mode must be full or adaptive")
    if parent_measurement_mode == "adaptive":
        scaling_arities = query["search"].get("thread_scaling_arities", [4, 16])
        if not scaling_arities or any(arity not in query["search"]["arities"] for arity in scaling_arities):
            raise ValueError(
                "adaptive parent measurement needs nonempty thread_scaling_arities drawn from search arities"
            )
    observed_trace_rate = trace_mean_rate(query)
    if query["arrivals"]["kind"] == "trace":
        if observed_trace_rate is None:
            raise ValueError("an arrival trace needs at least two events separated in time")
        tolerance = max(abs(observed_trace_rate), 1.0) * 1e-9
        if (
            abs(query["search"]["min_arrival_rate"] - observed_trace_rate) > tolerance
            or abs(query["search"]["max_arrival_rate"] - observed_trace_rate) > tolerance
        ):
            raise ValueError(
                "an exact arrival trace must use its mean rate between the first and last event "
                "for both search rate bounds"
            )


def validate_schema2_query_shape(query: dict[str, Any]) -> None:
    if query["workload"].get("adapter") != "privacy_pool_withdrawal":
        raise ValueError("schema-2 queries require the privacy_pool_withdrawal adapter")
    if query["workload"].get("adapter_schema_version") != 1:
        raise ValueError("schema-2 queries require privacy-pool adapter version 1")
    if query["workload"].get("proof_source", {}).get("kind") != "generated":
        raise ValueError("schema-2 privacy-pool queries require generated leaf proofs")
    if query["arrivals"].get("kind") != "block_burst":
        raise ValueError("schema-2 queries require block_burst arrivals")
    if query["arrivals"].get("burst_count") != 6:
        raise ValueError("schema-2 screening requires burst_count = 6")
    if float(query["arrivals"].get("period_seconds", 0)) != float(
        query.get("assumptions", {}).get("ethereum_slot_seconds", -1)
    ):
        raise ValueError("schema-2 burst period must equal the recorded Ethereum slot duration")
    if query["root_policy"].get("kind") != "fixed_count":
        raise ValueError("schema-2 queries require fixed_count roots")
    if query.get("root_lifecycle") != "independent":
        raise ValueError("schema-2 privacy-pool roots must be independent")
    config = query["workload"].get("adapter_config", {})
    if config.get("tree_depth") != 32 or config.get("hash") != "blake2s_256":
        raise ValueError("schema-2 privacy-pool configuration must pin depth 32 and blake2s_256")
    requested_counts = (
        query["search"].get("inputs_per_root", [])
        + query["search"].get("optional_inputs_per_root", [])
    )
    if not requested_counts or int(config.get("fixture_count", 0)) < max(requested_counts):
        raise ValueError("privacy-pool fixture_count must cover all requested input counts")
    assumptions = query.get("assumptions")
    if not assumptions:
        raise ValueError("schema-2 queries require assumptions")
    if int(assumptions.get("ethereum_slot_seconds", 0)) <= 0:
        raise ValueError("schema-2 Ethereum slot duration must be positive")
    reference = int(assumptions["reference_withdrawal_gas"])
    if reference <= 0 or int(assumptions["target_block_gas"]) <= 0 or int(assumptions["block_gas_limit"]) <= 0:
        raise ValueError("schema-2 gas assumptions must be positive")
    if int(assumptions["target_withdrawals_per_block"]) != int(assumptions["target_block_gas"]) // reference:
        raise ValueError("target withdrawals must use recorded gas-limit floor division")
    if int(assumptions["maximum_withdrawals_per_block"]) != int(assumptions["block_gas_limit"]) // reference:
        raise ValueError("maximum withdrawals must use recorded gas-limit floor division")
    optional_gas = int(assumptions.get("optional_direct_withdrawal_gas", 0))
    optional_count = int(assumptions.get("optional_direct_maximum_withdrawals_per_block", 0))
    if optional_gas <= 0 or optional_count != int(assumptions["block_gas_limit"]) // optional_gas:
        raise ValueError("optional direct withdrawal count must use recorded gas-limit floor division")
    if not query["search"].get("inputs_per_root"):
        raise ValueError("schema-2 search needs inputs_per_root")
    if query["search"]["inputs_per_root"] != [2, 4, 8, 16, 32, 45, 64, 91]:
        raise ValueError("schema-2 required input counts must match the screening set")
    optional_counts = query["search"].get("optional_inputs_per_root", [])
    if optional_counts != [102] or set(optional_counts) & set(query["search"]["inputs_per_root"]):
        raise ValueError("schema-2 optional input counts must be the disjoint 102 sensitivity point")
    if query["workload"].get("leaf_log_inv_rates") != [1, 2, 3, 4]:
        raise ValueError("schema-2 leaf rates must cover log inverse rates 1 through 4")
    if query["search"]["arities"] != list(range(2, 17)):
        raise ValueError("schema-2 primary arities must cover 2 through 16")
    if query["search"].get("primary_root_log_inv_rates") != [1]:
        raise ValueError("schema-2 primary root rate must be 1/2")
    if query["search"].get("compression_root_log_inv_rates") != [2, 3, 4]:
        raise ValueError("schema-2 compression root rates must be 1/4, 1/8, and 1/16")
    if query["search"].get("diagnostic_rate_matrix_arities") != [4]:
        raise ValueError("schema-2 rate diagnostics must use arity 4")
    if query["search"].get("thread_scaling_arities") != [4, 16]:
        raise ValueError("schema-2 worker calibration must use arities 4 and 16")
    hardware = query["hardware_limits"]
    if (
        int(hardware.get("performance_workers", 0)) != 8
        or int(hardware.get("efficiency_workers", -1)) != 0
        or int(hardware.get("proving_processes", 0)) != 1
        or int(hardware.get("prover_ram_bytes", 0)) != 42_949_672_960
    ):
        raise ValueError("schema-2 hardware limits must match the screening configuration")
    if query.get("deadlines", {}).get("boundary") != "serialized" or float(
        query.get("deadlines", {}).get("max_input_to_root_seconds", 0)
    ) != float(assumptions["ethereum_slot_seconds"]):
        raise ValueError("schema-2 deadline must use the serialized boundary and one Ethereum slot")
    expected_nonfinal = [(1, 1), (2, 1), (3, 1), (4, 1)]
    actual_nonfinal = [(item["child_log_inv_rate"], item["parent_log_inv_rate"])
                       for item in query["search"]["nonfinal_rate_pairs"]]
    if actual_nonfinal != expected_nonfinal:
        raise ValueError("schema-2 non-final rate policy is not the required policy")
    expected_final = expected_nonfinal + [(1, 2), (1, 3), (1, 4)]
    actual_final = [(item["child_log_inv_rate"], item["parent_log_inv_rate"])
                    for item in query["search"]["final_rate_pairs"]]
    if actual_final != expected_final:
        raise ValueError("schema-2 final rate policy is not the required policy")


def schema2_geometry_tuples(query: dict[str, Any]) -> list[tuple[int, int, int]]:
    """Return the legal primary non-final geometry tuples."""
    return [(arity, pair["child_log_inv_rate"], pair["parent_log_inv_rate"])
            for arity in query["search"]["arities"]
            for pair in query["search"]["nonfinal_rate_pairs"]]


def schema2_diagnostic_tuples(query: dict[str, Any]) -> list[tuple[int, int, int]]:
    """Return the arity-4 rate diagnostic tuples."""
    return [(arity, child, parent)
            for arity in query["search"]["diagnostic_rate_matrix_arities"]
            for child in range(1, 5)
            for parent in range(1, 5)]


def schema2_unique_geometry_tuples(query: dict[str, Any]) -> list[tuple[int, int, int]]:
    return list(dict.fromkeys(schema2_geometry_tuples(query) + schema2_diagnostic_tuples(query)))


def schema2_geometry_execution_order(query: dict[str, Any]) -> list[tuple[int, int, int]]:
    """Put the arity 2, 4, and 16 preflight surface before the remaining tuples."""
    tuples = schema2_unique_geometry_tuples(query)
    preflight = [item for arity in (2, 4, 16) for item in tuples if item[0] == arity]
    return list(dict.fromkeys(preflight + tuples))


def schema2_campaign_configurations(query: dict[str, Any], workers: Sequence[int], smoke: bool = False,
                                    selected_rate: int | None = None) -> list[tuple[int, int, int, int, str]]:
    rates = list(query["workload"]["leaf_log_inv_rates"])
    if smoke:
        return [(2, rates[0], workers[0], 1, "smoke")]
    counts = query["search"]["inputs_per_root"]
    primary_worker = workers[0]
    priority_counts = [n for n in (45, 91) if n in counts]
    priority_counts.extend(n for n in counts if n not in priority_counts)
    configurations = [(n, rate, primary_worker, 1, "primary") for n in priority_counts for rate in rates]
    selected_rate = rates[0] if selected_rate is None else selected_rate
    configurations += [(n, selected_rate, worker, 1, "scaling")
                       for n in (16, 45, 91) for worker in workers[1:4]]
    configurations += [(n, selected_rate, primary_worker, root_rate, "compression")
                       for n in (45, 91) for root_rate in (2, 3, 4)]
    return configurations


def schema2_root_target(smoke: bool) -> int:
    return 1 if smoke else 6


def schema2_plan_filename(
    phase: str,
    inputs_per_root: int,
    leaf_log_inv_rate: int,
    root_log_inv_rate: int,
    performance_workers: int,
) -> str:
    """Return the worker-specific filename for one resolved recursion plan."""
    return (
        f"{phase}-{inputs_per_root}-{leaf_log_inv_rate}-{root_log_inv_rate}"
        f"-w{performance_workers}.json"
    )


def schema2_plan_digest(plan: dict[str, Any]) -> str:
    """Hash a resolved recursion plan using the digest stored in candidate records."""
    return hashlib.sha256(
        json.dumps(plan, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def load_schema2_plan(
    path: Path,
    expected_digest: str | None = None,
) -> tuple[dict[str, Any], str]:
    """Load a recursion plan and optionally check its recorded candidate digest."""
    plan = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(plan, dict):
        raise ValueError(f"schema-2 plan must be a JSON object: {path}")
    actual_digest = schema2_plan_digest(plan)
    if expected_digest is not None and actual_digest != expected_digest:
        raise ValueError(
            f"schema-2 plan digest mismatch for {path.name}: "
            f"expected {expected_digest}, got {actual_digest}"
        )
    return plan, actual_digest


def schema2_plan_manifests(
    output_dir: Path,
    query: dict[str, Any],
    query_sha256: str,
    query_blake2s: str,
    plan: dict[str, Any],
    plan_digest: str,
    case_prefix: str,
    program_identity: str | None,
) -> list[Path]:
    """Materialize every real parent job in a resolved plan as a recursive child specification."""
    nodes: list[dict[str, Any]] = [
        {
            "kind": "leaf",
            "fixture_index": index,
            "output_log_inv_rate": int(plan["leaf_log_inv_rate"]),
        }
        for index in range(int(plan["leaf_count"]))
    ]
    manifests: list[Path] = []
    manifest_root = output_dir / "parent-cases" / "plan" / plan_digest
    for level_index, level in enumerate(plan.get("levels", [])):
        next_nodes = []
        offset = 0
        for job_index, child_count in enumerate(level.get("child_counts", [])):
            child_count = int(child_count)
            child_specs = nodes[offset:offset + child_count]
            if len(child_specs) != child_count:
                raise ValueError("resolved plan manifest does not cover its input nodes")
            if child_count == 1:
                if int(level["child_log_inv_rate"]) != int(level["parent_log_inv_rate"]):
                    raise ValueError("a unary plan carry cannot change rate")
                next_nodes.append(child_specs[0])
            else:
                manifest_path = manifest_root / "level" / str(level_index) / "job" / f"{job_index}.json"
                manifest = {
                    "schema_version": 1,
                    "case_id": f"{case_prefix}-l{level_index}-j{job_index}",
                    "query_sha256": query_sha256,
                    "query_blake2s": query_blake2s,
                    "executed_plan_digest": plan_digest,
                    "program_identity": program_identity,
                    "workload_adapter": "privacy_pool_withdrawal",
                    "role": "final" if int(level["output_count"]) == 1 else "nonfinal",
                    "fixture_seed": int(query["workload"]["adapter_config"]["fixture_seed"]),
                    "children": child_specs,
                    "expected_fixture_indices": sorted(schema2_spec_fixture_indices(child_specs)),
                    "configuration": {
                        "arity": child_count,
                        "child_log_inv_rate": int(level["child_log_inv_rate"]),
                        "parent_log_inv_rate": int(level["parent_log_inv_rate"]),
                    },
                }
                write_json(manifest_path, manifest)
                manifests.append(manifest_path)
                next_nodes.append({
                    "kind": "parent",
                    "output_log_inv_rate": int(level["parent_log_inv_rate"]),
                    "children": child_specs,
                })
            offset += child_count
        if offset != len(nodes) or len(next_nodes) != int(level["output_count"]):
            raise ValueError("resolved plan manifest has inconsistent level counts")
        nodes = next_nodes
    if len(nodes) != 1:
        raise ValueError("resolved plan manifest did not produce one root")
    return manifests


def schema2_spec_fixture_indices(specs: Sequence[dict[str, Any]]) -> list[int]:
    indices = []
    for spec in specs:
        if spec.get("kind") == "leaf":
            indices.append(int(spec["fixture_index"]))
        elif spec.get("kind") == "parent":
            indices.extend(schema2_spec_fixture_indices(spec["children"]))
        else:
            raise ValueError("unknown plan manifest child kind")
    return indices


def schema2_logical_candidate_key(row: dict[str, Any]) -> tuple[Any, ...]:
    return (
        int(row["inputs_per_root"]),
        int(row["leaf_log_inv_rate"]),
        int(row["required_root_log_inv_rate"]),
        int(row["performance_workers"]),
        int(row.get("efficiency_workers", 0)),
        int(row.get("proving_processes", 1)),
        row["tier"],
    )


def schema2_candidate_artifacts_complete(
    candidate: dict[str, Any],
    roots: Sequence[dict[str, Any]],
    root_target: int,
) -> bool:
    """Check that a successful candidate has its complete verified root record set."""
    if candidate.get("terminal_status") != "success" or int(candidate.get("completed_roots", 0)) != root_target:
        return False
    candidate_id = candidate.get("candidate_attempt_id")
    matching = [root for root in roots if root.get("candidate_id") == candidate_id]
    if len(matching) != root_target or sorted(int(root.get("root_index", -1)) for root in matching) != list(
        range(root_target)
    ):
        return False
    expected_digest = {root.get("expected_withdrawal_list_digest") for root in matching}
    return len(expected_digest) == 1 and all(
        root.get("status") == "success"
        and root.get("parse_ok") is True
        and root.get("in_memory_verify_ok") is True
        and root.get("roundtrip_verify_ok") is True
        and int(root.get("expected_withdrawal_count", -1)) == int(candidate.get("inputs_per_root", -2))
        and root.get("executed_plan_digest") == candidate.get("executed_plan_digest")
        for root in matching
    )


def select_schema2_leaf_rate(candidates: Sequence[dict[str, Any]], deadline_seconds: float = 12.0,
                             ram_limit_bytes: int = 42_949_672_960) -> int:
    """Apply the screening rate tie-breakers to completed primary candidates."""
    rates = sorted({int(row["leaf_log_inv_rate"]) for row in candidates})
    scored = []
    for rate in rates:
        rows = [
            row
            for row in candidates
            if int(row["leaf_log_inv_rate"]) == rate and row.get("phase", "primary") == "primary"
        ]
        passing = [row for row in rows if row.get("pass") and
                   (row.get("max_serialized_input_to_root_seconds") or float("inf")) <= deadline_seconds and
                   int(row.get("peak_rss_bytes") or 0) <= ram_limit_bytes]
        max_count = max((int(row["inputs_per_root"]) for row in passing), default=-1)
        if max_count < 0:
            continue
        at_max = [row for row in passing if int(row["inputs_per_root"]) == max_count]
        latency = max((float(row.get("max_serialized_input_to_root_seconds") or float("inf")) for row in at_max), default=float("inf"))
        rss = max((int(row.get("peak_rss_bytes") or 0) for row in at_max), default=2**63 - 1)
        proof = max((int(row.get("max_serialized_root_proof_bytes") or row.get("proof_bytes") or 2**63 - 1) for row in at_max), default=2**63 - 1)
        scored.append((-max_count, latency, rss, proof, rate))
    if not scored:
        raise ValueError("no completed primary candidates available for leaf-rate selection")
    return min(scored)[-1]


def schema2_candidate_coverage_points(
    query: dict[str, Any],
    workers: Sequence[int],
    smoke: bool,
    candidates: Sequence[dict[str, Any]],
) -> tuple[int | None, list[dict[str, Any]]]:
    """Resolve the fixed screening candidate matrix against recorded attempts."""
    selected_rate = None
    if not smoke:
        try:
            selected_rate = select_schema2_leaf_rate(candidates)
        except ValueError:
            pass
    required_configurations = (
        schema2_campaign_configurations(query, workers, True)
        if smoke
        else schema2_campaign_configurations(query, workers, False, selected_rate)
        if selected_rate is not None
        else schema2_campaign_configurations(query, workers, False)[:32]
    )
    coverage = []
    for n, leaf_rate, worker, root_rate, phase in required_configurations:
        matching = [
            row
            for row in candidates
            if int(row.get("inputs_per_root", -1)) == n
            and int(row.get("leaf_log_inv_rate", -1)) == leaf_rate
            and int(row.get("performance_workers", -1)) == worker
            and int(row.get("required_root_log_inv_rate", -1)) == root_rate
            and row.get("phase") == phase
        ]
        resolved = next(
            (row for row in matching if row.get("terminal_status") in {"success", "deterministic_ram"}),
            None,
        )
        coverage.append({
            "key": {
                "inputs_per_root": n,
                "leaf_log_inv_rate": leaf_rate,
                "performance_workers": worker,
                "required_root_log_inv_rate": root_rate,
                "phase": phase,
            },
            "state": "complete" if resolved is not None else "failed" if matching else "pending",
            "attempt_id": None if resolved is None else resolved.get("candidate_attempt_id"),
            "reason": None if resolved is not None else (
                matching[-1].get("failure_reason") if matching else "not executed"
            ),
        })
    return selected_rate, coverage


def schema2_boundary_tuples(records: Sequence[dict[str, Any]]) -> list[tuple[int, int, int]]:
    """Return geometry tuples adjacent to a proof-shape boundary."""
    indexed = {}
    for record in records:
        configuration = record.get("configuration", {})
        key = (int(configuration.get("arity", 0)),
               int(configuration.get("child_log_inv_rate", 0)),
               int(configuration.get("parent_log_inv_rate", 0)))
        indexed[key] = record

    def shape(record: dict[str, Any]) -> str:
        return json.dumps((record.get("child_shape"), record.get("parent_shape")), sort_keys=True)

    boundaries = set()
    for key, record in indexed.items():
        arity, child_rate, parent_rate = key
        for neighbor in ((arity - 1, child_rate, parent_rate),
                         (arity + 1, child_rate, parent_rate),
                         (arity, child_rate - 1, parent_rate),
                         (arity, child_rate + 1, parent_rate)):
            if neighbor in indexed and shape(record) != shape(indexed[neighbor]):
                boundaries.add(key)
                boundaries.add(neighbor)
    return sorted(boundaries)


def schema2_repeat_boundary_tuples(records: Sequence[dict[str, Any]]) -> list[tuple[int, int, int]]:
    """Find shape boundaries only on the representative geometry surface."""
    return schema2_boundary_tuples([
        record
        for record in records
        if record.get("measurement_phase") == "geometry"
        and int(record.get("performance_workers", 0)) == 1
    ])


def run_json_command_monitored(
    command: Sequence[str],
    env: dict[str, str],
    timeout_seconds: float,
    collect_phase_peaks: bool = False,
    ram_limit_bytes: int | None = None,
):
    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env,
    )
    peak_rss = 0
    phase = "preparation"
    phase_peaks: dict[str, int] = {}
    phase_lock = threading.Lock()
    stderr_lines: list[str] = []

    def read_stderr() -> None:
        nonlocal phase
        for line in process.stderr:
            line = line.rstrip("\r\n")
            stderr_lines.append(line)
            if line.strip().startswith("LEANVM_BENCHMARK_PHASE="):
                with phase_lock:
                    phase = line.strip().split("=", 1)[1]

    def captured_stderr(communicate_stderr: str | None) -> str:
        captured = "\n".join(stderr_lines).strip()
        remainder = (communicate_stderr or "").strip()
        if captured and remainder and remainder not in captured:
            return f"{captured}\n{remainder}"
        return captured or remainder

    stderr_thread = threading.Thread(target=read_stderr, daemon=True)
    stderr_thread.start()
    deadline = time.monotonic() + timeout_seconds
    while process.poll() is None:
        current_rss = process_rss_bytes([process])
        peak_rss = max(peak_rss, current_rss)
        with phase_lock:
            phase_peaks[phase] = max(phase_peaks.get(phase, 0), current_rss)
        if ram_limit_bytes is not None and current_rss > ram_limit_bytes:
            terminate_processes([process])
            process.communicate()
            stderr_thread.join(timeout=1.0)
            raise RamLimitExceeded(peak_rss)
        if time.monotonic() >= deadline:
            terminate_processes([process])
            stdout, stderr = process.communicate()
            stderr_thread.join(timeout=1.0)
            raise subprocess.TimeoutExpired(
                command,
                timeout_seconds,
                output=stdout,
                stderr=captured_stderr(stderr),
            )
        time.sleep(0.05)
    stdout, stderr = process.communicate()
    stderr_thread.join(timeout=1.0)
    peak_rss = max(peak_rss, process_rss_bytes([process]))
    stderr = captured_stderr(stderr)
    if process.returncode:
        raise subprocess.CalledProcessError(process.returncode, command, output=stdout, stderr=stderr)
    lines = [line for line in stdout.splitlines() if line.strip()]
    if len(lines) != 1:
        raise ValueError(f"command emitted {len(lines)} JSON records instead of one: {stderr.strip()}")
    result = json.loads(lines[0])
    if collect_phase_peaks:
        return result, peak_rss, phase_peaks
    return result, peak_rss


def exception_text(error: BaseException, limit: int = 4_000) -> str:
    """Return a bounded failure receipt that retains subprocess diagnostics."""
    detail = ""
    if isinstance(error, subprocess.SubprocessError):
        stderr = getattr(error, "stderr", None)
        stdout = getattr(error, "output", None)
        detail = stderr or stdout or ""
        if isinstance(detail, bytes):
            detail = detail.decode(errors="replace")
        detail = str(detail).strip()
    summary = str(error)
    if not detail:
        return summary
    detail = detail[-limit:]
    return f"{summary}\n{detail}"


def run_schema2_campaign(query_path: Path, query: dict[str, Any], output_dir: Path, tier: str, smoke: bool,
                         time_budget_seconds: float, finish_reserve_seconds: float, case_timeout_seconds: float,
                         performance_worker_counts: str | None, resume: bool, geometry_parent_samples: int | None) -> None:
    if tier != "screening":
        raise ValueError("schema-2 campaigns currently accept only the screening tier")
    if (
        not math.isfinite(time_budget_seconds)
        or not math.isfinite(finish_reserve_seconds)
        or not math.isfinite(case_timeout_seconds)
        or time_budget_seconds <= 0
        or finish_reserve_seconds < 0
        or finish_reserve_seconds >= time_budget_seconds
        or case_timeout_seconds <= 0
    ):
        raise ValueError("schema-2 timeouts require a positive budget and case timeout with a smaller nonnegative reserve")
    if geometry_parent_samples is not None and geometry_parent_samples < 1:
        raise ValueError("geometry parent samples must be positive")
    started = time.monotonic()
    if output_dir.exists() and any(output_dir.iterdir()) and not resume:
        raise ValueError(f"refusing to overwrite nonempty output directory: {output_dir}")
    output_dir.mkdir(parents=True, exist_ok=True)
    workspace = query_path.parents[1]
    source_state = source_fingerprint(workspace, output_dir)
    runner_blake2s = hashlib.blake2s(Path(__file__).read_bytes()).hexdigest()
    adapter_config_blake2s = hashlib.blake2s(
        json.dumps(query["workload"]["adapter_config"], sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    raw_path = output_dir / "raw.jsonl"
    query_copy = output_dir / "query.json"
    normalized = output_dir / "normalized-query.json"
    query_bytes = query_path.read_bytes()
    query_digest = hashlib.sha256(query_bytes).hexdigest()
    query_blake2s = hashlib.blake2s(query_bytes).hexdigest()
    if resume and query_copy.exists() and json.loads(query_copy.read_text(encoding="utf-8")) != query:
        raise ValueError("--resume requires the same query")
    metadata_path = output_dir / "run-metadata.json"
    prior_metadata = None
    resume_migration = None
    compatible_source_digests = {source_state["digest"]}
    compatible_runner_digests = {runner_blake2s}
    if resume and metadata_path.exists():
        prior_metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        prior_source_digest = prior_metadata.get("source_fingerprint", {}).get("digest")
        prior_runner_digest = prior_metadata.get("runner_blake2s")
        if prior_source_digest != source_state["digest"]:
            if (
                prior_metadata.get("runner_version") == 2
                and prior_runner_digest == BOUNDARY_REPEAT_FIX_FROM_RUNNER_BLAKE2S
            ):
                resume_migration = {
                    "from_runner_version": 2,
                    "from_runner_blake2s": prior_runner_digest,
                    "from_source_fingerprint": prior_source_digest,
                    "reason": "exclude non-geometry records from representative boundary repeats",
                }
                compatible_source_digests.add(prior_source_digest)
                compatible_runner_digests.add(prior_runner_digest)
            else:
                raise ValueError("--resume requires the same commit and source fingerprint")
        if prior_metadata.get("adapter_config_blake2s") != adapter_config_blake2s:
            raise ValueError("--resume requires the same workload adapter configuration")
        if prior_metadata.get("tier") != tier or bool(prior_metadata.get("smoke")) != smoke:
            raise ValueError("--resume requires the same tier and smoke mode")
    query_copy.write_bytes(query_bytes)
    write_json(normalized, query)
    run_metadata = {
        "runner_version": RUNNER_VERSION,
        "query_sha256": query_digest,
        "started_unix_seconds": time.time(),
        "tier": tier,
        "smoke": smoke,
        "assumptions": query.get("assumptions", {}),
        "hardware_limits": query.get("hardware_limits", {}),
        "workload": query.get("workload", {}),
        "timing_boundary": query.get("deadlines", {}).get("boundary", "serialized"),
        "source_fingerprint": source_state,
        "runner_blake2s": runner_blake2s,
        "adapter_config_blake2s": adapter_config_blake2s,
    }
    if prior_metadata is not None:
        run_metadata["initial_started_unix_seconds"] = prior_metadata.get(
            "initial_started_unix_seconds", prior_metadata.get("started_unix_seconds")
        )
        run_metadata["resume_count"] = int(prior_metadata.get("resume_count", 0)) + 1
        migrations = list(prior_metadata.get("resume_migrations", []))
        if resume_migration is not None:
            migrations.append({
                **resume_migration,
                "to_runner_version": RUNNER_VERSION,
                "to_runner_blake2s": runner_blake2s,
                "to_source_fingerprint": source_state["digest"],
            })
        if migrations:
            run_metadata["resume_migrations"] = migrations
    for path in ("parent-jobs.jsonl", "parent-checkpoint.jsonl", "candidate-checkpoint.jsonl"):
        (output_dir / path).touch()
    (output_dir / "leaf-cache").mkdir(exist_ok=True)
    raw_path.touch()
    build_allowance = time_budget_seconds - (time.monotonic() - started) - finish_reserve_seconds
    if build_allowance <= 0:
        raise TimeoutError("time budget reserve was reached before the release build")
    binary = build_binary(workspace, build_allowance)
    binary_sha256 = hashlib.sha256(binary.read_bytes()).hexdigest()
    if prior_metadata is not None and prior_metadata.get("release_binary_sha256") not in {
        None,
        binary_sha256,
    }:
        raise ValueError("--resume requires the same release binary")
    run_metadata["release_binary_sha256"] = binary_sha256
    write_json(metadata_path, run_metadata)
    if resume_migration is not None:
        print("resume compatibility: applying the schema-2 boundary-repeat runner fix", file=sys.stderr)
    subprocess.run([str(binary), "recursion-benchmark-validate", "--query", str(query_path)], check=True,
                   timeout=max(1.0, time_budget_seconds - (time.monotonic() - started)))
    counts = [2] if smoke else list(query["search"]["inputs_per_root"])
    rates = list(query["workload"]["leaf_log_inv_rates"])
    workers = [int(value) for value in performance_worker_counts.split(",")] if performance_worker_counts else [8, 4, 2, 1]
    workers = list(dict.fromkeys(workers))
    if smoke:
        if performance_worker_counts is not None and workers != [1]:
            raise ValueError("schema-2 smoke mode requires exactly one performance worker")
        workers = [1]
    elif workers != [8, 4, 2, 1]:
        raise ValueError("schema-2 screening requires performance workers 8,4,2,1 in that order")
    maximum_workers = int(query["hardware_limits"]["performance_workers"])
    if not workers or any(worker < 1 or worker > maximum_workers for worker in workers):
        raise ValueError(f"performance worker counts must be within 1..={maximum_workers}")
    reuse_base = {
        "query_sha256": query_digest,
        "binary_sha256": binary_sha256,
        "source_fingerprint": source_state["digest"],
        "runner_blake2s": runner_blake2s,
        "adapter_config_blake2s": adapter_config_blake2s,
        "workload_adapter": query["workload"]["adapter"],
        "workload_adapter_schema_version": query["workload"]["adapter_schema_version"],
        "tier": tier,
    }
    candidates = []
    roots = []
    pending = []
    if resume and raw_path.exists():
        for line in raw_path.read_text(encoding="utf-8").splitlines():
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            if entry.get("record_type") == "candidate" and entry.get("candidate"):
                candidates.append(entry["candidate"])
            elif entry.get("record_type") == "root" and entry.get("root"):
                roots.append(entry["root"])
    target_root_count = schema2_root_target(smoke)
    completed_required_logical_keys = {
        schema2_logical_candidate_key(row)
        for row in candidates
        if schema2_candidate_artifacts_complete(row, roots, target_root_count)
        and row.get("query_sha256") == query_digest
        and row.get("binary_sha256") == binary_sha256
        and row.get("source_fingerprint") in compatible_source_digests
        and row.get("runner_blake2s") in compatible_runner_digests
    }
    completed_keys = set()

    def normalized_checkpoint_key(value: Any) -> str | None:
        if not isinstance(value, dict):
            return None
        if (
            value.get("query_sha256") != query_digest
            or value.get("binary_sha256") != binary_sha256
            or value.get("source_fingerprint") not in compatible_source_digests
            or value.get("runner_blake2s") not in compatible_runner_digests
            or value.get("adapter_config_blake2s") != adapter_config_blake2s
        ):
            return None
        normalized_key = dict(value)
        normalized_key["source_fingerprint"] = source_state["digest"]
        normalized_key["runner_blake2s"] = runner_blake2s
        return json.dumps(normalized_key, sort_keys=True)

    if resume:
        for line in (output_dir / "candidate-checkpoint.jsonl").read_text(encoding="utf-8").splitlines():
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            if ((entry.get("status") == "success"
                    and entry.get("completed_roots") == schema2_root_target(smoke)
                    or entry.get("status") == "deterministic_ram")
                    and entry.get("query_sha256") == query_digest
                    and entry.get("binary_sha256") == binary_sha256):
                key = normalized_checkpoint_key(entry.get("key"))
                if key is not None:
                    completed_keys.add(key)
        for line in (output_dir / "parent-checkpoint.jsonl").read_text(encoding="utf-8").splitlines():
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            if entry.get("status") in {"success", "deterministic_ram"}:
                key = normalized_checkpoint_key(entry.get("key"))
                if key is not None:
                    completed_keys.add(key)
    geometry_records = []
    if resume:
        for line in (output_dir / "parent-jobs.jsonl").read_text(encoding="utf-8").splitlines():
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            if record.get("record_type") == "parent_job":
                geometry_records.append(record)
    if not smoke:
        geometry_samples = geometry_parent_samples or 1
        for arity, child_rate, parent_rate in schema2_unique_geometry_tuples(query):
            manifest_path = output_dir / "parent-cases" / "representative" / f"{arity}-{child_rate}-{parent_rate}.json"
            write_json(manifest_path, {
                "schema_version": 1,
                "case_id": f"privacy-pool-{arity}-{child_rate}-{parent_rate}",
                "query_sha256": query_digest,
                "query_blake2s": query_blake2s,
                "workload_adapter": "privacy_pool_withdrawal",
                "fixture_seed": int(query["workload"]["adapter_config"]["fixture_seed"]),
                "fixture_indices": list(range(arity)),
                "configuration": {
                    "arity": arity,
                    "child_log_inv_rate": child_rate,
                    "parent_log_inv_rate": parent_rate,
                },
            })
        for arity, child_rate, parent_rate in schema2_geometry_execution_order(query):
            key = {**reuse_base, "arity": arity, "child_log_inv_rate": child_rate, "parent_log_inv_rate": parent_rate,
                   "fixture_seed": int(query["workload"]["adapter_config"]["fixture_seed"]), "phase": "geometry"}
            allowed = min(case_timeout_seconds, time_budget_seconds - (time.monotonic() - started) - finish_reserve_seconds)
            if allowed <= 0:
                pending.append({"key": key, "state": "pending", "reason": "time budget reserve"})
                continue
            command = [str(binary), "privacy-pool-capacity-case", "--query", str(query_path), "--arity", str(arity),
                       "--child-log-inv-rate", str(child_rate), "--parent-log-inv-rate", str(parent_rate),
                       "--role", "nonfinal" if (child_rate, parent_rate) in {
                           (item["child_log_inv_rate"], item["parent_log_inv_rate"])
                           for item in query["search"]["nonfinal_rate_pairs"]
                       } else "diagnostic", "--repeat", str(geometry_samples),
                       "--performance-workers", "1",
                       "--leaf-cache-dir", str(output_dir / "leaf-cache")]
            manifest_path = output_dir / "parent-cases" / "representative" / (
                f"{arity}-{child_rate}-{parent_rate}.json"
            )
            manifest_path.parent.mkdir(parents=True, exist_ok=True)
            write_json(manifest_path, {
                "schema_version": 1,
                "case_id": f"privacy-pool-{arity}-{child_rate}-{parent_rate}",
                "query_sha256": query_digest,
                "query_blake2s": query_blake2s,
                "workload_adapter": "privacy_pool_withdrawal",
                "fixture_seed": int(query["workload"]["adapter_config"]["fixture_seed"]),
                "fixture_indices": list(range(arity)),
                "configuration": {"arity": arity, "child_log_inv_rate": child_rate,
                                   "parent_log_inv_rate": parent_rate},
            })
            manifest_digest = hashlib.blake2s(manifest_path.read_bytes()).hexdigest()
            key["workload_case_blake2s"] = manifest_digest
            if resume and json.dumps(key, sort_keys=True) in completed_keys:
                continue
            command += ["--workload-case", str(manifest_path), "--workload-case-digest",
                        manifest_digest]
            try:
                record, observed_peak_rss = run_json_command_monitored(
                    command, native_environment(1, 0), allowed,
                    ram_limit_bytes=int(query["hardware_limits"]["prover_ram_bytes"]),
                )
                record["observed_peak_rss_bytes"] = observed_peak_rss
                record["measurement_phase"] = "geometry"
                record["workload_case_blake2s"] = hashlib.blake2s(manifest_path.read_bytes()).hexdigest()
                geometry_records.append(record)
                append_jsonl(output_dir / "parent-jobs.jsonl", record)
                append_jsonl(output_dir / "parent-checkpoint.jsonl", {"key": key, "status": "success", "record": record})
            except (subprocess.SubprocessError, json.JSONDecodeError, KeyError, ValueError, RamLimitExceeded) as error:
                status = "deterministic_ram" if isinstance(error, RamLimitExceeded) else "failed"
                failure_text = exception_text(error)
                failure = {"key": key, "status": status, "error": failure_text}
                pending.append({"key": key, "state": "failed", "reason": failure_text})
                append_jsonl(output_dir / "parent-checkpoint.jsonl", failure)
                append_jsonl(raw_path, {"record_type": "parent_job_failure", **failure})
        # Measure the worker-scaling calibration surface before selecting a
        # leaf rate. These records are capacity data, not planner permission
        # for diagnostic rate pairs.
        for worker in (workers[0],):
            for arity in (4, 16):
                for child_rate in rates:
                    key = {**reuse_base, "arity": arity, "child_log_inv_rate": child_rate,
                           "parent_log_inv_rate": 1,
                           "fixture_seed": int(query["workload"]["adapter_config"]["fixture_seed"]),
                           "worker": worker, "phase": "calibration"}
                    manifest_path = output_dir / "parent-cases" / "representative" / f"{arity}-{child_rate}-1.json"
                    manifest_digest = hashlib.blake2s(manifest_path.read_bytes()).hexdigest()
                    key["workload_case_blake2s"] = manifest_digest
                    if resume and json.dumps(key, sort_keys=True) in completed_keys:
                        continue
                    allowed = min(case_timeout_seconds, time_budget_seconds - (time.monotonic() - started) - finish_reserve_seconds)
                    if allowed <= 0:
                        pending.append({"key": key, "state": "pending", "reason": "time budget reserve"})
                        continue
                    command = [str(binary), "privacy-pool-capacity-case", "--query", str(query_path), "--arity", str(arity),
                               "--child-log-inv-rate", str(child_rate), "--parent-log-inv-rate", "1",
                               "--role", "nonfinal", "--repeat", "1",
                               "--performance-workers", str(worker),
                               "--leaf-cache-dir", str(output_dir / "leaf-cache"),
                               "--workload-case", str(manifest_path), "--workload-case-digest", manifest_digest]
                    try:
                        record, observed_peak_rss = run_json_command_monitored(
                            command, native_environment(worker, 0), allowed,
                            ram_limit_bytes=int(query["hardware_limits"]["prover_ram_bytes"]),
                        )
                        record["observed_peak_rss_bytes"] = observed_peak_rss
                        record["measurement_phase"] = "calibration"
                        geometry_records.append(record)
                        append_jsonl(output_dir / "parent-jobs.jsonl", record)
                        append_jsonl(output_dir / "parent-checkpoint.jsonl", {
                            "key": key, "status": "success", "record": record,
                        })
                    except (subprocess.SubprocessError, json.JSONDecodeError, KeyError, ValueError, RamLimitExceeded) as error:
                        status = "deterministic_ram" if isinstance(error, RamLimitExceeded) else "failed"
                        failure_text = exception_text(error)
                        failure = {"key": key, "status": status, "error": failure_text}
                        pending.append({"key": key, "state": "failed", "reason": failure_text})
                        append_jsonl(output_dir / "parent-checkpoint.jsonl", failure)
    write_schema2_capacity_artifacts(output_dir, geometry_records)

    def ensure_selected_rate_calibrations(selected_rate: int) -> None:
        pairs = list(dict.fromkeys([(selected_rate, 1), (1, 1)]))
        for worker in workers[1:]:
            if worker == 1:
                continue
            for arity in (4, 16):
                for child_rate, parent_rate in pairs:
                    manifest_path = (
                        output_dir / "parent-cases" / "representative" /
                        f"{arity}-{child_rate}-{parent_rate}.json"
                    )
                    manifest_digest = hashlib.blake2s(manifest_path.read_bytes()).hexdigest()
                    key = {
                        **reuse_base,
                        "arity": arity,
                        "child_log_inv_rate": child_rate,
                        "parent_log_inv_rate": parent_rate,
                        "fixture_seed": int(query["workload"]["adapter_config"]["fixture_seed"]),
                        "worker": worker,
                        "phase": "selected_rate_calibration",
                        "workload_case_blake2s": manifest_digest,
                    }
                    if resume and json.dumps(key, sort_keys=True) in completed_keys:
                        continue
                    allowed = min(
                        case_timeout_seconds,
                        time_budget_seconds - (time.monotonic() - started) - finish_reserve_seconds,
                    )
                    if allowed <= 0:
                        pending.append({"key": key, "state": "pending", "reason": "time budget reserve"})
                        continue
                    command = [
                        str(binary), "privacy-pool-capacity-case", "--query", str(query_path),
                        "--arity", str(arity), "--child-log-inv-rate", str(child_rate),
                        "--parent-log-inv-rate", str(parent_rate), "--role", "nonfinal",
                        "--repeat", "1", "--performance-workers", str(worker),
                        "--leaf-cache-dir", str(output_dir / "leaf-cache"),
                        "--workload-case", str(manifest_path),
                        "--workload-case-digest", manifest_digest,
                    ]
                    try:
                        record, observed_peak_rss = run_json_command_monitored(
                            command,
                            native_environment(worker, 0),
                            allowed,
                            ram_limit_bytes=int(query["hardware_limits"]["prover_ram_bytes"]),
                        )
                        record["observed_peak_rss_bytes"] = observed_peak_rss
                        record["measurement_phase"] = "selected_rate_calibration"
                        geometry_records.append(record)
                        append_jsonl(output_dir / "parent-jobs.jsonl", record)
                        append_jsonl(
                            output_dir / "parent-checkpoint.jsonl",
                            {"key": key, "status": "success", "record": record},
                        )
                    except (
                        subprocess.SubprocessError,
                        json.JSONDecodeError,
                        KeyError,
                        ValueError,
                        RamLimitExceeded,
                    ) as error:
                        status = "deterministic_ram" if isinstance(error, RamLimitExceeded) else "failed"
                        failure_text = exception_text(error)
                        failure_record = {"key": key, "status": status, "error": failure_text}
                        pending.append({"key": key, "state": "failed", "reason": failure_text})
                        append_jsonl(output_dir / "parent-checkpoint.jsonl", failure_record)
        write_schema2_capacity_artifacts(output_dir, geometry_records)

    def measure_compressed_final_parent(
        baseline_path: Path,
        inputs_per_root: int,
        leaf_rate: int,
        parent_rate: int,
        worker: int,
    ) -> dict[str, Any] | None:
        baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
        baseline_digest = hashlib.sha256(
            json.dumps(baseline, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        final_level_index = len(baseline.get("levels", [])) - 1
        if final_level_index < 0 or len(baseline["levels"][-1].get("child_counts", [])) != 1:
            pending.append({
                "key": {"inputs_per_root": inputs_per_root, "leaf_log_inv_rate": leaf_rate,
                        "parent_log_inv_rate": parent_rate},
                "state": "failed",
                "reason": "compression baseline has no single final parent job",
            })
            return None
        baseline_manifest_path = (
            output_dir / "parent-cases" / "plan" / baseline_digest /
            "level" / str(final_level_index) / "job" / "0.json"
        )
        if not baseline_manifest_path.exists():
            pending.append({
                "key": {"baseline_plan_digest": baseline_digest, "parent_log_inv_rate": parent_rate},
                "state": "failed",
                "reason": "compression baseline final-parent manifest is missing",
            })
            return None
        manifest = json.loads(baseline_manifest_path.read_text(encoding="utf-8"))
        manifest.pop("executed_plan_digest", None)
        manifest["case_id"] = f"compression-{inputs_per_root}-{leaf_rate}-{parent_rate}-final"
        manifest["role"] = "final"
        manifest["baseline_plan_digest"] = baseline_digest
        manifest["configuration"]["parent_log_inv_rate"] = parent_rate
        manifest_path = (
            output_dir / "parent-cases" / "compression" / baseline_digest /
            f"root-rate-{parent_rate}.json"
        )
        write_json(manifest_path, manifest)
        manifest_digest = hashlib.blake2s(manifest_path.read_bytes()).hexdigest()
        final_level = baseline["levels"][-1]
        arity = int(final_level["child_counts"][0])
        child_rate = int(final_level["child_log_inv_rate"])
        key = {
            **reuse_base,
            "phase": "compressed_final_capacity",
            "inputs_per_root": inputs_per_root,
            "leaf_log_inv_rate": leaf_rate,
            "arity": arity,
            "child_log_inv_rate": child_rate,
            "parent_log_inv_rate": parent_rate,
            "performance_workers": worker,
            "baseline_plan_digest": baseline_digest,
            "workload_case_blake2s": manifest_digest,
        }
        existing = next(
            (
                record for record in geometry_records
                if record.get("workload_case_blake2s") == manifest_digest
                and int(record.get("performance_workers", 0)) == worker
            ),
            None,
        )
        if existing is not None:
            return existing
        if resume and json.dumps(key, sort_keys=True) in completed_keys:
            return None
        allowed = min(
            case_timeout_seconds,
            time_budget_seconds - (time.monotonic() - started) - finish_reserve_seconds,
        )
        if allowed <= 0:
            pending.append({"key": key, "state": "pending", "reason": "time budget reserve"})
            return None
        command = [
            str(binary), "privacy-pool-capacity-case", "--query", str(query_path),
            "--arity", str(arity), "--child-log-inv-rate", str(child_rate),
            "--parent-log-inv-rate", str(parent_rate), "--role", "final",
            "--repeat", "1", "--performance-workers", str(worker),
            "--leaf-cache-dir", str(output_dir / "leaf-cache"),
            "--workload-case", str(manifest_path), "--workload-case-digest", manifest_digest,
        ]
        try:
            record, observed_peak_rss = run_json_command_monitored(
                command,
                native_environment(worker, 0),
                allowed,
                ram_limit_bytes=int(query["hardware_limits"]["prover_ram_bytes"]),
            )
            record["observed_peak_rss_bytes"] = observed_peak_rss
            record["measurement_phase"] = "compressed_final_capacity"
            geometry_records.append(record)
            append_jsonl(output_dir / "parent-jobs.jsonl", record)
            append_jsonl(
                output_dir / "parent-checkpoint.jsonl",
                {"key": key, "status": "success", "record": record},
            )
            write_schema2_capacity_artifacts(output_dir, geometry_records)
            return record
        except (
            subprocess.SubprocessError,
            json.JSONDecodeError,
            KeyError,
            ValueError,
            RamLimitExceeded,
        ) as error:
            status = "deterministic_ram" if isinstance(error, RamLimitExceeded) else "failed"
            failure_text = exception_text(error)
            pending.append({"key": key, "state": "failed", "reason": failure_text})
            append_jsonl(
                output_dir / "parent-checkpoint.jsonl",
                {"key": key, "status": status, "error": failure_text},
            )
            return None

    if smoke:
        configurations = schema2_campaign_configurations(query, workers, True)
    else:
        configurations = schema2_campaign_configurations(query, workers, False)[:32]
    followups_added = False
    if not smoke and sum(row.get("phase") == "primary" for row in candidates) >= 32:
        try:
            selected_rate = select_schema2_leaf_rate(candidates)
        except ValueError as error:
            pending.append({
                "key": {"phase": "leaf_rate_selection"},
                "state": "pending",
                "reason": exception_text(error),
            })
        else:
            ensure_selected_rate_calibrations(selected_rate)
            configurations.extend(schema2_campaign_configurations(query, workers, False, selected_rate)[32:])
            followups_added = True
    for n, leaf_rate, worker, root_rate, phase in configurations:
                key = {**reuse_base, "inputs_per_root": n, "leaf_log_inv_rate": leaf_rate, "required_root_log_inv_rate": root_rate,
                       "performance_workers": worker, "efficiency_workers": 0, "proving_processes": 1,
                       "tier": tier, "phase": phase}
                if resume and schema2_logical_candidate_key(key) in completed_required_logical_keys:
                    continue
                allowed = min(case_timeout_seconds, time_budget_seconds - (time.monotonic() - started) - finish_reserve_seconds)
                if allowed <= 0:
                    pending.append({"key": key, "state": "pending", "reason": "time budget reserve"})
                    continue
                plan_path = output_dir / "plans" / schema2_plan_filename(
                    phase,
                    n,
                    leaf_rate,
                    root_rate,
                    worker,
                )
                plan_path.parent.mkdir(parents=True, exist_ok=True)
                if phase == "compression" and not smoke:
                    baseline_path = output_dir / "plans" / schema2_plan_filename(
                        "primary",
                        n,
                        leaf_rate,
                        1,
                        worker,
                    )
                    if not baseline_path.exists():
                        pending.append({"key": key, "state": "pending", "reason": "baseline plan is missing"})
                        continue
                    baseline_candidate = next((
                        candidate
                        for candidate in reversed(candidates)
                        if candidate.get("phase") == "primary"
                        and int(candidate.get("inputs_per_root", -1)) == n
                        and int(candidate.get("leaf_log_inv_rate", -1)) == leaf_rate
                        and int(candidate.get("required_root_log_inv_rate", -1)) == 1
                        and int(candidate.get("performance_workers", -1)) == worker
                    ), None)
                    baseline_digest = None if baseline_candidate is None else baseline_candidate.get(
                        "executed_plan_digest"
                    )
                    if not baseline_digest:
                        pending.append({
                            "key": key,
                            "state": "pending",
                            "reason": "baseline plan digest is missing",
                        })
                        continue
                    try:
                        original_baseline, _ = load_schema2_plan(
                            baseline_path,
                            str(baseline_digest),
                        )
                    except (json.JSONDecodeError, OSError, ValueError) as error:
                        pending.append({
                            "key": key,
                            "state": "failed",
                            "reason": f"baseline plan: {error}",
                        })
                        continue
                    final_parent_record = measure_compressed_final_parent(
                        baseline_path, n, leaf_rate, root_rate, worker
                    )
                    if final_parent_record is None:
                        pending.append({
                            "key": key,
                            "state": "pending",
                            "reason": "compressed final-parent capacity measurement is unavailable",
                        })
                        continue
                    baseline = json.loads(json.dumps(original_baseline))
                    if not baseline.get("levels"):
                        raise ValueError("compression baseline plan has no recursive levels")
                    baseline_final_cost = baseline["levels"][-1].get("estimated_service_seconds", 0.0)
                    baseline["levels"][-1]["parent_log_inv_rate"] = root_rate
                    baseline["root_log_inv_rate"] = root_rate
                    baseline["query_blake2s"] = query_blake2s
                    baseline["baseline_plan_digest"] = schema2_plan_digest(original_baseline)
                    final_level = baseline["levels"][-1]
                    final_level["estimated_service_seconds"] = float(
                        final_parent_record["mean_service_seconds"]
                    )
                    final_level["estimated_output_bytes"] = int(final_parent_record["proof_bytes"])
                    final_level["estimated_peak_rss_bytes"] = int(
                        final_parent_record.get("observed_peak_rss_bytes", 0)
                    )
                    baseline["estimated_service_seconds"] = max(
                        0.0,
                        baseline.get("estimated_service_seconds", 0.0)
                        - baseline_final_cost
                        + final_level["estimated_service_seconds"],
                    )
                    baseline["estimated_peak_rss_bytes"] = max(
                        int(original_baseline.get("estimated_peak_rss_bytes", 0)),
                        final_level["estimated_peak_rss_bytes"],
                    )
                    baseline["estimated_root_proof_bytes"] = final_level["estimated_output_bytes"]
                    baseline["all_job_costs_directly_measured"] = bool(
                        original_baseline.get("all_job_costs_directly_measured", False)
                    ) and bool(final_parent_record.get("verified", False))
                    write_json(plan_path, baseline)
                elif smoke:
                    smoke_plan = {
                        "leaf_count": n, "leaf_log_inv_rate": leaf_rate,
                        "root_log_inv_rate": root_rate,
                        "query_blake2s": query_blake2s,
                        "levels": [{"input_count": 2, "output_count": 1,
                                     "child_log_inv_rate": leaf_rate,
                                     "parent_log_inv_rate": root_rate,
                                     "child_counts": [2],
                                     "estimated_service_seconds": 0.0}],
                        "total_jobs": 1, "estimated_service_seconds": 0.0,
                        "estimated_peak_rss_bytes": 0,
                        "all_job_costs_directly_measured": False,
                    }
                    write_json(plan_path, smoke_plan)
                else:
                    try:
                        plan_record, _ = run_json_command_monitored(
                            [str(binary), "privacy-pool-plan", "--query", str(query_path),
                             "--costs", str(output_dir / "capacity.json"),
                             "--inputs-per-root", str(n), "--leaf-log-inv-rate", str(leaf_rate),
                             "--root-log-inv-rate", str(root_rate),
                             "--performance-workers", str(worker)],
                            native_environment(1, 0), allowed,
                        )
                    except (subprocess.SubprocessError, json.JSONDecodeError, KeyError, ValueError) as error:
                        pending.append({"key": key, "state": "failed", "reason": f"plan resolution: {error}"})
                        continue
                    plan_record["query_blake2s"] = query_blake2s
                    write_json(plan_path, plan_record)
                executed_plan, plan_digest = load_schema2_plan(plan_path)
                schema2_plan_manifests(
                    output_dir,
                    query,
                    query_digest,
                    query_blake2s,
                    executed_plan,
                    plan_digest,
                    f"{phase}-{n}-{leaf_rate}-{root_rate}",
                    next(
                        (record.get("program_identity") for record in geometry_records
                         if record.get("program_identity")),
                        None,
                    ),
                )
                key["executed_plan_digest"] = plan_digest
                key["parent_costs_blake2s"] = hashlib.blake2s(
                    (output_dir / "capacity.json").read_bytes()
                ).hexdigest()
                key["query_sha256"] = query_digest
                key["binary_sha256"] = binary_sha256
                if resume and json.dumps(key, sort_keys=True) in completed_keys:
                    continue
                roots_for_candidate = []
                failure = None
                ram_failure = False
                campaign_result: dict[str, Any] = {}
                phase_peaks: dict[str, int] = {}
                target_roots = schema2_root_target(smoke)
                command = [str(binary), "recursion-benchmark-case", "--query", str(query_path),
                           "--inputs-per-root", str(n), "--leaf-log-inv-rate", str(leaf_rate),
                           "--root-log-inv-rate", str(root_rate), "--root-target", str(target_roots), "--run-id",
                           f"schema2-{n}-{leaf_rate}-{worker}-{root_rate}", "--leaf-cache-dir",
                           str(output_dir / "leaf-cache"), "--fixed-plan", str(plan_path)]
                observed_peak_rss = 0
                try:
                    allowed = min(
                        case_timeout_seconds,
                        time_budget_seconds - (time.monotonic() - started) - finish_reserve_seconds,
                    )
                    if allowed <= 0:
                        raise TimeoutError("time budget reserve")
                    record, observed_peak_rss, phase_peaks = run_json_command_monitored(
                        command,
                        native_environment(worker, 0),
                        allowed,
                        collect_phase_peaks=True,
                        ram_limit_bytes=int(query["hardware_limits"]["prover_ram_bytes"]),
                    )
                    campaign_result = record["result"]
                    roots_for_candidate = list(campaign_result["roots"])
                    for result in roots_for_candidate:
                        result["observed_peak_rss_bytes"] = observed_peak_rss
                        result["preparation_peak_rss_bytes"] = phase_peaks.get("preparation", observed_peak_rss)
                        result["timed_proving_peak_rss_bytes"] = phase_peaks.get("timed_proving", observed_peak_rss)
                        result["post_run_verification_peak_rss_bytes"] = phase_peaks.get(
                            "post_verification", observed_peak_rss
                        )
                except RamLimitExceeded as error:
                    observed_peak_rss = error.peak_rss_bytes
                    failure = exception_text(error)
                    ram_failure = True
                except (subprocess.SubprocessError, json.JSONDecodeError, KeyError, ValueError, TimeoutError) as error:
                    failure = exception_text(error)
                deadline_seconds = float(query["deadlines"]["max_input_to_root_seconds"])
                complete = (
                    failure is None
                    and campaign_result.get("status") == "success"
                    and int(campaign_result.get("completed_roots", 0)) == target_roots
                    and len(roots_for_candidate) == target_roots
                    and all(
                        root.get("status") == "success"
                        and root.get("parse_ok")
                        and root.get("in_memory_verify_ok")
                        and root.get("roundtrip_verify_ok")
                        for root in roots_for_candidate
                    )
                )
                max_latency = max(
                    (root["serialized_input_to_root_seconds"] for root in roots_for_candidate), default=None
                )
                within_deadline = complete and max_latency is not None and max_latency <= deadline_seconds
                within_ram = observed_peak_rss <= int(query["hardware_limits"]["prover_ram_bytes"])
                passed = complete and within_deadline and within_ram
                if failure is None and max_latency is not None and not within_deadline:
                    failure = f"serialized input-to-root deadline exceeded ({max_latency:.6f}s > {deadline_seconds:.6f}s)"
                if failure is None and not complete:
                    failure = "candidate did not return the required verified roots"
                latencies = [float(root["serialized_input_to_root_seconds"]) for root in roots_for_candidate]
                intervals = [
                    float(root["root_interval_seconds"])
                    for root in roots_for_candidate
                    if root.get("root_interval_seconds") is not None
                ]
                actual_rates = {int(root["actual_root_log_inv_rate"]) for root in roots_for_candidate}
                phase_rss = {
                    name: max((int(root.get(name, 0)) for root in roots_for_candidate), default=0)
                    for name in (
                        "preparation_peak_rss_bytes",
                        "timed_proving_peak_rss_bytes",
                        "post_run_verification_peak_rss_bytes",
                    )
                }
                peak_rss = max(observed_peak_rss, *phase_rss.values())
                row = {
                    **key,
                    "candidate_attempt_id": f"{phase}-{n}-{leaf_rate}-{worker}-{root_rate}",
                    "workload_adapter": query["workload"]["adapter"],
                    "tree_depth": 32,
                    "hash": "blake2s_256",
                    "block_period_seconds": float(query["arrivals"]["period_seconds"]),
                    "derived_average_inputs_per_second": n / float(query["arrivals"]["period_seconds"]),
                    "actual_root_log_inv_rate": next(iter(actual_rates)) if len(actual_rates) == 1 else None,
                    "completed_roots": len(roots_for_candidate),
                    "completed_inputs": len(roots_for_candidate) * n,
                    "leaf_preparation_seconds": campaign_result.get("leaf_preparation_seconds"),
                    "leaf_cache_hits": campaign_result.get("leaf_cache_hits"),
                    "leaf_cache_misses": campaign_result.get("leaf_cache_misses"),
                    "max_serialized_input_to_root_seconds": max_latency,
                    "median_serialized_input_to_root_seconds": statistics.median(latencies) if latencies else None,
                    "max_root_interval_seconds_diagnostic": max(intervals, default=None),
                    **phase_rss,
                    "peak_rss_bytes": peak_rss,
                    "max_serialized_root_proof_bytes": max(
                        (int(root["serialized_root_proof_bytes"]) for root in roots_for_candidate),
                        default=None,
                    ),
                    **summarize_native_root_timings(roots_for_candidate),
                    "all_roots_verified_against_expected": complete,
                    "all_job_costs_directly_measured": bool(
                        executed_plan.get("all_job_costs_directly_measured", False)
                    ),
                    "pass": passed and not smoke,
                    "terminal_status": (
                        "deterministic_ram" if ram_failure else "success" if complete else "failed"
                    ),
                    "failure_reason": failure or ("smoke data" if smoke else ""),
                    "program_identity": campaign_result.get("program_identity"),
                    "plan_path": str(plan_path),
                    "executed_plan_digest": plan_digest,
                    "baseline_plan_digest": executed_plan.get("baseline_plan_digest"),
                }
                candidates.append(row)
                append_jsonl(raw_path, {"record_type": "candidate", "candidate": row})
                for index, result in enumerate(roots_for_candidate):
                    root = {"candidate_id": row["candidate_attempt_id"], "root_index": index,
                            "executed_plan_digest": plan_digest,
                            "baseline_plan_digest": executed_plan.get("baseline_plan_digest"),
                            **native_root_timing_fields(result),
                            **result}
                    roots.append(root)
                    append_jsonl(raw_path, {"record_type": "root", "root": root})
                append_jsonl(output_dir / "candidate-checkpoint.jsonl", {
                    "key": key,
                    "status": "deterministic_ram" if ram_failure else ("success" if complete else "failed"),
                    "completed_roots": len(roots_for_candidate),
                    "query_sha256": query_digest,
                    "binary_sha256": binary_sha256,
                    "executed_plan_digest": plan_digest,
                })
                if not smoke and not followups_added and phase == "primary" and sum(row.get("phase") == "primary" for row in candidates) >= 32:
                    try:
                        selected_rate = select_schema2_leaf_rate(candidates)
                    except ValueError as error:
                        pending.append({
                            "key": {"phase": "leaf_rate_selection"},
                            "state": "pending",
                            "reason": exception_text(error),
                        })
                    else:
                        ensure_selected_rate_calibrations(selected_rate)
                        configurations.extend(
                            schema2_campaign_configurations(query, workers, False, selected_rate)[32:]
                        )
                        followups_added = True

    if not smoke:
        repeat_manifests: list[tuple[Path, str, str]] = []
        for arity, child_rate, parent_rate in schema2_repeat_boundary_tuples(geometry_records):
            path = output_dir / "parent-cases" / "representative" / f"{arity}-{child_rate}-{parent_rate}.json"
            role = "nonfinal" if (child_rate, parent_rate) in {
                (item["child_log_inv_rate"], item["parent_log_inv_rate"])
                for item in query["search"]["nonfinal_rate_pairs"]
            } else "diagnostic"
            repeat_manifests.append((path, role, "boundary_repeat"))
        exact_shapes = set()
        for n in (45, 91):
            for leaf_rate in rates:
                primary_candidate = next((
                    candidate
                    for candidate in reversed(candidates)
                    if candidate.get("phase") == "primary"
                    and int(candidate.get("inputs_per_root", -1)) == n
                    and int(candidate.get("leaf_log_inv_rate", -1)) == leaf_rate
                    and int(candidate.get("required_root_log_inv_rate", -1)) == 1
                    and int(candidate.get("performance_workers", -1)) == workers[0]
                ), None)
                if primary_candidate is None or not primary_candidate.get("executed_plan_digest"):
                    continue
                plan_path = output_dir / "plans" / schema2_plan_filename(
                    "primary",
                    n,
                    leaf_rate,
                    1,
                    workers[0],
                )
                if not plan_path.exists():
                    continue
                plan, plan_digest = load_schema2_plan(
                    plan_path,
                    str(primary_candidate["executed_plan_digest"]),
                )
                for path in sorted((output_dir / "parent-cases" / "plan" / plan_digest).glob("level/*/job/*.json")):
                    manifest = json.loads(path.read_text(encoding="utf-8"))
                    shape_key = hashlib.blake2s(json.dumps({
                        "children": manifest["children"],
                        "configuration": manifest["configuration"],
                        "program_identity": manifest.get("program_identity"),
                    }, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
                    if shape_key in exact_shapes:
                        continue
                    exact_shapes.add(shape_key)
                    repeat_manifests.append((path, manifest["role"], "plan_shape_repeat"))
        for manifest_path, role, phase in repeat_manifests:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            config = manifest["configuration"]
            manifest_digest = hashlib.blake2s(manifest_path.read_bytes()).hexdigest()
            existing_samples = sum(
                len(record.get("aggregation_seconds", []))
                for record in geometry_records
                if record.get("workload_case_blake2s") == manifest_digest
                and int(record.get("performance_workers", 0)) == 1
            )
            additional = max(0, 3 - existing_samples)
            if additional == 0:
                continue
            key = {
                **reuse_base,
                "phase": phase,
                "arity": int(config["arity"]),
                "child_log_inv_rate": int(config["child_log_inv_rate"]),
                "parent_log_inv_rate": int(config["parent_log_inv_rate"]),
                "performance_workers": 1,
                "workload_case_blake2s": manifest_digest,
            }
            if resume and json.dumps(key, sort_keys=True) in completed_keys:
                continue
            allowed = min(
                case_timeout_seconds,
                time_budget_seconds - (time.monotonic() - started) - finish_reserve_seconds,
            )
            if allowed <= 0:
                pending.append({"key": key, "state": "pending", "reason": "time budget reserve"})
                continue
            command = [
                str(binary), "privacy-pool-capacity-case", "--query", str(query_path),
                "--arity", str(config["arity"]),
                "--child-log-inv-rate", str(config["child_log_inv_rate"]),
                "--parent-log-inv-rate", str(config["parent_log_inv_rate"]),
                "--role", role, "--repeat", str(additional), "--performance-workers", "1",
                "--leaf-cache-dir", str(output_dir / "leaf-cache"),
                "--workload-case", str(manifest_path), "--workload-case-digest", manifest_digest,
            ]
            try:
                record, observed_peak_rss = run_json_command_monitored(
                    command,
                    native_environment(1, 0),
                    allowed,
                    ram_limit_bytes=int(query["hardware_limits"]["prover_ram_bytes"]),
                )
                record["observed_peak_rss_bytes"] = observed_peak_rss
                record["measurement_phase"] = phase
                geometry_records.append(record)
                append_jsonl(output_dir / "parent-jobs.jsonl", record)
                append_jsonl(
                    output_dir / "parent-checkpoint.jsonl",
                    {"key": key, "status": "success", "record": record},
                )
            except (
                subprocess.SubprocessError,
                json.JSONDecodeError,
                KeyError,
                ValueError,
                RamLimitExceeded,
            ) as error:
                status = "deterministic_ram" if isinstance(error, RamLimitExceeded) else "failed"
                failure_text = exception_text(error)
                pending.append({"key": key, "state": "failed", "reason": failure_text})
                append_jsonl(
                    output_dir / "parent-checkpoint.jsonl",
                    {"key": key, "status": status, "error": failure_text},
                )
    selected_rate, candidate_coverage = schema2_candidate_coverage_points(
        query,
        workers,
        smoke,
        candidates,
    )
    geometry_coverage = []
    for arity, child_rate, parent_rate in ([] if smoke else schema2_unique_geometry_tuples(query)):
        matching = [
            record for record in geometry_records
            if record.get("measurement_phase") == "geometry"
            and int(record.get("configuration", {}).get("arity", -1)) == arity
            and int(record.get("configuration", {}).get("child_log_inv_rate", -1)) == child_rate
            and int(record.get("configuration", {}).get("parent_log_inv_rate", -1)) == parent_rate
        ]
        geometry_coverage.append({
            "key": {"arity": arity, "child_log_inv_rate": child_rate, "parent_log_inv_rate": parent_rate},
            "state": "complete" if matching else "pending",
        })
    capacity_requirements = []
    if not smoke:
        capacity_requirements.extend(
            {
                "measurement_phase": "calibration",
                "arity": arity,
                "child_log_inv_rate": child_rate,
                "parent_log_inv_rate": 1,
                "performance_workers": workers[0],
            }
            for arity in (4, 16)
            for child_rate in rates
        )
        if selected_rate is not None:
            for worker in workers[1:3]:
                for arity in (4, 16):
                    for child_rate, parent_rate in dict.fromkeys(((selected_rate, 1), (1, 1))):
                        capacity_requirements.append({
                            "measurement_phase": "selected_rate_calibration",
                            "arity": arity,
                            "child_log_inv_rate": child_rate,
                            "parent_log_inv_rate": parent_rate,
                            "performance_workers": worker,
                        })
            capacity_requirements.extend(
                {
                    "measurement_phase": "compressed_final_capacity",
                    "workload_case_id": f"compression-{n}-{selected_rate}-{root_rate}-final",
                    "performance_workers": workers[0],
                }
                for n in (45, 91)
                for root_rate in (2, 3, 4)
            )
    capacity_coverage = []
    for requirement in capacity_requirements:
        def matches_requirement(record: dict[str, Any]) -> bool:
            configuration = record.get("configuration", {})
            for field, expected in requirement.items():
                actual = configuration.get(field, record.get(field))
                if actual != expected:
                    return False
            return True

        matching = [record for record in geometry_records if matches_requirement(record)]
        capacity_coverage.append({
            "key": requirement,
            "state": "complete" if matching else "pending",
        })
    completed_candidates = sum(point["state"] == "complete" for point in candidate_coverage)
    completed_geometry = sum(point["state"] == "complete" for point in geometry_coverage)
    completed_capacity = sum(point["state"] == "complete" for point in capacity_coverage)
    required_candidate_count = 1 if smoke else 47
    coverage_complete = (
        not smoke
        and selected_rate is not None
        and len(candidate_coverage) == required_candidate_count
        and completed_candidates == required_candidate_count
        and completed_geometry == 72
        and completed_capacity == len(capacity_requirements)
        and not pending
    )
    run_status = "smoke only" if smoke else "complete screening" if coverage_complete else "partial screening coverage"
    coverage = {
        "schema_version": 2,
        "run_status": run_status,
        "required_candidates": required_candidate_count,
        "completed_candidates": completed_candidates,
        "candidate_points": candidate_coverage,
        "required_geometry": 0 if smoke else 72,
        "completed_geometry": completed_geometry,
        "geometry_points": geometry_coverage,
        "required_capacity_calibrations": len(capacity_requirements),
        "completed_capacity_calibrations": completed_capacity,
        "capacity_points": capacity_coverage,
        "selected_leaf_log_inv_rate": selected_rate,
        "pending": pending,
        "time_budget_seconds": time_budget_seconds,
        "finish_reserve_seconds": finish_reserve_seconds,
        "elapsed_seconds": time.monotonic() - started,
        "complete": coverage_complete,
    }
    write_json(output_dir / "candidates.json", {"schema_version": 2, "candidates": candidates})
    write_json(output_dir / "coverage.json", coverage)
    write_schema2_capacity_artifacts(output_dir, geometry_records)
    write_json(output_dir / "summary.json", {
        "schema_version": 2,
        "run_status": run_status,
        "partial": not coverage_complete,
        "run_metadata": run_metadata,
        "coverage": coverage,
        "candidates": candidates,
        "roots": roots,
        "pending": pending,
    })
    write_rows_csv(output_dir / "candidates.csv", SCHEMA2_CANDIDATE_FIELDS, candidates)
    write_rows_csv(output_dir / "roots.csv", SCHEMA2_ROOT_FIELDS, roots)
    passing_by_rate = {}
    for rate in rates:
        passing = [
            row for row in candidates
            if row.get("phase") == "primary"
            and int(row.get("leaf_log_inv_rate", -1)) == rate
            and row.get("pass")
        ]
        passing_by_rate[rate] = max((int(row["inputs_per_root"]) for row in passing), default=None)
    def seconds(value: Any) -> str:
        return "" if value is None else f"{float(value):.3f}"

    def gibibytes(value: Any) -> str:
        return "" if value is None else f"{int(value) / (1 << 30):.2f}"

    critical_lines = [
        "| Withdrawals | Leaf log inverse rate | Result | Max latency (s) | Peak RSS (GiB) |",
        "| ---: | ---: | :--- | ---: | ---: |",
    ]
    for n in (45, 91):
        for rate in rates:
            row = next((
                row for row in candidates
                if row.get("phase") == "primary"
                and int(row.get("inputs_per_root", -1)) == n
                and int(row.get("leaf_log_inv_rate", -1)) == rate
            ), None)
            result = "missing" if row is None else "pass" if row.get("pass") else "fail"
            critical_lines.append(
                f"| {n} | {rate} | {result} | {seconds(None if row is None else row.get('max_serialized_input_to_root_seconds'))} | "
                f"{gibibytes(None if row is None else row.get('peak_rss_bytes'))} |"
            )
    scaling_rows = [row for row in candidates if row.get("phase") == "scaling"]
    compression_rows = [row for row in candidates if row.get("phase") == "compression"]
    scaling_lines = [
        "| Withdrawals | Workers | Result | Max latency (s) | Peak RSS (GiB) |",
        "| ---: | ---: | :--- | ---: | ---: |",
    ]
    if selected_rate is not None:
        for n in (16, 45, 91):
            for worker in workers:
                expected_phase = "primary" if worker == workers[0] else "scaling"
                row = next((
                    row for row in candidates
                    if row.get("phase") == expected_phase
                    and int(row.get("inputs_per_root", -1)) == n
                    and int(row.get("leaf_log_inv_rate", -1)) == selected_rate
                    and int(row.get("performance_workers", -1)) == worker
                ), None)
                result = "missing" if row is None else "pass" if row.get("pass") else "fail"
                scaling_lines.append(
                    f"| {n} | {worker} | {result} | {seconds(None if row is None else row.get('max_serialized_input_to_root_seconds'))} | "
                    f"{gibibytes(None if row is None else row.get('peak_rss_bytes'))} |"
                )
    else:
        scaling_lines.append("|  |  | leaf rate not selected |  |  |")
    compression_lines = [
        "| Withdrawals | Root log inverse rate | Result | Max latency (s) | Peak RSS (GiB) | Max proof bytes |",
        "| ---: | ---: | :--- | ---: | ---: | ---: |",
    ]
    for n in (45, 91):
        for root_rate in (2, 3, 4):
            row = next((
                row for row in compression_rows
                if int(row.get("inputs_per_root", -1)) == n
                and int(row.get("required_root_log_inv_rate", -1)) == root_rate
            ), None)
            result = "missing" if row is None else "pass" if row.get("pass") else "fail"
            compression_lines.append(
                f"| {n} | {root_rate} | {result} | {seconds(None if row is None else row.get('max_serialized_input_to_root_seconds'))} | "
                f"{gibibytes(None if row is None else row.get('peak_rss_bytes'))} | "
                f"{'' if row is None else row.get('max_serialized_root_proof_bytes', '')} |"
            )
    parent_lines = []
    geometry_only = [
        record for record in geometry_records
        if record.get("measurement_phase") == "geometry"
        and int(record.get("performance_workers", 0)) == 1
    ]
    for child_rate in rates:
        legal = [
            record for record in geometry_only
            if int(record.get("configuration", {}).get("child_log_inv_rate", -1)) == child_rate
            and int(record.get("configuration", {}).get("parent_log_inv_rate", -1)) == 1
        ]
        if legal:
            fastest = min(legal, key=lambda record: float(record["mean_service_seconds"]))
            parent_lines.append(
                f"- {child_rate} -> 1: fastest measured arity {fastest['configuration']['arity']} at "
                f"{float(fastest['mean_service_seconds']):.3f} seconds."
            )
        else:
            parent_lines.append(f"- {child_rate} -> 1: missing.")
    missing_points = [
        {"key": point["key"], "reason": point.get("reason", "not completed")}
        for group in (candidate_coverage, geometry_coverage, capacity_coverage)
        for point in group
        if point["state"] != "complete"
    ] + pending
    report_lines = [
        f"# Privacy Pool withdrawal {run_status}",
        "",
        f"Largest passing withdrawals per root by leaf log inverse rate: {passing_by_rate}.",
        "",
        "## N=45 and N=91",
        "",
        *critical_lines,
        "",
        "## Selected leaf rate and worker scaling",
        "",
        f"Selected leaf log inverse rate: {selected_rate if selected_rate is not None else 'none'}.",
        f"Recorded scaling configurations: {len(scaling_rows)} of 9.",
        "",
        *scaling_lines,
        "",
        "## Final root compression",
        "",
        f"Recorded compression configurations: {len(compression_rows)} of 6.",
        "",
        *compression_lines,
        "",
        "## Parent geometry",
        "",
        f"Recorded primary geometry tuples: {completed_geometry} of {0 if smoke else 72}.",
        f"Total parent capacity records, including calibration and repeats: {len(geometry_records)}.",
        "",
        *parent_lines,
        "",
        "## Provenance and limits",
        "",
        f"Query SHA-256: `{query_digest}`.",
        f"Git commit: `{source_state['git_commit']}`.",
        f"Source fingerprint: `{source_state['digest']}`.",
        f"Release binary SHA-256: `{binary_sha256}`.",
        f"Hardware: {detected_hardware()['description']}.",
        "Workload: Privacy Pool withdrawal, two depth-32 Merkle paths, BLAKE2s-256.",
        f"Timing boundary: serialized input-to-root with a {query['assumptions']['ethereum_slot_seconds']}-second block period.",
        "Each screening candidate uses six roots; smoke mode uses one root.",
        "Native root validation is measured after all roots serialize and is excluded from input-to-root latency.",
        "",
        "## Missing points",
        "",
    ]
    if missing_points:
        report_lines.extend(f"- `{item['key']}`: {item['reason']}" for item in missing_points)
    else:
        report_lines.append("No pending work was recorded.")
    (output_dir / "summary.md").write_text("\n".join(report_lines) + "\n", encoding="utf-8")


def write_interrupted_schema2_artifacts(
    output_dir: Path,
    query: dict[str, Any],
    smoke: bool,
    reason: str,
    time_budget_seconds: float,
    finish_reserve_seconds: float,
    elapsed_seconds: float,
) -> None:
    """Normalize append-only progress after an interrupted operational phase."""
    output_dir.mkdir(parents=True, exist_ok=True)

    def jsonl_records(path: Path) -> list[dict[str, Any]]:
        if not path.exists():
            return []
        records = []
        for line in path.read_text(encoding="utf-8").splitlines():
            try:
                value = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(value, dict):
                records.append(value)
        return records

    raw = jsonl_records(output_dir / "raw.jsonl")
    candidates = [entry["candidate"] for entry in raw if isinstance(entry.get("candidate"), dict)]
    roots = [entry["root"] for entry in raw if isinstance(entry.get("root"), dict)]
    parent_records = [
        record
        for record in jsonl_records(output_dir / "parent-jobs.jsonl")
        if record.get("record_type") == "parent_job"
    ]
    workers = [1] if smoke else [8, 4, 2, 1]
    selected_rate, candidate_points = schema2_candidate_coverage_points(
        query,
        workers,
        smoke,
        candidates,
    )
    geometry_points = []
    for arity, child_rate, parent_rate in ([] if smoke else schema2_unique_geometry_tuples(query)):
        complete = any(
            record.get("measurement_phase") == "geometry"
            and int(record.get("configuration", {}).get("arity", -1)) == arity
            and int(record.get("configuration", {}).get("child_log_inv_rate", -1)) == child_rate
            and int(record.get("configuration", {}).get("parent_log_inv_rate", -1)) == parent_rate
            for record in parent_records
        )
        geometry_points.append({
            "key": {
                "arity": arity,
                "child_log_inv_rate": child_rate,
                "parent_log_inv_rate": parent_rate,
            },
            "state": "complete" if complete else "pending",
            "reason": None if complete else "campaign interrupted before measurement",
        })
    coverage = {
        "schema_version": 2,
        "run_status": "smoke only" if smoke else "partial screening coverage",
        "complete": False,
        "required_geometry": 0 if smoke else 72,
        "completed_geometry": sum(point["state"] == "complete" for point in geometry_points),
        "geometry_points": geometry_points,
        "required_candidates": 1 if smoke else 47,
        "completed_candidates": sum(point["state"] == "complete" for point in candidate_points),
        "candidate_points": candidate_points,
        "required_capacity_calibrations": 0,
        "completed_capacity_calibrations": 0,
        "capacity_points": [],
        "selected_leaf_log_inv_rate": selected_rate,
        "pending": [{"key": {"phase": "campaign"}, "state": "pending", "reason": reason}],
        "interruption_reason": reason,
        "time_budget_seconds": time_budget_seconds,
        "finish_reserve_seconds": finish_reserve_seconds,
        "elapsed_seconds": elapsed_seconds,
    }
    metadata = {}
    metadata_path = output_dir / "run-metadata.json"
    if metadata_path.exists():
        try:
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            metadata = {}
    write_json(output_dir / "candidates.json", {"schema_version": 2, "candidates": candidates})
    write_json(output_dir / "coverage.json", coverage)
    write_schema2_capacity_artifacts(output_dir, parent_records)
    write_json(
        output_dir / "summary.json",
        {
            "schema_version": 2,
            "run_status": coverage["run_status"],
            "partial": True,
            "run_metadata": metadata,
            "coverage": coverage,
            "candidates": candidates,
            "roots": roots,
            "pending": coverage["pending"],
        },
    )
    write_rows_csv(output_dir / "candidates.csv", SCHEMA2_CANDIDATE_FIELDS, candidates)
    write_rows_csv(output_dir / "roots.csv", SCHEMA2_ROOT_FIELDS, roots)
    for path in ("raw.jsonl", "parent-jobs.jsonl", "parent-checkpoint.jsonl", "candidate-checkpoint.jsonl"):
        (output_dir / path).touch(exist_ok=True)
    (output_dir / "summary.md").write_text(
        "# Privacy Pool withdrawal partial screening coverage\n\n"
        f"The campaign stopped before all required points completed: {reason}.\n\n"
        f"Completed candidate records: {len(candidates)}. Completed parent geometry tuples: "
        f"{coverage['completed_geometry']} of {coverage['required_geometry']}.\n",
        encoding="utf-8",
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--spec", required=True, type=Path, help="Versioned application query JSON")
    parser.add_argument("--tier", required=True, choices=sorted(TIERS))
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--resume", action="store_true", help="Reuse completed parent-job checkpoints")
    parser.add_argument("--smoke", action="store_true", help="Run one N=2 schema-2 smoke case without winner selection")
    parser.add_argument("--time-budget-seconds", type=float, default=43200.0)
    parser.add_argument("--finish-reserve-seconds", type=float, default=1800.0)
    parser.add_argument("--case-timeout-seconds", type=float, default=3600.0)
    parser.add_argument(
        "--performance-worker-counts",
        help="Comma-separated total performance-worker counts to test; defaults to powers of two and the query maximum",
    )
    parser.add_argument(
        "--geometry-parent-samples",
        type=int,
        help="Override the tier's repetition count for the one-thread parent geometry baseline",
    )
    parser.add_argument(
        "--calibration-only-parent-model",
        action="store_true",
        help="Choose direct candidates from thread-calibration jobs without measuring the one-thread geometry surface",
    )
    args = parser.parse_args()
    workspace = Path(__file__).resolve().parents[1]
    query_path = args.spec.resolve()
    query = json.loads(query_path.read_text(encoding="utf-8"))
    validate_query_shape(query)
    if query["schema_version"] == 2:
        output_dir = args.output.resolve()
        schema2_started = time.monotonic()
        try:
            run_schema2_campaign(
                query_path,
                query,
                output_dir,
                args.tier,
                args.smoke,
                args.time_budget_seconds,
                args.finish_reserve_seconds,
                args.case_timeout_seconds,
                args.performance_worker_counts,
                args.resume,
                args.geometry_parent_samples,
            )
        except (KeyboardInterrupt, TimeoutError, subprocess.SubprocessError, RamLimitExceeded, OSError) as error:
            write_interrupted_schema2_artifacts(
                output_dir,
                query,
                args.smoke,
                f"{type(error).__name__}: {exception_text(error)}",
                args.time_budget_seconds,
                args.finish_reserve_seconds,
                time.monotonic() - schema2_started,
            )
            raise
        return
    requested_performance_worker_counts = None
    if args.performance_worker_counts:
        requested_performance_worker_counts = list(dict.fromkeys(
            int(value) for value in args.performance_worker_counts.split(",") if value.strip()
        ))
        maximum_workers = int(query["hardware_limits"]["performance_workers"])
        if not requested_performance_worker_counts or any(
            value < 1 or value > maximum_workers for value in requested_performance_worker_counts
        ):
            raise ValueError(
                f"--performance-worker-counts must contain values from 1 through {maximum_workers}"
            )
    if args.geometry_parent_samples is not None and args.geometry_parent_samples < 1:
        raise ValueError("--geometry-parent-samples must be positive")
    if args.calibration_only_parent_model and query["search"].get("parent_measurement_mode", "full") != "adaptive":
        raise ValueError("--calibration-only-parent-model requires adaptive parent measurement")
    args.output.mkdir(parents=True, exist_ok=True)
    output_dir = args.output.resolve()
    raw_path = output_dir / "raw.jsonl"
    saved_query_path = output_dir / "query.json"
    if args.resume and saved_query_path.exists():
        saved_query = json.loads(saved_query_path.read_text(encoding="utf-8"))
        if saved_query != query:
            raise ValueError("cannot resume because the saved query differs from --spec")
    elif not args.resume and raw_path.exists():
        raise ValueError("output already contains benchmark artifacts; use a new directory or --resume")
    if not raw_path.exists():
        raw_path.write_text("", encoding="utf-8")
    write_json(saved_query_path, query)
    binary = build_binary(workspace)
    subprocess.run(
        [str(binary), "recursion-benchmark-validate", "--query", str(query_path)],
        check=True,
    )
    hardware = detected_hardware()
    append_jsonl(
        raw_path,
        {
            "record_type": "run_header",
            "tier": args.tier,
            "hardware": hardware,
            "query": query,
            "resumed": args.resume,
            "requested_performance_worker_counts": requested_performance_worker_counts,
            "geometry_parent_samples": args.geometry_parent_samples,
            "calibration_only_parent_model": args.calibration_only_parent_model,
        },
    )

    cost_cache: dict[tuple[int, int], Path] = {}
    parent_job_failures: list[dict[str, Any]] = []
    candidates: list[dict[str, Any]] = []
    tested_topologies: set[tuple[int, int, int]] = set()
    base_allocation = {"performance_workers": 1, "efficiency_workers": 0}
    parent_measurement_mode = query["search"].get("parent_measurement_mode", "full")

    def base_costs() -> Path:
        key = base_allocation["performance_workers"], base_allocation["efficiency_workers"]
        if key not in cost_cache:
            cost_cache[key] = measure_job_costs(
                binary,
                query,
                base_allocation,
                args.geometry_parent_samples or TIERS[args.tier]["parent_samples"],
                output_dir,
                raw_path,
                parent_job_failures,
            )
        return cost_cache[key]

    def costs_for(topology: dict[str, Any]) -> list[Path]:
        paths = []
        for allocation in topology["worker_allocations"]:
            key = allocation["performance_workers"], allocation["efficiency_workers"]
            if key not in cost_cache:
                if parent_measurement_mode == "adaptive" and allocation != base_allocation:
                    calibration_path = measure_job_costs(
                        binary,
                        query,
                        allocation,
                        TIERS[args.tier]["parent_samples"],
                        output_dir,
                        raw_path,
                        parent_job_failures,
                        case_arities=query["search"].get("thread_scaling_arities", [4, 16]),
                        artifact_suffix="scaling",
                    )
                    if args.calibration_only_parent_model:
                        cost_cache[key] = model_job_costs_from_calibration(
                            calibration_path,
                            query,
                            allocation,
                            output_dir,
                        )
                    else:
                        cost_cache[key] = model_job_costs_for_allocation(
                            base_costs(),
                            calibration_path,
                            base_allocation,
                            allocation,
                            output_dir,
                        )
                else:
                    cost_cache[key] = base_costs() if allocation == base_allocation else measure_job_costs(
                        binary,
                        query,
                        allocation,
                        TIERS[args.tier]["parent_samples"],
                        output_dir,
                        raw_path,
                        parent_job_failures,
                    )
            paths.append(cost_cache[key])
        return paths

    def test_topology(topology: dict[str, Any]) -> None:
        key = topology_key(topology)
        if key in tested_topologies:
            return
        tested_topologies.add(key)
        cost_paths = costs_for(topology)
        for leaf_rate in query["workload"]["leaf_log_inv_rates"]:
            candidates.extend(
                search_rate(
                    binary,
                    output_dir / "query.json",
                    query,
                    topology,
                    cost_paths,
                    leaf_rate,
                    args.tier,
                    raw_path,
                )
            )

    initial = initial_topologies(query["hardware_limits"])
    if requested_performance_worker_counts is not None:
        initial = [
            topology
            for topology in initial
            if topology["performance_workers"] in requested_performance_worker_counts
        ]
    for topology in initial:
        if topology_preserves_root_policy(query, topology):
            test_topology(topology)
    while True:
        feasible = [candidate for candidate in candidates if candidate["passes"]]
        if not feasible:
            break
        current_winner = max(feasible, key=winner_sort_key)
        neighbors = [
            topology
            for topology in neighboring_topologies(current_winner["topology"], query["hardware_limits"])
            if topology_preserves_root_policy(query, topology)
            and topology_key(topology) not in tested_topologies
            and (
                requested_performance_worker_counts is None
                or topology["performance_workers"] in requested_performance_worker_counts
            )
        ]
        if not neighbors:
            break
        for topology in neighbors:
            test_topology(topology)

    candidates.sort(
        key=lambda result: (
            result["requested_input_rate"],
            result["topology"]["performance_workers"],
            result["topology"]["efficiency_workers"],
            result["topology"]["processes"],
            result["leaf_log_inv_rate"],
        )
    )
    feasible = [candidate for candidate in candidates if candidate["passes"]]
    winner = max(feasible, key=winner_sort_key, default=None)
    closest_candidate = winner or min(
        candidates,
        key=lambda result: (
            sum(not item["passes"] for item in result["constraints"]),
            -result["requested_input_rate"],
        ),
        default=None,
    )
    summary = {
        "schema_version": SCHEMA_VERSION,
        "tier": args.tier,
        "claim": {
            "screening": "screened candidate",
            "standard": "provisional greatest passing directly tested rate",
            "publication": "validated greatest passing directly tested rate",
        }[args.tier],
        "hardware": hardware,
        "winner": winner,
        "closest_candidate": closest_candidate,
        "tested_candidate_count": len(candidates),
        "no_feasible_configuration": winner is None,
        "parent_job_failures": parent_job_failures,
    }
    write_json(output_dir / "summary.json", summary)
    write_json(
        output_dir / "candidates.json",
        {
            "schema_version": SCHEMA_VERSION,
            "tier": args.tier,
            "hardware": hardware,
            "query": query,
            "candidates": candidates,
            "parent_job_failures": parent_job_failures,
        },
    )
    write_candidate_csv(output_dir / "candidates.csv", candidates)
    write_capacity_csv(output_dir)
    print(output_dir / "summary.json")


if __name__ == "__main__":
    main()
