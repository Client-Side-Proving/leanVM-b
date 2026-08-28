#!/usr/bin/env python3
"""Search and validate a recursive STARK aggregation configuration from a JSON query."""

from __future__ import annotations

import argparse
import ctypes
import csv
import json
import math
import os
import platform
import random
import statistics
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Sequence


SCHEMA_VERSION = 1
NATIVE_RUSTFLAGS = "-C target-cpu=native"
TIERS = {
    "screening": {"parent_samples": 3, "roots": 6, "fresh_runs": 1},
    "standard": {"parent_samples": 10, "roots": 30, "fresh_runs": 1},
    "publication": {"parent_samples": 10, "roots": 100, "fresh_runs": 3},
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
        capture_output=True,
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
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def append_jsonl(path: Path, value: Any) -> None:
    with path.open("a", encoding="utf-8") as output:
        output.write(json.dumps(value, separators=(",", ":")) + "\n")


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


def build_binary(workspace: Path) -> Path:
    environment = native_environment(1, 0)
    subprocess.run(
        ["cargo", "build", "--release", "--bin", "leanvm-b"],
        cwd=workspace,
        env=environment,
        check=True,
    )
    executable = "leanvm-b.exe" if os.name == "nt" else "leanvm-b"
    return workspace / "target" / "release" / executable


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
    if query["schema_version"] != SCHEMA_VERSION:
        raise ValueError(f"query schema_version must be {SCHEMA_VERSION}")
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


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--spec", required=True, type=Path, help="Versioned application query JSON")
    parser.add_argument("--tier", required=True, choices=sorted(TIERS))
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--resume", action="store_true", help="Reuse completed parent-job checkpoints")
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
    requested_performance_worker_counts = None
    if args.performance_worker_counts:
        requested_performance_worker_counts = sorted(
            {int(value) for value in args.performance_worker_counts.split(",") if value.strip()}
        )
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
