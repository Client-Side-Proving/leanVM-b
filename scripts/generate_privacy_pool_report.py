#!/usr/bin/env python3
"""Generate the standalone Privacy Pool recursion benchmark report."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any


def read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"expected a JSON object in {path}")
    return value


def read_raw_records(input_dir: Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    candidates: list[dict[str, Any]] = []
    roots: list[dict[str, Any]] = []
    raw_path = input_dir / "raw.jsonl"
    for line_number, line in enumerate(raw_path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        value = json.loads(line)
        if not isinstance(value, dict):
            raise ValueError(f"expected a JSON object in {raw_path}:{line_number}")
        record_type = value.get("record_type")
        if record_type == "candidate":
            candidate = value.get("candidate")
            if not isinstance(candidate, dict):
                raise ValueError(f"candidate record is missing candidate in {raw_path}:{line_number}")
            candidates.append(candidate)
        elif record_type == "root":
            root = value.get("root")
            if not isinstance(root, dict):
                raise ValueError(f"root record is missing root in {raw_path}:{line_number}")
            roots.append(root)
    return candidates, roots


def candidate_rank(candidate: dict[str, Any], index: int) -> tuple[int, int, int]:
    complete = int(candidate.get("completed_roots", 0)) > 0 and bool(candidate.get("all_roots_verified_against_expected"))
    status = candidate.get("terminal_status")
    status_rank = 2 if status == "success" else 1 if status == "deterministic_ram" else 0
    return int(complete), status_rank, index


def canonical_candidates(candidates: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Choose the completed record when a resumed run contains multiple attempts."""
    selected: dict[str, tuple[tuple[int, int, int], dict[str, Any]]] = {}
    for index, candidate in enumerate(candidates):
        candidate_id = str(candidate["candidate_attempt_id"])
        ranked = candidate_rank(candidate, index), candidate
        if candidate_id not in selected or ranked[0] > selected[candidate_id][0]:
            selected[candidate_id] = ranked
    return [entry[1] for entry in selected.values()]


def load_leaf_proof_sizes(input_dir: Path) -> dict[tuple[int, int], int]:
    pattern = re.compile(r"-i(\d+)-r(\d+)\.bin$")
    sizes: dict[tuple[int, int], int] = {}
    for path in (input_dir / "leaf-cache").glob("*.bin"):
        match = pattern.search(path.name)
        if match:
            sizes[(int(match.group(2)), int(match.group(1)))] = path.stat().st_size
    return sizes


def schema2_plan_digest(plan: dict[str, Any]) -> str:
    return hashlib.sha256(
        json.dumps(plan, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def load_tree_from_manifests(
    input_dir: Path, candidate: dict[str, Any]
) -> dict[str, Any] | None:
    expected_digest = candidate.get("executed_plan_digest")
    if not expected_digest:
        return None
    level_root = input_dir / "parent-cases" / "plan" / str(expected_digest) / "level"
    if not level_root.is_dir():
        return None
    level_dirs = sorted(
        (path for path in level_root.iterdir() if path.is_dir() and path.name.isdigit()),
        key=lambda path: int(path.name),
    )
    if [int(path.name) for path in level_dirs] != list(range(len(level_dirs))):
        return None
    input_count = int(candidate["inputs_per_root"])
    levels = []
    for level_index, level_dir in enumerate(level_dirs):
        jobs: dict[int, int] = {}
        child_rates: set[int] = set()
        parent_rates: set[int] = set()
        for manifest_path in (level_dir / "job").glob("*.json"):
            if not manifest_path.stem.isdigit():
                return None
            manifest = read_json(manifest_path)
            if manifest.get("executed_plan_digest") != expected_digest:
                return None
            configuration = manifest.get("configuration")
            children = manifest.get("children")
            if not isinstance(configuration, dict) or not isinstance(children, list):
                return None
            output_index = int(manifest_path.stem)
            arity = int(configuration["arity"])
            if output_index in jobs or arity != len(children) or arity < 2:
                return None
            jobs[output_index] = arity
            child_rates.add(int(configuration["child_log_inv_rate"]))
            parent_rates.add(int(configuration["parent_log_inv_rate"]))
        if not jobs or len(child_rates) != 1 or len(parent_rates) != 1:
            return None
        output_count = input_count - sum(arity - 1 for arity in jobs.values())
        if output_count <= 0 or max(jobs) >= output_count:
            return None
        child_counts = [jobs.get(index, 1) for index in range(output_count)]
        if sum(child_counts) != input_count:
            return None
        levels.append({
            "level": level_index + 1,
            "isRoot": output_count == 1,
            "inputCount": input_count,
            "outputCount": output_count,
            "childCounts": child_counts,
            "childRate": next(iter(child_rates)),
            "parentRate": next(iter(parent_rates)),
            "estimatedSeconds": None,
        })
        input_count = output_count
    if not levels or levels[-1]["outputCount"] != 1:
        return None
    return {
        "levels": levels,
        "estimatedSeconds": None,
        "levelTimesEstimated": False,
    }


def load_tree_plan(input_dir: Path, candidate: dict[str, Any]) -> dict[str, Any] | None:
    plan_path = candidate.get("plan_path")
    if not plan_path:
        return load_tree_from_manifests(input_dir, candidate)
    local_path = input_dir / "plans" / Path(str(plan_path)).name
    if not local_path.exists():
        return load_tree_from_manifests(input_dir, candidate)
    plan = read_json(local_path)
    expected_digest = candidate.get("executed_plan_digest")
    if expected_digest and schema2_plan_digest(plan) != expected_digest:
        return load_tree_from_manifests(input_dir, candidate)
    levels = []
    for index, level in enumerate(plan.get("levels", [])):
        levels.append({
            "level": index + 1,
            "isRoot": int(level["output_count"]) == 1,
            "inputCount": int(level["input_count"]),
            "outputCount": int(level["output_count"]),
            "childCounts": [int(value) for value in level["child_counts"]],
            "childRate": int(level["child_log_inv_rate"]),
            "parentRate": int(level["parent_log_inv_rate"]),
            "estimatedSeconds": float(level["estimated_service_seconds"]),
        })
    return {
        "levels": levels,
        "estimatedSeconds": float(plan.get("estimated_service_seconds", 0)),
        "levelTimesEstimated": True,
    }


def backlog_at_next_block(
    roots: list[dict[str, Any]], block_period_seconds: float
) -> int | None:
    """Count measured roots still pending when the next block would arrive."""
    if not roots:
        return None
    arrivals = []
    completions = []
    for root in roots:
        arrival = root.get("burst_arrival_seconds")
        if arrival is None:
            return None
        arrival = float(arrival)
        completion = root.get("campaign_elapsed_at_serialization_seconds")
        if completion is None:
            latency = root.get("serialized_input_to_root_seconds")
            if latency is None:
                return None
            completion = arrival + float(latency)
        arrivals.append(arrival)
        completions.append(float(completion))
    next_block_arrival = max(arrivals) + block_period_seconds
    return sum(completion > next_block_arrival for completion in completions)


def compact_candidate(
    candidate: dict[str, Any],
    leaf_sizes: dict[tuple[int, int], int],
    roots: list[dict[str, Any]],
    input_dir: Path,
    source_index: int,
    block_period_seconds: float,
) -> dict[str, Any]:
    peak_rss = candidate.get("peak_rss_bytes")
    proof_bytes = candidate.get("max_serialized_root_proof_bytes")
    proofs = int(candidate["inputs_per_root"])
    leaf_rate = int(candidate["leaf_log_inv_rate"])
    proof_sizes = [leaf_sizes.get((leaf_rate, index)) for index in range(proofs)]
    child_proof_bytes = sum(proof_sizes) if all(size is not None for size in proof_sizes) else None
    candidate_id = str(candidate["candidate_attempt_id"])
    plan_digest = candidate.get("executed_plan_digest")
    candidate_roots_by_index = {
        int(root["root_index"]): root
        for root in roots
        if root.get("candidate_id") == candidate_id
        and root.get("status") == "success"
        and (plan_digest is None or root.get("executed_plan_digest") == plan_digest)
    }
    candidate_roots = [candidate_roots_by_index[index] for index in sorted(candidate_roots_by_index)]
    input_to_root_seconds = [
        float(root["serialized_input_to_root_seconds"])
        for root in candidate_roots
        if root.get("serialized_input_to_root_seconds") is not None
    ]
    proving_seconds = [
        float(root["proving_and_verification_seconds"]) + float(root["serialization_seconds"])
        for root in candidate_roots
        if root.get("proving_and_verification_seconds") is not None
        and root.get("serialization_seconds") is not None
    ]
    report_id = hashlib.sha256(
        f"{source_index}:{candidate_id}:{plan_digest or 'no-plan'}".encode()
    ).hexdigest()
    compact = {
        "id": report_id,
        "proofs": proofs,
        "leafRate": leaf_rate,
        "rootRate": int(candidate["required_root_log_inv_rate"]),
        "workers": int(candidate["performance_workers"]),
        "complete": candidate.get("terminal_status") == "success",
        "completedRoots": len(candidate_roots),
        "verified": bool(candidate.get("all_roots_verified_against_expected")),
        "maxLatency": candidate.get("max_serialized_input_to_root_seconds"),
        "meanLatency": None if not input_to_root_seconds else sum(input_to_root_seconds) / len(input_to_root_seconds),
        "backlogAtNextBlock": backlog_at_next_block(candidate_roots, block_period_seconds),
        "meanProvingSeconds": None if not proving_seconds else sum(proving_seconds) / len(proving_seconds),
        "peakRssGiB": None if peak_rss is None else int(peak_rss) / (1 << 30),
        "rootProofBytes": None if proof_bytes is None else int(proof_bytes),
        "childProofBytes": child_proof_bytes,
        "tree": load_tree_plan(input_dir, candidate),
    }
    if not compact["complete"]:
        compact["reason"] = "RAM limit exceeded" if candidate.get("terminal_status") == "deterministic_ram" else "Measurement did not complete"
    return compact


def compatible_query_fields(query: dict[str, Any]) -> dict[str, Any]:
    hardware = query["hardware_limits"]
    return {
        "schema_version": query["schema_version"],
        "workload": query["workload"],
        "arrivals": query["arrivals"],
        "root_policy": query["root_policy"],
        "root_lifecycle": query["root_lifecycle"],
        "deadlines": query["deadlines"],
        "network": query["network"],
        "performance_workers": hardware["performance_workers"],
        "efficiency_workers": hardware["efficiency_workers"],
        "proving_processes": hardware["proving_processes"],
    }


def build_payload(input_dirs: list[Path], hardware_description: str) -> dict[str, Any]:
    if not input_dirs:
        raise ValueError("at least one benchmark directory is required")
    input_dir = input_dirs[0]
    capacity = read_json(input_dir / "capacity.json")
    query = read_json(input_dir / "query.json")
    expected_query = compatible_query_fields(query)
    leaf_sizes = load_leaf_proof_sizes(input_dir)
    roots_per_candidate = int(query["arrivals"]["burst_count"])
    block_period_seconds = float(query["arrivals"]["period_seconds"])
    compact: list[dict[str, Any]] = []
    for source_index, source_dir in enumerate(input_dirs):
        source_query = read_json(source_dir / "query.json")
        if compatible_query_fields(source_query) != expected_query:
            raise ValueError(f"incompatible benchmark query in {source_dir}")
        raw_candidates, roots = read_raw_records(source_dir)
        for candidate in canonical_candidates(raw_candidates):
            row = compact_candidate(
                candidate,
                leaf_sizes,
                roots,
                source_dir,
                source_index,
                block_period_seconds,
            )
            if row["complete"] and row["completedRoots"] >= roots_per_candidate and row["verified"]:
                compact.append(row)
    compact.sort(
        key=lambda row: (
            row["proofs"],
            row["leafRate"],
            row["rootRate"],
            -row["workers"],
            row["peakRssGiB"],
            row["maxLatency"],
        )
    )

    workload = query["workload"]["adapter_config"]
    hardware = query["hardware_limits"]
    network = query["network"]
    geometry = []
    for record in capacity.get("parent_jobs", []):
        if record.get("measurement_phase") != "geometry" or int(record.get("performance_workers", 0)) != 1:
            continue
        config = record["configuration"]
        geometry.append({
            "arity": int(config["arity"]),
            "childRate": int(config["child_log_inv_rate"]),
            "parentRate": int(config["parent_log_inv_rate"]),
            "serviceSeconds": float(record["mean_service_seconds"]),
        })
    geometry.sort(key=lambda row: (row["parentRate"], row["childRate"], row["arity"]))

    return {
        "deadlineSeconds": float(query["deadlines"]["max_input_to_root_seconds"]),
        "blockPeriodSeconds": block_period_seconds,
        "rootsPerCandidate": roots_per_candidate,
        "treeDepth": int(workload["tree_depth"]),
        "hash": workload["hash"],
        "hardware": {
            "description": hardware_description,
            "performanceWorkers": int(hardware["performance_workers"]),
            "provingProcesses": int(hardware["proving_processes"]),
            "ramLimitGiB": int(hardware["prover_ram_bytes"]) / (1 << 30),
        },
        "network": {
            "connectedPeers": int(network["connected_peers"]),
            "rootProofRecipients": int(network["root_proof_recipients"]),
            "rollingWindowSeconds": float(network["rolling_window_seconds"]),
        },
        "candidates": compact,
        "geometry": geometry,
    }


REPORT_HTML = r'''<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src data:; object-src 'none'; base-uri 'none'; form-action 'none'">
<title>LeanVM-b Privacy Pool Benchmark</title>
<style>
:root { color-scheme: light dark; --bg:light-dark(#f6f7f9,#101214); --surface:light-dark(#fff,#171a1e); --surface-2:light-dark(#eef1f5,#20242a); --text:light-dark(#17191d,#f1f3f5); --muted:light-dark(#5e6673,#a8b0bb); --line:light-dark(#d7dce3,#343a43); --blue:light-dark(#2563eb,#6ea8fe); --orange:light-dark(#c05a00,#ff9b50); --green:light-dark(#137a46,#4ad295); --red:light-dark(#bb2d3b,#ff7580); --purple:light-dark(#7652c7,#b69cff); --shadow:light-dark(0 10px 30px rgba(18,29,48,.08),0 10px 30px rgba(0,0,0,.24)); }
* { box-sizing:border-box; }
body { margin:0; background:var(--bg); color:var(--text); font:15px/1.48 ui-sans-serif,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif; }
button,select,input { font:inherit; }
.shell { max-width:1180px; margin:0 auto; padding:28px 22px 48px; }
header { margin-bottom:20px; }
h1 { margin:0 0 6px; font-size:clamp(25px,4vw,40px); line-height:1.12; letter-spacing:-.03em; font-weight:650; }
h2 { margin:0 0 14px; font-size:19px; font-weight:650; }
h3 { margin:0; font-size:14px; font-weight:650; }
p { margin:0; }
.subhead { max-width:820px; color:var(--muted); }
.context { display:flex; gap:8px 18px; flex-wrap:wrap; color:var(--muted); font-size:13px; margin-top:14px; }
.context strong { color:var(--text); font-weight:600; }
.tabs { display:flex; gap:4px; border-bottom:1px solid var(--line); margin-bottom:22px; overflow-x:auto; }
.tabs button { border:0; border-bottom:2px solid transparent; color:var(--muted); background:transparent; padding:10px 13px; cursor:pointer; white-space:nowrap; }
.tabs button[aria-selected="true"] { color:var(--text); border-color:var(--blue); }
.tab-panel[hidden] { display:none; }
.card { background:var(--surface); border:1px solid var(--line); border-radius:12px; box-shadow:var(--shadow); }
.scenario { padding:17px 18px 18px; margin-bottom:18px; }
.scenario-head { display:flex; justify-content:space-between; align-items:baseline; gap:18px; margin-bottom:13px; }
.scenario-head h2 { margin:0; }
.scenario-note,.section-note { color:var(--muted); font-size:13px; }
.scenario-grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(230px,1fr)); gap:18px 22px; }
.control { display:grid; gap:6px; min-width:0; }
.control-title { display:flex; justify-content:space-between; gap:8px; font-size:13px; font-weight:600; }
.control-value { color:var(--blue); white-space:nowrap; font-variant-numeric:tabular-nums; }
.control small { color:var(--muted); min-height:38px; line-height:1.35; }
input[type="range"] { width:100%; accent-color:var(--blue); }
.stats { display:grid; grid-template-columns:repeat(3,minmax(0,1fr)); gap:12px; margin-bottom:12px; }
.stat { padding:17px; min-height:125px; }
.label { color:var(--muted); font-size:12px; text-transform:uppercase; letter-spacing:.055em; }
.value { margin-top:7px; font-size:clamp(22px,3vw,30px); line-height:1.08; font-weight:650; font-variant-numeric:tabular-nums; }
.detail { margin-top:8px; color:var(--muted); font-size:13px; }
.section { margin-top:24px; }
.chart-card { padding:16px 16px 10px; }
.section-head { display:flex; align-items:baseline; justify-content:space-between; gap:18px; margin-bottom:6px; }
.chart { width:100%; min-height:360px; }
.chart svg { display:block; width:100%; height:auto; overflow:visible; }
.resource-grid { display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); gap:12px; }
.resource-chart { padding:14px 14px 8px; }
.resource-chart h3 { margin-bottom:4px; }
.resource-chart .chart { min-height:240px; }
.axis,.grid { stroke:var(--line); stroke-width:1; }
.grid { opacity:.75; }
.axis-text { fill:var(--muted); font-size:12px; }
.axis-title { fill:var(--text); font-size:12px; font-weight:600; }
.deadline { stroke:var(--red); stroke-width:1.5; stroke-dasharray:6 5; }
.legend { display:flex; flex-wrap:wrap; gap:8px 18px; margin:8px 0 2px; color:var(--muted); font-size:13px; }
.legend span { display:inline-flex; align-items:center; gap:7px; }
.dot { width:10px; height:10px; border-radius:50%; display:inline-block; }
.ring { width:13px; height:13px; border:2px solid var(--blue); border-radius:50%; display:inline-block; }
.swatch { width:19px; height:3px; border-radius:2px; }
.two-col { display:grid; grid-template-columns:minmax(0,1.3fr) minmax(300px,.7fr); gap:16px; align-items:start; }
.table-card { overflow:hidden; }
.table-title { padding:14px 16px 0; }
.table-title p { color:var(--muted); font-size:13px; margin:-8px 0 12px; }
.table-wrap { overflow-x:auto; }
table { width:100%; border-collapse:collapse; }
th,td { padding:10px 12px; border-bottom:1px solid var(--line); text-align:left; vertical-align:top; }
th { color:var(--muted); font-size:12px; font-weight:600; white-space:nowrap; }
td.num,th.num { text-align:right; font-variant-numeric:tabular-nums; }
tbody tr:last-child td { border-bottom:0; }
.result { font-weight:650; }
.pass { color:var(--green); }
.fail { color:var(--red); }
.na { color:var(--muted); }
.filters { display:flex; flex-wrap:wrap; gap:12px; padding:14px 16px; border-bottom:1px solid var(--line); }
.filters label { display:grid; gap:4px; color:var(--muted); font-size:12px; }
select { min-width:130px; padding:7px 30px 7px 9px; border:1px solid var(--line); border-radius:7px; background:var(--surface); color:var(--text); }
.footnote { margin-top:22px; color:var(--muted); font-size:13px; }
@media (max-width:960px) { .scenario-grid{grid-template-columns:repeat(2,minmax(0,1fr))} .stats{grid-template-columns:1fr} .two-col,.resource-grid{grid-template-columns:1fr} }
@media (max-width:560px) { .shell{padding:20px 12px 36px} .scenario-head{display:block} .scenario-grid{grid-template-columns:1fr} }
</style>
</head>
<body>
<main class="shell">
  <header>
    <div>
      <h1>LeanVM-b Privacy Pool withdrawal</h1>
      <p class="subhead">Measured recursive proving capacity for a batch of Privacy Pool proofs arriving once per Ethereum block.</p>
      <div class="context" id="context"></div>
    </div>
  </header>
  <nav class="tabs" role="tablist" aria-label="Report sections">
    <button type="button" role="tab" aria-selected="true" aria-controls="overview">Capacity</button>
    <button type="button" role="tab" aria-selected="false" aria-controls="candidates">Measurements</button>
    <button type="button" role="tab" aria-selected="false" aria-controls="geometry">Parent geometry</button>
  </nav>
  <section class="tab-panel" id="overview" role="tabpanel">
    <section class="card scenario">
      <div class="scenario-head"><h2>Hardware and network limits</h2><p class="scenario-note">Initial network speed: 300 Mbit/s download and upload.</p></div>
      <div class="scenario-grid">
        <label class="control"><span class="control-title">Maximum performance threads <output class="control-value" id="workers-value"></output></span><small>Configurations using more performance threads are excluded.</small><input id="workers" type="range"></label>
        <label class="control"><span class="control-title">RAM limit <output class="control-value" id="ram-value"></output></span><small>Compared with measured peak RSS.</small><input id="ram" type="range" min="8" step="1"></label>
        <label class="control"><span class="control-title">Maximum input-to-root time <output class="control-value" id="deadline-value"></output></span><small>From child-proof arrival through serialized root proof.</small><input id="deadline" type="range" min="1" step="1"></label>
        <label class="control"><span class="control-title">Connected peers <output class="control-value" id="peers-value"></output></span><small>Bounds the number of peers receiving each root proof.</small><input id="peers" type="range" min="1" max="200" step="1"></label>
        <label class="control"><span class="control-title">Root-proof recipients <output class="control-value" id="recipients-value"></output></span><small>Each serialized root proof is sent once to every selected recipient.</small><input id="recipients" type="range" min="0" step="1"></label>
        <label class="control"><span class="control-title">Available download speed <output class="control-value" id="ingress-value"></output></span><small>Compare with the child proofs downloaded when a block arrives.</small><input id="ingress" type="range" min="-1" max="4" step="0.05"></label>
        <label class="control"><span class="control-title">Available upload speed <output class="control-value" id="egress-value"></output></span><small>Compare with root proofs uploaded to the selected recipients.</small><input id="egress" type="range" min="-1" max="4" step="0.05"></label>
      </div>
    </section>
    <div class="stats" id="stats"></div>
    <section class="card chart-card section">
      <div class="section-head"><h2>Tested batch size and input-to-root time</h2><p class="section-note">Logarithmic time scale</p></div>
      <div class="legend"><span><i class="dot" style="background:var(--green)"></i>Meets selected limits</span><span><i class="dot" style="background:var(--red)"></i>Fails at least one selected limit</span><span><i class="ring"></i>Selected configuration</span></div>
      <div class="chart" id="capacity-chart"></div>
    </section>
    <section class="section">
      <div class="section-head"><h2>Limits by batch size</h2></div>
      <div class="legend"><span><i class="dot" style="background:var(--green)"></i>Within this limit</span><span><i class="dot" style="background:var(--red)"></i>Over this limit</span><span><i class="ring"></i>Selected configuration</span></div>
      <div class="resource-grid" id="resource-charts"></div>
    </section>
    <div class="two-col section">
      <section class="card table-card"><div class="table-title"><h2>Selected configuration against the limits</h2></div><div class="table-wrap"><table id="limits-table"></table></div></section>
      <section class="card table-card"><div class="table-title"><h2>Why the next larger batch fails</h2></div><div class="table-wrap"><table id="next-capacity-table"></table></div></section>
    </div>
    <section class="card table-card section"><div class="table-title"><h2>Selected aggregation tree</h2><p id="tree-note"></p></div><div class="table-wrap"><table id="tree-table"></table></div></section>
    <p class="footnote">Each result covers six block arrivals, 12 seconds apart. At each arrival, all proofs for that block are supplied together; a root does not wait for proofs from later blocks. A configuration is admitted when every measured batch meets the selected input-to-root limit and all six roots are complete before the next block arrival. Ethereum inclusion of the root is outside this benchmark. Child proofs are prepared before timing starts. All serialized child proofs are counted as downloads. Each serialized root proof is counted once per recipient as an upload. The benchmark calculates network requirements from proof sizes; it does not transmit data over a network.</p>
  </section>
  <section class="tab-panel" id="candidates" role="tabpanel" hidden>
    <section class="card table-card"><div class="filters"><label>Proofs per root<select id="proofs-filter"></select></label><label>Leaf WHIR rate<select id="leaf-filter"></select></label><label>Performance threads<select id="workers-filter"></select></label></div><div class="table-wrap"><table id="candidate-table"></table></div></section>
  </section>
  <section class="tab-panel" id="geometry" role="tabpanel" hidden>
    <section class="card chart-card"><div class="section-head"><h2>Representative parent proving time</h2><p class="section-note">Parent WHIR rate 1/2 · one performance thread · logarithmic time scale</p></div><div class="legend" id="geometry-legend"></div><div class="chart" id="geometry-chart"></div></section>
    <p class="footnote">Times are measured means. The arity-16 point for child WHIR rate 1/2 was terminated by the operating system.</p>
  </section>
</main>
<script>
const DATA=__REPORT_DATA__;
const RATE_COLORS=["var(--blue)","var(--orange)","var(--green)","var(--purple)"];
const rateLabel=value=>`1/${2**Number(value)}`;
const fmt=(value,digits=3)=>value==null?"—":Number(value).toLocaleString(undefined,{minimumFractionDigits:digits,maximumFractionDigits:digits});
const esc=value=>String(value).replace(/[&<>"']/g,char=>({"&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;","'":"&#039;"})[char]);
const measuredWorkers=[...new Set(DATA.candidates.map(row=>row.workers))].sort((a,b)=>a-b);
const maxLatency=Math.ceil(Math.max(...DATA.candidates.map(row=>Number(row.maxLatency||0))));
const state={workers:DATA.hardware.performanceWorkers,deadline:DATA.deadlineSeconds,ramGiB:DATA.hardware.ramLimitGiB,connectedPeers:DATA.network.connectedPeers,rootRecipients:DATA.network.rootProofRecipients,ingressMbps:300,egressMbps:300};

function formatRate(value){if(value>=1e6)return`${fmt(value/1e6,2)} Tbit/s`;if(value>=1e3)return`${fmt(value/1e3,2)} Gbit/s`;return`${fmt(value,value<10?2:1)} Mbit/s`;}
function intrinsicPass(row){return row.complete&&row.completedRoots>=DATA.rootsPerCandidate&&row.verified&&row.maxLatency!=null&&row.meanLatency!=null&&row.backlogAtNextBlock!=null&&row.peakRssGiB!=null&&row.rootProofBytes!=null&&row.childProofBytes!=null;}
function networkMetrics(row){const ingressBytes=row.childProofBytes,egressBytes=row.rootProofBytes*state.rootRecipients;return{maximumIngress:ingressBytes*8/1e6/DATA.network.rollingWindowSeconds,maximumEgress:egressBytes*8/1e6/DATA.network.rollingWindowSeconds};}
function checks(row){const network=networkMetrics(row);return[
  {label:"Performance threads",measured:row.workers,limit:state.workers,unit:"threads",digits:0,pass:row.workers<=state.workers},
  {label:"Peak RSS",measured:row.peakRssGiB,limit:state.ramGiB,unit:"GiB",digits:2,pass:row.peakRssGiB<=state.ramGiB},
  {label:"Maximum input-to-root time",measured:row.maxLatency,limit:state.deadline,unit:"s",digits:3,pass:row.maxLatency<=state.deadline},
  {label:"Roots pending at next block arrival",measured:row.backlogAtNextBlock,limit:0,unit:"roots",digits:0,pass:row.backlogAtNextBlock===0},
  {label:"Download required",measured:network.maximumIngress,limit:state.ingressMbps,unit:"Mbit/s",digits:2,pass:network.maximumIngress<=state.ingressMbps},
  {label:"Upload required",measured:network.maximumEgress,limit:state.egressMbps,unit:"Mbit/s",digits:2,pass:network.maximumEgress<=state.egressMbps}
];}
function passes(row){return intrinsicPass(row)&&checks(row).every(check=>check.pass);}
function winnerSort(a,b){return b.proofs-a.proofs||a.peakRssGiB-b.peakRssGiB||a.workers-b.workers||a.maxLatency-b.maxLatency||a.rootProofBytes-b.rootProofBytes;}
function selectedCandidate(){return DATA.candidates.filter(passes).sort(winnerSort)[0]||null;}
function checkValue(check,value){if(check.unit==="threads")return`${fmt(value,0)} ${Number(value)===1?'thread':'threads'}`;if(check.unit==="roots")return`${fmt(value,0)} ${Number(value)===1?'root':'roots'}`;return`${fmt(value,check.digits)} ${check.unit}`;}
function failedChecks(row){if(!intrinsicPass(row))return[row.reason||"Measurement did not complete"];return checks(row).filter(check=>!check.pass).map(check=>`${check.label}: ${checkValue(check,check.measured)} exceeds ${checkValue(check,check.limit)}`);}
function nextLargerCandidate(selected){const sizes=[...new Set(DATA.candidates.filter(row=>intrinsicPass(row)&&row.workers<=state.workers&&row.proofs>selected.proofs).map(row=>row.proofs))].sort((a,b)=>a-b);if(!sizes.length)return null;const rows=DATA.candidates.filter(row=>row.proofs===sizes[0]&&intrinsicPass(row)&&row.workers<=state.workers);return rows.sort((a,b)=>failedChecks(a).length-failedChecks(b).length||a.maxLatency-b.maxLatency||a.peakRssGiB-b.peakRssGiB)[0]||null;}

function setHeader(){
  document.getElementById("context").innerHTML=[`<span><strong>${esc(DATA.hardware.description)}</strong></span>`,`<span><strong>${DATA.blockPeriodSeconds} s</strong> between block arrivals</span>`,`<span><strong>${DATA.hardware.provingProcesses}</strong> proving process</span>`,`<span>up to <strong>${DATA.hardware.performanceWorkers}</strong> performance threads</span>`,`<span><strong>${DATA.hardware.ramLimitGiB} GiB</strong> benchmark RAM cap</span>`,`<span><strong>All child proofs</strong> counted as inbound traffic</span>`,`<span><strong>${DATA.treeDepth}</strong>-level Merkle paths</span>`,`<span><strong>${esc(DATA.hash.replaceAll("_","-"))}</strong></span>`].join("");
}
function setupControls(){
  const controls={workers:document.getElementById("workers"),deadline:document.getElementById("deadline"),ram:document.getElementById("ram"),peers:document.getElementById("peers"),recipients:document.getElementById("recipients"),ingress:document.getElementById("ingress"),egress:document.getElementById("egress")};
  controls.workers.min=measuredWorkers[0];controls.workers.max=measuredWorkers[measuredWorkers.length-1];controls.workers.step=1;controls.workers.value=state.workers;
  controls.deadline.max=Math.max(120,maxLatency);controls.deadline.value=state.deadline;controls.ram.max=DATA.hardware.ramLimitGiB;controls.ram.value=state.ramGiB;controls.peers.value=state.connectedPeers;controls.recipients.max=state.connectedPeers;controls.recipients.value=state.rootRecipients;controls.ingress.value=Math.log10(state.ingressMbps);controls.egress.value=Math.log10(state.egressMbps);
  controls.workers.addEventListener("input",event=>{state.workers=Number(event.target.value);render();});controls.deadline.addEventListener("input",event=>{state.deadline=Number(event.target.value);render();});controls.ram.addEventListener("input",event=>{state.ramGiB=Number(event.target.value);render();});
  controls.peers.addEventListener("input",event=>{state.connectedPeers=Number(event.target.value);state.rootRecipients=Math.min(state.rootRecipients,state.connectedPeers);controls.recipients.max=state.connectedPeers;controls.recipients.value=state.rootRecipients;render();});controls.recipients.addEventListener("input",event=>{state.rootRecipients=Number(event.target.value);render();});controls.ingress.addEventListener("input",event=>{state.ingressMbps=10**Number(event.target.value);render();});controls.egress.addEventListener("input",event=>{state.egressMbps=10**Number(event.target.value);render();});
}
function renderControlValues(){document.getElementById("workers-value").textContent=state.workers;document.getElementById("deadline-value").textContent=`${fmt(state.deadline,0)} s`;document.getElementById("ram-value").textContent=`${fmt(state.ramGiB,0)} GiB`;document.getElementById("peers-value").textContent=state.connectedPeers;document.getElementById("recipients-value").textContent=state.rootRecipients;document.getElementById("ingress-value").textContent=formatRate(state.ingressMbps);document.getElementById("egress-value").textContent=formatRate(state.egressMbps);}
function renderStats(selected){
  const cards=selected?[["Greatest tested batch meeting the selected limits",`${selected.proofs} proofs / root`,"No roots pending at the next block arrival"],["Selected recursion parameters",`${selected.workers} threads · leaf WHIR rate ${rateLabel(selected.leafRate)}`,`Root WHIR rate ${rateLabel(selected.rootRate)}`],["Measured resource use",`${fmt(selected.maxLatency)} s max · ${fmt(selected.peakRssGiB,2)} GiB RSS`,`${formatRate(networkMetrics(selected).maximumIngress)} download required · ${formatRate(networkMetrics(selected).maximumEgress)} upload required`]]:[["Greatest tested batch meeting the selected limits","No measured configuration","Increase one or more selected limits to admit a successful measurement"],["Hardware",`${state.workers} threads · ${fmt(state.ramGiB,0)} GiB`,`${fmt(state.deadline,0)}-second input-to-root limit`],["Network",`${formatRate(state.ingressMbps)} download`,`${formatRate(state.egressMbps)} upload · ${state.rootRecipients} root recipient${state.rootRecipients===1?"":"s"}`]];
  document.getElementById("stats").innerHTML=cards.map(([label,value,detail])=>`<article class="card stat"><div class="label">${esc(label)}</div><div class="value">${esc(value)}</div><div class="detail">${esc(detail)}</div></article>`).join("");
}
function scatterChart(selected){
  const rows=DATA.candidates.filter(intrinsicPass),width=940,height=390,margin={top:24,right:28,bottom:58,left:72},innerW=width-margin.left-margin.right,innerH=height-margin.top-margin.bottom;
  const xs=[...new Set(rows.map(row=>row.proofs))].sort((a,b)=>a-b),ys=rows.map(row=>row.maxLatency).concat([state.deadline]).filter(value=>value>0),minY=Math.max(.1,Math.min(...ys)*.72),maxY=Math.max(...ys)*1.18,logMin=Math.log10(minY),logMax=Math.log10(maxY);
  const x=value=>margin.left+(xs.indexOf(value)/Math.max(1,xs.length-1))*innerW,y=value=>margin.top+(logMax-Math.log10(value))/(logMax-logMin)*innerH,powers=[];
  for(let power=Math.floor(logMin);power<=Math.ceil(logMax);power++)for(const factor of[1,2,5]){const value=factor*10**power;if(value>=minY&&value<=maxY)powers.push(value);}const yTicks=powers.filter((_,index)=>powers.length<=8||index%2===0);
  let svg=`<svg viewBox="0 0 ${width} ${height}" role="img" aria-label="Measured input-to-root time by proofs per root">`;
  for(const tick of yTicks)svg+=`<line class="grid" x1="${margin.left}" x2="${width-margin.right}" y1="${y(tick)}" y2="${y(tick)}"/><text class="axis-text" x="${margin.left-10}" y="${y(tick)+4}" text-anchor="end">${tick<10?fmt(tick,tick<1?1:0):Math.round(tick)}</text>`;
  for(const tick of xs)svg+=`<text class="axis-text" x="${x(tick)}" y="${height-margin.bottom+24}" text-anchor="middle">${tick}</text>`;
  svg+=`<line class="axis" x1="${margin.left}" x2="${width-margin.right}" y1="${height-margin.bottom}" y2="${height-margin.bottom}"/><line class="axis" x1="${margin.left}" x2="${margin.left}" y1="${margin.top}" y2="${height-margin.bottom}"/><line class="deadline" x1="${margin.left}" x2="${width-margin.right}" y1="${y(state.deadline)}" y2="${y(state.deadline)}"/><text x="${width-margin.right-2}" y="${Math.max(margin.top+12,y(state.deadline)-7)}" text-anchor="end" fill="var(--red)" font-size="12">Selected limit ${fmt(state.deadline,0)} s</text>`;
  rows.forEach(row=>{const jitter=(row.leafRate-2.5)*3+(row.rootRate-1)*1.5+(8-row.workers)*.35,cx=x(row.proofs)+jitter,cy=y(row.maxLatency),ok=passes(row),isSelected=selected&&selected.id===row.id;if(isSelected)svg+=`<circle cx="${cx}" cy="${cy}" r="9" fill="none" stroke="var(--blue)" stroke-width="2.5"/>`;svg+=`<circle cx="${cx}" cy="${cy}" r="4.7" fill="${ok?'var(--green)':'var(--red)'}" stroke="var(--surface)" stroke-width="1.2"><title>${row.proofs} proofs/root · ${row.workers} threads · leaf ${rateLabel(row.leafRate)} · root ${rateLabel(row.rootRate)} · ${fmt(row.maxLatency)} s maximum input-to-root · ${fmt(row.backlogAtNextBlock,0)} roots pending at next block arrival · ${fmt(row.peakRssGiB,2)} GiB RSS · ${ok?'meets':'fails'} selected limits</title></circle>`;});
  svg+=`<text class="axis-title" x="${margin.left+innerW/2}" y="${height-10}" text-anchor="middle">Proofs aggregated into one block root</text><text class="axis-title" transform="translate(17 ${margin.top+innerH/2}) rotate(-90)" text-anchor="middle">Maximum input-to-root time (seconds)</text></svg>`;document.getElementById("capacity-chart").innerHTML=svg;
}
function resourceMetrics(){return[
  {key:"threads",title:"Performance threads",unit:"threads",digits:0,value:row=>row.workers,limit:()=>state.workers},
  {key:"memory",title:"Peak RSS",unit:"GiB",digits:2,value:row=>row.peakRssGiB,limit:()=>state.ramGiB},
  {key:"backlog",title:"Roots pending at next block arrival",unit:"roots",digits:0,value:row=>row.backlogAtNextBlock,limit:()=>0},
  {key:"download",title:"Download required",unit:"Mbit/s",digits:2,logarithmic:true,value:row=>row.childProofBytes==null?null:networkMetrics(row).maximumIngress,limit:()=>state.ingressMbps},
  {key:"upload",title:"Upload required",unit:"Mbit/s",digits:2,logarithmic:true,value:row=>row.rootProofBytes==null?null:networkMetrics(row).maximumEgress,limit:()=>state.egressMbps}
];}
function resourceValue(metric,value){return metric.key==="threads"?fmt(value,0):fmt(value,metric.digits);}
function resourceChart(target,metric,selected){
  const rows=DATA.candidates.filter(row=>metric.value(row)!=null),limit=metric.limit(),width=520,height=260,margin={top:22,right:18,bottom:54,left:66},innerW=width-margin.left-margin.right,innerH=height-margin.top-margin.bottom;
  const xs=[...new Set(rows.map(row=>row.proofs))].sort((a,b)=>a-b),values=rows.map(metric.value).concat([limit]).filter(value=>value!=null&&value>=0);
  const x=value=>margin.left+(xs.indexOf(value)/Math.max(1,xs.length-1))*innerW;
  let y,ticks;
  if(metric.logarithmic){const positive=values.filter(value=>value>0),low=positive.length?Math.max(.001,Math.min(...positive)*.7):.001,high=positive.length?Math.max(...positive)*1.2:1,logLow=Math.log10(low),logHigh=Math.log10(high);y=value=>margin.top+(logHigh-Math.log10(Math.max(value,low)))/(logHigh-logLow)*innerH;ticks=[];for(let power=Math.floor(logLow);power<=Math.ceil(logHigh);power++){const value=10**power;if(value>=low&&value<=high)ticks.push(value);}}
  else{const high=Math.max(1,...values)*1.12;y=value=>margin.top+(high-value)/high*innerH;ticks=[0,high/4,high/2,high*3/4,high];if(metric.key==="threads")ticks=[...new Set(measuredWorkers.concat([state.workers]))].sort((a,b)=>a-b).filter(value=>value<=high);}
  let svg=`<svg viewBox="0 0 ${width} ${height}" role="img" aria-label="${esc(metric.title)} by proofs per root">`;
  ticks.forEach(tick=>{svg+=`<line class="grid" x1="${margin.left}" x2="${width-margin.right}" y1="${y(tick)}" y2="${y(tick)}"/><text class="axis-text" x="${margin.left-8}" y="${y(tick)+4}" text-anchor="end">${resourceValue(metric,tick)}</text>`;});
  xs.forEach(tick=>{svg+=`<text class="axis-text" x="${x(tick)}" y="${height-margin.bottom+22}" text-anchor="middle">${tick}</text>`;});
  svg+=`<line class="axis" x1="${margin.left}" x2="${width-margin.right}" y1="${height-margin.bottom}" y2="${height-margin.bottom}"/><line class="axis" x1="${margin.left}" x2="${margin.left}" y1="${margin.top}" y2="${height-margin.bottom}"/><line class="deadline" x1="${margin.left}" x2="${width-margin.right}" y1="${y(limit)}" y2="${y(limit)}"/><text x="${width-margin.right-2}" y="${Math.max(margin.top+12,y(limit)-6)}" text-anchor="end" fill="var(--red)" font-size="12">Limit ${resourceValue(metric,limit)}</text>`;
  rows.forEach(row=>{const value=metric.value(row),jitter=(row.leafRate-2.5)*2+(row.rootRate-1)+(8-row.workers)*.25,cx=x(row.proofs)+jitter,cy=y(value),within=value<=limit,isSelected=selected&&selected.id===row.id;if(isSelected)svg+=`<circle cx="${cx}" cy="${cy}" r="8.5" fill="none" stroke="var(--blue)" stroke-width="2.5"/>`;svg+=`<circle cx="${cx}" cy="${cy}" r="4.5" fill="${within?'var(--green)':'var(--red)'}" stroke="var(--surface)" stroke-width="1"><title>${row.proofs} proofs/root · ${row.workers} threads · ${metric.title}: ${resourceValue(metric,value)} ${metric.unit}</title></circle>`;});
  svg+=`<text class="axis-title" x="${margin.left+innerW/2}" y="${height-9}" text-anchor="middle">Proofs aggregated into one block root</text><text class="axis-title" transform="translate(16 ${margin.top+innerH/2}) rotate(-90)" text-anchor="middle">${esc(metric.unit)}${metric.logarithmic?' (log scale)':''}</text></svg>`;
  document.getElementById(target).innerHTML=svg;
}
function renderResourceCharts(selected){const metrics=resourceMetrics(),target=document.getElementById("resource-charts");target.innerHTML=metrics.map(metric=>`<article class="card resource-chart"><h3>${esc(metric.title)}</h3><div class="chart" id="resource-${metric.key}"></div></article>`).join("");metrics.forEach(metric=>resourceChart(`resource-${metric.key}`,metric,selected));}
function table(headers,rows){return`<thead><tr>${headers.map(header=>`<th class="${header.numeric?"num":""}">${esc(header.label)}</th>`).join("")}</tr></thead><tbody>${rows.map(row=>`<tr>${row.map((cell,index)=>`<td class="${headers[index].numeric?"num":""}">${cell}</td>`).join("")}</tr>`).join("")}</tbody>`;}
function renderLimits(selected){const target=document.getElementById("limits-table");if(!selected){target.innerHTML=table([{label:"Result"}],[[`<span class="na">No configuration meets the selected limits.</span>`]]);return;}target.innerHTML=table([{label:"Quantity"},{label:"Measured",numeric:true},{label:"Selected limit",numeric:true},{label:"Result"}],checks(selected).map(check=>[esc(check.label),esc(checkValue(check,check.measured)),esc(checkValue(check,check.limit)),`<span class="result ${check.pass?'pass':'fail'}">${check.pass?'within limit':'over limit'}</span>`]));}
function renderNextCapacity(selected){const target=document.getElementById("next-capacity-table");if(!selected){target.innerHTML=table([{label:"Result"}],[[`<span class="na">Select limits that admit a configuration.</span>`]]);return;}const next=nextLargerCandidate(selected);if(!next){target.innerHTML=table([{label:"Result"}],[[`<span class="na">No larger successful measurement is available within the selected thread limit.</span>`]]);return;}const failures=failedChecks(next);target.innerHTML=table([{label:"Batch"},{label:"Configuration"},{label:"Measured"},{label:"Limits exceeded"}],[[`${next.proofs} proofs/root`,`${next.workers} threads · leaf WHIR ${rateLabel(next.leafRate)} · root WHIR ${rateLabel(next.rootRate)}`,`${fmt(next.maxLatency)} s maximum input-to-root · ${fmt(next.backlogAtNextBlock,0)} roots pending at next block arrival · ${fmt(next.peakRssGiB,2)} GiB RSS`,failures.length?esc(failures.join("; ")):`<span class="pass">None</span>`]]);}
function populateSelect(id,values,formatter=value=>value){const select=document.getElementById(id);select.innerHTML=`<option value="">All</option>`+values.map(value=>`<option value="${esc(value)}">${esc(formatter(value))}</option>`).join("");select.addEventListener("change",renderCandidates);}
function dynamicStatus(row){if(passes(row))return'<span class="result pass">meets selected limits</span>';if(!intrinsicPass(row))return`<span class="result fail">${esc(row.reason)}</span>`;return`<span class="result fail">${esc(failedChecks(row).join("; "))}</span>`;}
function renderCandidates(){const proofs=document.getElementById("proofs-filter").value,leaf=document.getElementById("leaf-filter").value,workers=document.getElementById("workers-filter").value;const rows=DATA.candidates.filter(row=>(!proofs||row.proofs===Number(proofs))&&(!leaf||row.leafRate===Number(leaf))&&(!workers||row.workers===Number(workers)));document.getElementById("candidate-table").innerHTML=table([{label:"Proofs / root",numeric:true},{label:"Leaf WHIR rate"},{label:"Root WHIR rate"},{label:"Performance threads",numeric:true},{label:"Maximum input-to-root",numeric:true},{label:"Mean input-to-root",numeric:true},{label:"Roots pending at next block",numeric:true},{label:"Peak RSS",numeric:true},{label:"Root proof",numeric:true},{label:"Selected limits"}],rows.map(row=>[row.proofs,rateLabel(row.leafRate),rateLabel(row.rootRate),row.workers,row.maxLatency==null?"—":`${fmt(row.maxLatency)} s`,row.meanLatency==null?"—":`${fmt(row.meanLatency)} s`,row.backlogAtNextBlock==null?"—":fmt(row.backlogAtNextBlock,0),row.peakRssGiB==null?"—":`${fmt(row.peakRssGiB,2)} GiB`,row.rootProofBytes==null?"—":`${fmt(row.rootProofBytes/1024,1)} KiB`,dynamicStatus(row)]));}
function renderTree(selected){const note=document.getElementById("tree-note"),target=document.getElementById("tree-table");if(!selected||!selected.tree||!selected.tree.levels.length){note.textContent="";target.innerHTML=table([{label:"Result"}],[[`<span class="na">No selected tree.</span>`]]);return;}const levels=selected.tree.levels,single=levels.length===1,hasLevelEstimates=selected.tree.levelTimesEstimated!==false,chain=[`${selected.proofs} leaf proofs`,...levels.map(level=>level.isRoot?"1 root":`${level.outputCount} parent proofs`)].join(" → ");note.textContent=single?`${chain}. The root time is the measured mean for the complete tree.`:hasLevelEstimates?`${chain}. The complete tree took ${fmt(selected.meanProvingSeconds)} s on average. Per-level timestamps were not recorded, so the level times are planner estimates.`:`${chain}. The complete tree took ${fmt(selected.meanProvingSeconds)} s on average. The grouping matches artifacts with the recorded plan digest; per-level times are unavailable.`;target.innerHTML=table([{label:"Level"},{label:"Input proofs",numeric:true},{label:"Nodes produced",numeric:true},{label:"Children per node"},{label:"WHIR rate"},{label:"Level time",numeric:true}],levels.map(level=>[level.isRoot?"Root":level.level,level.inputCount,level.outputCount,level.childCounts.join(" + "),`${rateLabel(level.childRate)} → ${rateLabel(level.parentRate)}`,single?`${fmt(selected.meanProvingSeconds)} s measured`:hasLevelEstimates?`${fmt(level.estimatedSeconds)} s estimated`:`—`]));}
function lineChart(target,series,options){const width=940,height=360,margin={top:22,right:28,bottom:54,left:72},innerW=width-margin.left-margin.right,innerH=height-margin.top-margin.bottom,xs=[...new Set(series.flatMap(item=>item.values.map(point=>point.x)))].sort((a,b)=>a-b),ys=series.flatMap(item=>item.values.map(point=>point.y)).filter(value=>value>0);if(options.reference>0)ys.push(options.reference);const minY=Math.max(.1,Math.min(...ys)*.72),maxY=Math.max(...ys)*1.18,logMin=Math.log10(minY),logMax=Math.log10(maxY),x=value=>margin.left+(xs.indexOf(value)/Math.max(1,xs.length-1))*innerW,y=value=>margin.top+(logMax-Math.log10(value))/(logMax-logMin)*innerH,powers=[];for(let power=Math.floor(logMin);power<=Math.ceil(logMax);power++)for(const factor of[1,2,5]){const value=factor*10**power;if(value>=minY&&value<=maxY)powers.push(value);}const yTicks=powers.filter((_,index)=>powers.length<=7||index%2===0);let svg=`<svg viewBox="0 0 ${width} ${height}" role="img" aria-label="${esc(options.aria)}">`;for(const tick of yTicks)svg+=`<line class="grid" x1="${margin.left}" x2="${width-margin.right}" y1="${y(tick)}" y2="${y(tick)}"/><text class="axis-text" x="${margin.left-10}" y="${y(tick)+4}" text-anchor="end">${tick<10?fmt(tick,tick<1?1:0):Math.round(tick)}</text>`;for(const tick of xs)svg+=`<text class="axis-text" x="${x(tick)}" y="${height-margin.bottom+23}" text-anchor="middle">${tick}</text>`;svg+=`<line class="axis" x1="${margin.left}" x2="${width-margin.right}" y1="${height-margin.bottom}" y2="${height-margin.bottom}"/><line class="axis" x1="${margin.left}" x2="${margin.left}" y1="${margin.top}" y2="${height-margin.bottom}"/>`;if(options.reference>0)svg+=`<line class="deadline" x1="${margin.left}" x2="${width-margin.right}" y1="${y(options.reference)}" y2="${y(options.reference)}"/><text x="${width-margin.right-2}" y="${Math.max(margin.top+12,y(options.reference)-7)}" text-anchor="end" fill="var(--red)" font-size="12">Whole-root input-to-root limit ${fmt(options.reference,0)} s</text>`;series.forEach(item=>{const values=[...item.values].sort((a,b)=>xs.indexOf(a.x)-xs.indexOf(b.x));svg+=`<polyline points="${values.map(point=>`${x(point.x)},${y(point.y)}`).join(" ")}" fill="none" stroke="${item.color}" stroke-width="2.4" stroke-linejoin="round" stroke-linecap="round"/>`;values.forEach(point=>{svg+=`<circle cx="${x(point.x)}" cy="${y(point.y)}" r="5" fill="var(--surface)" stroke="${item.color}" stroke-width="2"><title>${esc(item.label)} · ${point.x} child proofs · ${fmt(point.y)} s</title></circle>`;});});svg+=`<text class="axis-title" x="${margin.left+innerW/2}" y="${height-9}" text-anchor="middle">${esc(options.xTitle)}</text><text class="axis-title" transform="translate(17 ${margin.top+innerH/2}) rotate(-90)" text-anchor="middle">${esc(options.yTitle)}</text></svg>`;document.getElementById(target).innerHTML=svg;}
function renderGeometry(){const rows=DATA.geometry.filter(row=>row.parentRate===1),rates=[...new Set(rows.map(row=>row.childRate))].sort((a,b)=>a-b),series=rates.map((rate,index)=>({label:`Child WHIR rate ${rateLabel(rate)}`,color:RATE_COLORS[index],values:rows.filter(row=>row.childRate===rate).map(row=>({x:row.arity,y:row.serviceSeconds}))}));document.getElementById("geometry-legend").innerHTML=series.map(item=>`<span><i class="swatch" style="background:${item.color}"></i>${item.label}</span>`).join("");lineChart("geometry-chart",series,{reference:state.deadline,xTitle:"Child proofs per parent",yTitle:"Mean proving time (seconds)",aria:"Representative parent proving time by arity and child WHIR rate"});}
function setupTabs(){document.querySelectorAll('[role="tab"]').forEach(tab=>tab.addEventListener("click",()=>{document.querySelectorAll('[role="tab"]').forEach(other=>other.setAttribute("aria-selected",String(other===tab)));document.querySelectorAll('.tab-panel').forEach(panel=>panel.hidden=panel.id!==tab.getAttribute("aria-controls"));}));}
function render(){renderControlValues();const selected=selectedCandidate();renderStats(selected);scatterChart(selected);renderResourceCharts(selected);renderLimits(selected);renderNextCapacity(selected);renderTree(selected);renderCandidates();renderGeometry();}

setHeader();setupControls();populateSelect("proofs-filter",[...new Set(DATA.candidates.map(row=>row.proofs))].sort((a,b)=>a-b));populateSelect("leaf-filter",[...new Set(DATA.candidates.map(row=>row.leafRate))].sort((a,b)=>a-b),rateLabel);populateSelect("workers-filter",measuredWorkers.slice().sort((a,b)=>b-a));setupTabs();render();
</script>
</body>
</html>
'''


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--input",
        required=True,
        action="append",
        type=Path,
        help="schema-2 benchmark directory; repeat to merge compatible measurements",
    )
    parser.add_argument("--output", required=True, type=Path, help="standalone HTML report path")
    parser.add_argument("--hardware-description", required=True, help="machine used for the benchmark")
    args = parser.parse_args()
    input_dirs = [path.resolve() for path in args.input]
    payload = build_payload(input_dirs, args.hardware_description)
    encoded = json.dumps(payload, separators=(",", ":"), ensure_ascii=True).replace("</", "<\\/")
    document = REPORT_HTML.replace("__REPORT_DATA__", encoded)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(document, encoding="utf-8")
    print(args.output)


if __name__ == "__main__":
    main()
