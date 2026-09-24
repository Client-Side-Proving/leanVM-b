"""Fast tests for query validation and schema-2 campaign bookkeeping."""

import json
import csv
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import run_recursion_benchmark as runner


ROOT = Path(__file__).parent


class BenchmarkRunnerTests(unittest.TestCase):
    def test_schema2_query_has_fixed_burst_definition(self):
        query = json.loads((ROOT / "privacy-pool-withdrawal-screening.json").read_text())
        runner.validate_query_shape(query)
        self.assertEqual(query["arrivals"]["burst_count"], 6)
        self.assertEqual(query["workload"]["adapter"], "privacy_pool_withdrawal")

    def test_schema2_geometry_surface_is_exact(self):
        query = json.loads((ROOT / "privacy-pool-withdrawal-screening.json").read_text())
        self.assertEqual(len(runner.schema2_geometry_tuples(query)), 60)
        self.assertEqual(len(runner.schema2_diagnostic_tuples(query)), 16)
        self.assertEqual(len(runner.schema2_unique_geometry_tuples(query)), 72)

    def test_schema2_geometry_preflight_runs_arities_two_four_and_sixteen_first(self):
        query = json.loads((ROOT / "privacy-pool-withdrawal-screening.json").read_text())
        ordered = runner.schema2_geometry_execution_order(query)
        self.assertEqual(len(ordered), 72)
        preflight_length = sum(arity in {2, 4, 16} for arity, _, _ in ordered)
        self.assertTrue(all(arity in {2, 4, 16} for arity, _, _ in ordered[:preflight_length]))
        self.assertEqual(set(ordered), set(runner.schema2_unique_geometry_tuples(query)))

    def test_smoke_uses_only_the_single_explicit_case(self):
        query = json.loads((ROOT / "privacy-pool-withdrawal-screening.json").read_text())
        self.assertEqual(query["search"]["inputs_per_root"][0], 2)
        self.assertEqual(query["search"]["primary_root_log_inv_rates"], [1])
        self.assertEqual(runner.schema2_root_target(True), 1)
        self.assertEqual(runner.schema2_root_target(False), 6)

    def test_native_root_validation_timings_are_reported_separately(self):
        roots = [
            {
                "native_in_memory_verification_seconds": 1.0,
                "native_deserialization_seconds": 2.0,
                "native_roundtrip_verification_seconds": 3.0,
                "native_validation_seconds": 6.0,
            },
            {
                "native_in_memory_verification_seconds": 3.0,
                "native_deserialization_seconds": 4.0,
                "native_roundtrip_verification_seconds": 5.0,
                "native_validation_seconds": 12.0,
            },
        ]
        self.assertEqual(
            runner.summarize_native_root_timings(roots),
            {
                "median_native_root_in_memory_verification_seconds": 2.0,
                "max_native_root_in_memory_verification_seconds": 3.0,
                "median_native_root_deserialization_seconds": 3.0,
                "max_native_root_deserialization_seconds": 4.0,
                "median_native_root_roundtrip_verification_seconds": 4.0,
                "max_native_root_roundtrip_verification_seconds": 5.0,
                "median_native_root_validation_seconds": 9.0,
                "max_native_root_validation_seconds": 12.0,
            },
        )
        self.assertEqual(
            runner.native_root_timing_fields(roots[0]),
            {
                "native_root_in_memory_verification_seconds": 1.0,
                "native_root_deserialization_seconds": 2.0,
                "native_root_roundtrip_verification_seconds": 3.0,
                "native_root_validation_seconds": 6.0,
            },
        )
        self.assertNotIn("native_root_verify_seconds", runner.SCHEMA2_ROOT_FIELDS)
        self.assertNotIn("median_native_root_verify_seconds", runner.SCHEMA2_CANDIDATE_FIELDS)

    def test_schema2_campaign_has_the_required_47_configurations(self):
        query = json.loads((ROOT / "privacy-pool-withdrawal-screening.json").read_text())
        configurations = runner.schema2_campaign_configurations(query, [8, 4, 2, 1])
        self.assertEqual(len(configurations), 47)
        self.assertEqual(sum(item[4] == "primary" for item in configurations), 32)
        self.assertEqual(sum(item[4] == "scaling" for item in configurations), 9)
        self.assertEqual(sum(item[4] == "compression" for item in configurations), 6)
        self.assertEqual([item[0] for item in configurations[:8]], [45] * 4 + [91] * 4)
        self.assertEqual([item[2] for item in configurations[32:41]], [4, 2, 1] * 3)

    def test_leaf_rate_selection_prefers_count_then_latency_rss_proof_and_rate(self):
        rows = [
            {"leaf_log_inv_rate": 1, "inputs_per_root": 45, "pass": True,
             "max_serialized_input_to_root_seconds": 8, "peak_rss_bytes": 20, "proof_bytes": 200},
            {"leaf_log_inv_rate": 2, "inputs_per_root": 45, "pass": True,
             "max_serialized_input_to_root_seconds": 7, "peak_rss_bytes": 30, "proof_bytes": 300},
            {"leaf_log_inv_rate": 2, "inputs_per_root": 32, "pass": True,
             "max_serialized_input_to_root_seconds": 1, "peak_rss_bytes": 1, "proof_bytes": 1},
        ]
        self.assertEqual(runner.select_schema2_leaf_rate(rows), 2)

    def test_leaf_rate_selection_requires_a_passing_candidate(self):
        with self.assertRaisesRegex(ValueError, "no completed primary candidates"):
            runner.select_schema2_leaf_rate([
                {"leaf_log_inv_rate": 1, "inputs_per_root": 91, "pass": False,
                 "max_serialized_input_to_root_seconds": 13, "peak_rss_bytes": 1, "proof_bytes": 1}
            ])

    def test_leaf_rate_selection_ignores_scaling_and_compression_rows(self):
        rows = [
            {"phase": "primary", "leaf_log_inv_rate": 1, "inputs_per_root": 91, "pass": True,
             "max_serialized_input_to_root_seconds": 4, "peak_rss_bytes": 20,
             "max_serialized_root_proof_bytes": 200},
            {"phase": "primary", "leaf_log_inv_rate": 2, "inputs_per_root": 91, "pass": True,
             "max_serialized_input_to_root_seconds": 5, "peak_rss_bytes": 20,
             "max_serialized_root_proof_bytes": 200},
            {"phase": "scaling", "leaf_log_inv_rate": 1, "inputs_per_root": 91, "pass": True,
             "max_serialized_input_to_root_seconds": 11, "peak_rss_bytes": 20,
             "max_serialized_root_proof_bytes": 200},
        ]
        self.assertEqual(runner.select_schema2_leaf_rate(rows), 1)

    def test_worker_order_is_preserved_by_deduplication(self):
        values = list(dict.fromkeys(int(value) for value in "8,4,8,2,1".split(",")))
        self.assertEqual(values, [8, 4, 2, 1])

    def test_schema2_plan_filenames_include_the_worker_count(self):
        four_workers = runner.schema2_plan_filename("scaling", 16, 4, 1, 4)
        two_workers = runner.schema2_plan_filename("scaling", 16, 4, 1, 2)
        self.assertEqual(four_workers, "scaling-16-4-1-w4.json")
        self.assertEqual(two_workers, "scaling-16-4-1-w2.json")
        self.assertNotEqual(four_workers, two_workers)

        query = json.loads((ROOT / "privacy-pool-withdrawal-screening.json").read_text())
        configurations = runner.schema2_campaign_configurations(query, [8, 4, 2, 1], selected_rate=4)
        filenames = [
            runner.schema2_plan_filename(phase, inputs, leaf_rate, root_rate, workers)
            for inputs, leaf_rate, workers, root_rate, phase in configurations
        ]
        self.assertEqual(len(filenames), 47)
        self.assertEqual(len(set(filenames)), len(filenames))

    def test_schema2_plan_loader_checks_the_recorded_digest(self):
        plan = {
            "leaf_count": 16,
            "leaf_log_inv_rate": 4,
            "root_log_inv_rate": 1,
            "levels": [],
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "scaling-16-4-1-w4.json"
            path.write_text(json.dumps(plan), encoding="utf-8")
            expected_digest = runner.schema2_plan_digest(plan)
            loaded, actual_digest = runner.load_schema2_plan(path, expected_digest)
            self.assertEqual(loaded, plan)
            self.assertEqual(actual_digest, expected_digest)

            plan["leaf_count"] = 32
            path.write_text(json.dumps(plan), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "plan digest mismatch"):
                runner.load_schema2_plan(path, expected_digest)

    def test_schema1_shape_remains_supported(self):
        query = json.loads((ROOT / "recursion-benchmark-example.json").read_text())
        runner.validate_query_shape(query)

    def test_percentile_and_topology_helpers(self):
        self.assertEqual(runner.percentile_nearest_rank([3, 1, 2], 0.99), 3)
        topology = runner.make_topology(8, 0, 2)
        self.assertEqual([item["performance_workers"] for item in topology["worker_allocations"]], [4, 4])

    def test_boundary_detection_uses_shape_changes(self):
        records = [
            {"configuration": {"arity": 2, "child_log_inv_rate": 1, "parent_log_inv_rate": 1},
             "child_shape": {"m": 10}, "parent_shape": {"m": 12}},
            {"configuration": {"arity": 3, "child_log_inv_rate": 1, "parent_log_inv_rate": 1},
             "child_shape": {"m": 11}, "parent_shape": {"m": 12}},
            {"configuration": {"arity": 4, "child_log_inv_rate": 1, "parent_log_inv_rate": 1},
             "child_shape": {"m": 11}, "parent_shape": {"m": 12}},
        ]
        self.assertEqual(runner.schema2_boundary_tuples(records), [(2, 1, 1), (3, 1, 1)])

    def test_boundary_repeats_ignore_compression_and_plan_shape_records(self):
        records = [
            {
                "measurement_phase": "geometry",
                "performance_workers": 1,
                "configuration": {"arity": 2, "child_log_inv_rate": 1, "parent_log_inv_rate": 1},
                "child_shape": {"m": 10},
                "parent_shape": {"m": 12},
            },
            {
                "measurement_phase": "geometry",
                "performance_workers": 1,
                "configuration": {"arity": 3, "child_log_inv_rate": 1, "parent_log_inv_rate": 1},
                "child_shape": {"m": 11},
                "parent_shape": {"m": 12},
            },
            {
                "measurement_phase": "compressed_final_capacity",
                "performance_workers": 1,
                "configuration": {"arity": 3, "child_log_inv_rate": 1, "parent_log_inv_rate": 2},
                "child_shape": {"m": 20},
                "parent_shape": {"m": 21},
            },
        ]
        self.assertEqual(runner.schema2_repeat_boundary_tuples(records), [(2, 1, 1), (3, 1, 1)])

    def test_candidate_resume_requires_every_verified_root_artifact(self):
        candidate = {
            "candidate_attempt_id": "primary-2-1-8-1",
            "terminal_status": "success",
            "completed_roots": 2,
            "inputs_per_root": 2,
            "executed_plan_digest": "plan",
        }
        roots = [
            {
                "candidate_id": candidate["candidate_attempt_id"],
                "root_index": index,
                "status": "success",
                "parse_ok": True,
                "in_memory_verify_ok": True,
                "roundtrip_verify_ok": True,
                "expected_withdrawal_count": 2,
                "expected_withdrawal_list_digest": "list",
                "executed_plan_digest": "plan",
            }
            for index in range(2)
        ]
        self.assertTrue(runner.schema2_candidate_artifacts_complete(candidate, roots, 2))
        roots[1]["roundtrip_verify_ok"] = False
        self.assertFalse(runner.schema2_candidate_artifacts_complete(candidate, roots, 2))

    def test_plan_manifests_preserve_recursive_shapes_and_skip_unary_carries(self):
        query = json.loads((ROOT / "privacy-pool-withdrawal-screening.json").read_text())
        plan = {
            "leaf_count": 5,
            "leaf_log_inv_rate": 1,
            "root_log_inv_rate": 1,
            "levels": [
                {"input_count": 5, "output_count": 2, "child_log_inv_rate": 1,
                 "parent_log_inv_rate": 1, "child_counts": [4, 1]},
                {"input_count": 2, "output_count": 1, "child_log_inv_rate": 1,
                 "parent_log_inv_rate": 1, "child_counts": [2]},
            ],
        }
        with tempfile.TemporaryDirectory() as directory:
            paths = runner.schema2_plan_manifests(
                Path(directory), query, "sha", "blake", plan, "plan", "case", "program"
            )
            self.assertEqual(len(paths), 2)
            first = json.loads(paths[0].read_text())
            root = json.loads(paths[1].read_text())
            self.assertEqual(first["expected_fixture_indices"], [0, 1, 2, 3])
            self.assertEqual(root["expected_fixture_indices"], [0, 1, 2, 3, 4])
            self.assertEqual(root["children"][0]["kind"], "parent")
            self.assertEqual(root["children"][1]["kind"], "leaf")

    def test_capacity_csv_aggregates_samples_by_exact_shape(self):
        base = {
            "workload_adapter": "privacy_pool_withdrawal",
            "workload_adapter_schema_version": 1,
            "adapter_config_digest": "adapter",
            "program_identity": "program",
            "role": "nonfinal",
            "measurement_phase": "geometry",
            "workload_shape_fingerprint": "shape",
            "ordered_child_claim_counts": [1, 1],
            "child_shapes": [{"m": 10}, {"m": 10}],
            "parent_shape": {"m": 12},
            "configuration": {"arity": 2, "child_log_inv_rate": 1,
                              "parent_log_inv_rate": 1, "performance_workers": 1},
            "performance_workers": 1,
            "proof_bytes": 100,
            "verified": True,
        }
        rows = runner.aggregate_schema2_capacity_records([
            {**base, "aggregation_seconds": [2.0], "observed_peak_rss_bytes": 10},
            {**base, "aggregation_seconds": [4.0, 6.0], "observed_peak_rss_bytes": 20},
        ])
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["sample_count"], 3)
        self.assertEqual(rows[0]["median_service_seconds"], 4.0)
        self.assertEqual(rows[0]["maximum_rss_bytes"], 20)

    def test_interrupted_campaign_writes_every_normalized_artifact(self):
        query = json.loads((ROOT / "privacy-pool-withdrawal-screening.json").read_text())
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            runner.write_interrupted_schema2_artifacts(
                output,
                query,
                False,
                "KeyboardInterrupt",
                43_200.0,
                1_800.0,
                12.5,
            )
            for name in (
                "capacity.csv", "capacity.json", "candidates.csv", "candidates.json",
                "roots.csv", "coverage.json", "summary.json", "summary.md", "raw.jsonl",
                "parent-jobs.jsonl", "parent-checkpoint.jsonl", "candidate-checkpoint.jsonl",
            ):
                self.assertTrue((output / name).exists(), name)
            coverage = json.loads((output / "coverage.json").read_text())
            self.assertEqual(coverage["run_status"], "partial screening coverage")
            self.assertEqual(len(coverage["geometry_points"]), 72)
            self.assertEqual(len(coverage["candidate_points"]), 32)
            self.assertEqual(coverage["required_candidates"], 47)
            self.assertEqual(coverage["time_budget_seconds"], 43_200.0)
            self.assertEqual(coverage["finish_reserve_seconds"], 1_800.0)
            self.assertEqual(coverage["elapsed_seconds"], 12.5)
            with (output / "candidates.csv").open(newline="") as source:
                self.assertEqual(next(csv.reader(source)), runner.SCHEMA2_CANDIDATE_FIELDS)

    def test_subprocess_failure_receipt_retains_stderr(self):
        error = runner.subprocess.CalledProcessError(
            2,
            ["benchmark"],
            output="",
            stderr="precise verifier failure",
        )
        text = runner.exception_text(error)
        self.assertIn("exit status 2", text)
        self.assertIn("precise verifier failure", text)

    def test_monitored_subprocess_captures_stderr(self):
        command = [
            sys.executable,
            "-c",
            "import sys; print('live verifier failure', file=sys.stderr); raise SystemExit(3)",
        ]
        with self.assertRaises(runner.subprocess.CalledProcessError) as caught:
            runner.run_json_command_monitored(command, runner.os.environ.copy(), 5.0)
        self.assertIn("live verifier failure", caught.exception.stderr)

    def test_schema2_validation_rejects_duplicate_or_overlapping_counts(self):
        query = json.loads((ROOT / "privacy-pool-withdrawal-screening.json").read_text())
        query["search"]["optional_inputs_per_root"] = [91]
        with self.assertRaisesRegex(ValueError, "optional input counts"):
            runner.validate_query_shape(query)


if __name__ == "__main__":
    unittest.main()
