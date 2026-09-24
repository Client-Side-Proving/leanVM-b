"""Focused tests for Privacy Pool report data and admission rules."""

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import generate_privacy_pool_report as report


class PrivacyPoolReportTests(unittest.TestCase):
    def test_tree_plan_digest_mismatch_uses_matching_manifests(self):
        expected_digest = "a" * 64
        candidate = {
            "inputs_per_root": 8,
            "plan_path": "/discarded/path/scaling-8-4-1.json",
            "executed_plan_digest": expected_digest,
        }
        with tempfile.TemporaryDirectory() as directory:
            input_dir = Path(directory)
            plan_dir = input_dir / "plans"
            plan_dir.mkdir()
            (plan_dir / "scaling-8-4-1.json").write_text(
                json.dumps({"levels": []}), encoding="utf-8"
            )

            def write_manifest(level, job, arity, child_rate, parent_rate):
                path = (
                    input_dir
                    / "parent-cases"
                    / "plan"
                    / expected_digest
                    / "level"
                    / str(level)
                    / "job"
                    / f"{job}.json"
                )
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(
                    json.dumps({
                        "executed_plan_digest": expected_digest,
                        "children": [{} for _ in range(arity)],
                        "configuration": {
                            "arity": arity,
                            "child_log_inv_rate": child_rate,
                            "parent_log_inv_rate": parent_rate,
                        },
                    }),
                    encoding="utf-8",
                )

            write_manifest(0, 2, 6, 4, 1)
            write_manifest(1, 0, 3, 1, 1)
            tree = report.load_tree_plan(input_dir, candidate)

        self.assertIsNotNone(tree)
        self.assertFalse(tree["levelTimesEstimated"])
        self.assertEqual(
            [level["childCounts"] for level in tree["levels"]],
            [[1, 1, 6], [3]],
        )
        self.assertTrue(all(level["estimatedSeconds"] is None for level in tree["levels"]))

    def test_compact_candidate_records_no_backlog_despite_endpoint_interval_bias(self):
        latencies = [5.278500541, 6.027498416, 5.121252708, 3.900777791, 5.403532125, 5.549510125]
        completions = [index * 12.0 + latency for index, latency in enumerate(latencies)]
        roots = []
        for index, (latency, completion) in enumerate(zip(latencies, completions)):
            roots.append(
                {
                    "candidate_id": "candidate",
                    "executed_plan_digest": "plan",
                    "root_index": index,
                    "status": "success",
                    "burst_arrival_seconds": index * 12.0,
                    "campaign_elapsed_at_serialization_seconds": completion,
                    "serialized_input_to_root_seconds": latency,
                    "root_interval_seconds": None if index == 0 else completion - completions[index - 1],
                    "proving_and_verification_seconds": latency - 0.001,
                    "serialization_seconds": 0.001,
                }
            )
        candidate = {
            "candidate_attempt_id": "candidate",
            "executed_plan_digest": "plan",
            "inputs_per_root": 16,
            "leaf_log_inv_rate": 4,
            "required_root_log_inv_rate": 1,
            "performance_workers": 8,
            "terminal_status": "success",
            "all_roots_verified_against_expected": True,
            "max_serialized_input_to_root_seconds": max(latencies),
            "peak_rss_bytes": 16 * (1 << 30),
            "max_serialized_root_proof_bytes": 400_000,
        }
        leaf_sizes = {(4, index): 100_000 for index in range(16)}

        with tempfile.TemporaryDirectory() as directory:
            compact = report.compact_candidate(
                candidate,
                leaf_sizes,
                roots,
                Path(directory),
                source_index=0,
                block_period_seconds=12.0,
            )

        intervals = [root["root_interval_seconds"] for root in roots[1:]]
        self.assertGreater(sum(intervals) / len(intervals), 12.0)
        self.assertLessEqual(compact["maxLatency"], 12.0)
        self.assertEqual(compact["backlogAtNextBlock"], 0)

    def test_backlog_counts_roots_pending_at_the_next_block_arrival(self):
        roots = [
            {
                "burst_arrival_seconds": index * 12.0,
                "campaign_elapsed_at_serialization_seconds": completion,
            }
            for index, completion in enumerate([20.0, 40.0, 60.0, 80.0, 100.0, 120.0])
        ]
        self.assertEqual(report.backlog_at_next_block(roots, 12.0), 3)

    def test_dashboard_admission_uses_deadline_and_backlog(self):
        self.assertIn("row.maxLatency<=state.deadline", report.REPORT_HTML)
        self.assertIn("row.backlogAtNextBlock===0", report.REPORT_HTML)
        self.assertNotIn(
            "row.meanRootInterval<=DATA.blockPeriodSeconds",
            report.REPORT_HTML,
        )
        self.assertNotIn("Average interval between roots", report.REPORT_HTML)


if __name__ == "__main__":
    unittest.main()
