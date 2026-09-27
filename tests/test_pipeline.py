import unittest

from src.pipeline import stage_outputs


class StageOutputsTest(unittest.TestCase):
    def test_stage_outputs_cover_all_enabled_algorithms(self):
        config = {
            "analysis_results_dir": "results/development/analysis",
            "signature_results_dir": "results/development/signatures",
            "authentication_intervals": [1, 5],
            "algorithms_config": "config/algorithms.json",
        }

        outputs = stage_outputs("signatures", config)
        names = {p.name for p in outputs}

        self.assertIn("signature_experiment_summary.json", names)
        self.assertIn("signatures_ECDSA-P256_k1.jsonl", names)
        self.assertIn("signatures_ML-DSA-44_k1.jsonl", names)
        self.assertIn("signatures_FN-DSA-512_k1.jsonl", names)
        self.assertIn("signatures_SLH-DSA-SHA2-128s_k1.jsonl", names)


if __name__ == "__main__":
    unittest.main()
