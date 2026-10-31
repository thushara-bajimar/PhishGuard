from __future__ import annotations

import csv
import tempfile
import unittest
from pathlib import Path

from app.ml.message_predict import MessagePredictionService, extract_message_indicators
from app.ml.message_train import train_model


class MessageHeuristicTests(unittest.TestCase):
    def test_warning_indicators_are_labeled_as_heuristics(self) -> None:
        text = "URGENT: verify your password now or your account will be suspended. Pay the processing fee at https://example.test/claim"
        indicators = extract_message_indicators(text)
        names = {item["name"] for item in indicators}

        self.assertIn("Urgent request", names)
        self.assertIn("Credential or account request", names)
        self.assertIn("Threatening language", names)
        self.assertIn("Unusual payment request", names)
        self.assertIn("Link present", names)
        self.assertTrue(all(item["source"] == "heuristic" for item in indicators))

    def test_harmless_message_does_not_get_keyword_alerts(self) -> None:
        self.assertEqual(extract_message_indicators("Meeting moved to 3pm, see you in the office."), [])


class MessageTrainingTests(unittest.TestCase):
    def test_training_saves_a_real_pipeline_and_metrics_then_predicts(self) -> None:
        # These small rows exist only as isolated test fixtures; they are not the product dataset.
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            dataset_path = root / "messages.csv"
            model_path = root / "model.joblib"
            with dataset_path.open("w", encoding="utf-8", newline="") as handle:
                writer = csv.DictWriter(handle, fieldnames=["Email Text", "Email Type"])
                writer.writeheader()
                for index in range(25):
                    writer.writerow({"Email Text": f"urgent verify password account secure login notice sample {index}", "Email Type": "Phishing Email"})
                    writer.writerow({"Email Text": f"team lunch meeting schedule project discussion sample {index}", "Email Type": "Safe Email"})

            metrics = train_model(dataset_path, model_path, "Email Text", "Email Type", "Phishing Email", random_state=11)
            self.assertTrue(model_path.is_file())
            self.assertTrue(model_path.with_suffix(".metrics.json").is_file())
            self.assertEqual(metrics["group_overlap"], 0)
            self.assertIn("precision_phishing", metrics)
            self.assertIn("recall_phishing", metrics)
            self.assertIn("f1_phishing", metrics)
            self.assertIn("confusion_matrix", metrics)

            result = MessagePredictionService(model_path).analyze("URGENT verify your account password now")
            self.assertIn(result["prediction"], {"potential_phishing", "no_phishing_detected"})
            self.assertGreaterEqual(result["risk_score"], 0)
            self.assertLessEqual(result["risk_score"], 100)
            self.assertTrue(all(item["source"] == "heuristic" for item in result["indicators"]))
            self.assertIn("uncalibrated", result["model_info"]["risk_score_note"])


if __name__ == "__main__":
    unittest.main()
