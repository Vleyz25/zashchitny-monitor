import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import main


class ProcessMonitorTests(unittest.TestCase):
    def test_cpu_is_normalized_to_total_system_capacity(self):
        self.assertEqual(main.normalize_process_cpu(400.0, logical_cpu_count=8), 50.0)
        self.assertEqual(main.normalize_process_cpu(800.0, logical_cpu_count=8), 100.0)
        self.assertEqual(main.normalize_process_cpu(-3.0, logical_cpu_count=8), 0.0)

    def test_live_processes_are_sorted_by_cpu_descending(self):
        observed = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
        samples = [
            main.ProcessSample(1, "quiet.exe", "C:/quiet.exe", 2.0, observed),
            main.ProcessSample(2, "busy.exe", "C:/busy.exe", 73.0, observed),
        ]
        self.assertEqual([sample.name for sample in main.rank_process_samples(samples)], ["busy.exe", "quiet.exe"])

    def test_report_keeps_target_process_path_and_peak_cpu(self):
        session = main.ProcessMonitorSession()
        first = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
        session.record([main.ProcessSample(42, "Системные прерывания", "", 15.0, first)])
        session.record([main.ProcessSample(42, "Системные прерывания", "", 87.5, first + timedelta(seconds=2))])

        report, history = session.report()

        self.assertIn("Системные прерывания", report)
        self.assertIn("пик CPU 87.5%", report)
        self.assertIn("Windows не предоставила путь", report)
        self.assertEqual(history[0].samples, 2)
        self.assertEqual(history[0].peak_cpu_percent, 87.5)

    def test_report_explains_target_was_not_observed(self):
        session = main.ProcessMonitorSession()
        report, history = session.report()
        self.assertIn("не обнаружен", report)
        self.assertEqual(history, [])


class InspectFileTests(unittest.TestCase):
    def test_inspects_file_and_reports_hash(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sample.txt"
            path.write_bytes(b"safe test fixture")
            with patch("main.get_signature", return_value=("Valid", "Test Publisher")):
                report = main.inspect_file(path)
            self.assertEqual(report.sha256, "d50eb9c9ba2d077238b944498ba49c2b9d3735b9f2f16b9304b3b8d81801d241")
            self.assertEqual(report.path, str(path.resolve()))
            self.assertEqual(report.signature, "Valid")
            self.assertEqual(report.signer, "Test Publisher")

    def test_rejects_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, "обычным файлом"):
                main.inspect_file(directory)

    def test_missing_path_fails(self):
        with self.assertRaises(FileNotFoundError):
            main.inspect_file("this-file-should-not-exist-2026-11-18.tmp")


if __name__ == "__main__":
    unittest.main()
