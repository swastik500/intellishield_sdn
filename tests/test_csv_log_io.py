"""Tests for CSV log header repair and resilient loading."""

import csv
import os
import tempfile
import unittest

from evaluation.csv_log_io import (
    KNOWN_CSV_HEADERS,
    csv_has_valid_header,
    ensure_csv_header,
    load_csv_rows,
)


class TestCsvLogIo(unittest.TestCase):
    def test_ensure_csv_header_creates_new_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "entropy_logs.csv")
            headers = KNOWN_CSV_HEADERS["entropy_logs.csv"]
            ensure_csv_header(path, headers)
            self.assertTrue(csv_has_valid_header(path))
            with open(path, newline="") as f:
                self.assertEqual(next(csv.reader(f)), headers)

    def test_ensure_csv_header_repairs_headerless_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "entropy_logs.csv")
            headers = KNOWN_CSV_HEADERS["entropy_logs.csv"]
            with open(path, "w", newline="") as f:
                f.write("2026-07-09 10:01:07,1,20,1.0,1.0,0.5,0.5,0.5,0.76,ALERT,85.0\n")

            ensure_csv_header(path, headers)
            self.assertTrue(csv_has_valid_header(path))
            rows = load_csv_rows(path)
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["timestamp"], "2026-07-09 10:01:07")
            self.assertEqual(rows[0]["status"], "ALERT")
            self.assertAlmostEqual(float(rows[0]["entropy_score"]), 0.76)

    def test_load_csv_rows_fallback_without_repair(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "detection_alerts.csv")
            headers = KNOWN_CSV_HEADERS["detection_alerts.csv"]
            with open(path, "w", newline="") as f:
                f.write(
                    "2026-07-09 10:02:00,1,SRC_ENTROPY_COLLAPSE,src_entropy,"
                    "0.12,0.5,0.78,90.0,ALERT\n"
                )

            rows = load_csv_rows(path, fallback_headers=headers)
            self.assertEqual(rows[0]["alert_type"], "SRC_ENTROPY_COLLAPSE")
            self.assertEqual(rows[0]["switch_id"], "1")


if __name__ == "__main__":
    unittest.main()
