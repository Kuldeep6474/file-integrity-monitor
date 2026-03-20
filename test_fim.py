#!/usr/bin/env python3
"""
Test suite for File Integrity Monitor (FIM)
Run with: python tests/test_fim.py
"""

import os
import sys
import json
import time
import unittest
import tempfile
import shutil

# Add parent directory to path so we can import fim
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import fim


class TestFIM(unittest.TestCase):
    """Test cases for the File Integrity Monitor"""

    def setUp(self):
        """Create a temporary directory with test files before each test"""
        self.test_dir = tempfile.mkdtemp()
        # Create some test files
        self.file1 = os.path.join(self.test_dir, "config.txt")
        self.file2 = os.path.join(self.test_dir, "data.txt")
        with open(self.file1, "w") as f:
            f.write("Original config content")
        with open(self.file2, "w") as f:
            f.write("Original data content")

    def tearDown(self):
        """Clean up after each test"""
        shutil.rmtree(self.test_dir, ignore_errors=True)
        if os.path.exists(fim.BASELINE_FILE):
            os.remove(fim.BASELINE_FILE)

    def test_sha256_consistent(self):
        """Same file should always produce the same hash"""
        hash1 = fim.compute_sha256(self.file1)
        hash2 = fim.compute_sha256(self.file1)
        self.assertEqual(hash1, hash2)
        self.assertIsNotNone(hash1)
        self.assertEqual(len(hash1), 64)  # SHA-256 = 64 hex chars

    def test_sha256_different_files(self):
        """Different files should produce different hashes"""
        hash1 = fim.compute_sha256(self.file1)
        hash2 = fim.compute_sha256(self.file2)
        self.assertNotEqual(hash1, hash2)

    def test_sha256_nonexistent_file(self):
        """Non-existent file should return None, not crash"""
        result = fim.compute_sha256("/nonexistent/path/file.txt")
        self.assertIsNone(result)

    def test_create_baseline(self):
        """Baseline should be created with correct file count"""
        baseline = fim.create_baseline(self.test_dir)
        self.assertEqual(baseline["meta"]["total_files"], 2)
        self.assertIn("files", baseline)

    def test_detect_modified_file(self):
        """Modified file should be detected as MODIFIED"""
        fim.create_baseline(self.test_dir)
        # Tamper with a file
        with open(self.file1, "w") as f:
            f.write("TAMPERED CONTENT!")
        results = fim.check_integrity(self.test_dir)
        self.assertEqual(len(results["modified"]), 1)
        self.assertEqual(results["summary"]["status"], "ALERT")

    def test_detect_deleted_file(self):
        """Deleted file should be detected as DELETED"""
        fim.create_baseline(self.test_dir)
        os.remove(self.file1)
        results = fim.check_integrity(self.test_dir)
        self.assertEqual(len(results["deleted"]), 1)

    def test_detect_new_file(self):
        """New file should be detected as NEW"""
        fim.create_baseline(self.test_dir)
        new_file = os.path.join(self.test_dir, "newfile.txt")
        with open(new_file, "w") as f:
            f.write("I am a new file")
        results = fim.check_integrity(self.test_dir)
        self.assertEqual(len(results["new_files"]), 1)

    def test_clean_result(self):
        """Unchanged files should result in CLEAN status"""
        fim.create_baseline(self.test_dir)
        results = fim.check_integrity(self.test_dir)
        self.assertEqual(results["summary"]["status"], "CLEAN")
        self.assertEqual(len(results["modified"]), 0)


if __name__ == "__main__":
    print("Running FIM Test Suite...\n")
    unittest.main(verbosity=2)
