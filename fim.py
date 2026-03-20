#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║           FILE INTEGRITY MONITOR (FIM)                       ║
║           Cybersecurity Project — GitHub Portfolio           ║
╚══════════════════════════════════════════════════════════════╝

Author  : [Your Name]
GitHub  : https://github.com/yourusername
Version : 1.0.0
License : MIT

DESCRIPTION:
    A professional-grade File Integrity Monitoring tool that detects
    unauthorized changes to files using SHA-256 cryptographic hashing.
    Monitors files in real-time, logs all events, and generates reports.

    This tool mimics enterprise security tools like Tripwire and AIDE.

DISCLAIMER:
    This tool is built for EDUCATIONAL purposes and legitimate
    system security monitoring only. Use only on systems you own
    or have written permission to monitor.

USAGE:
    python fim.py --init  --path /path/to/monitor
    python fim.py --check --path /path/to/monitor
    python fim.py --watch --path /path/to/monitor --interval 30
    python fim.py --report
"""

import os
import sys
import json
import time
import hashlib
import logging
import argparse
import datetime
import platform
from pathlib import Path
from typing import Dict, List, Tuple, Optional


# ─────────────────────────────────────────────
#  CONFIGURATION
# ─────────────────────────────────────────────

BASELINE_FILE  = "baseline.json"       # stores original file hashes
LOG_FILE       = "logs/fim.log"        # event log file
REPORT_FILE    = "reports/report.json" # latest report output
VERSION        = "1.0.0"
BANNER = """
╔══════════════════════════════════════════════════════════╗
║   ███████╗██╗███╗   ███╗                                 ║
║   ██╔════╝██║████╗ ████║                                 ║
║   █████╗  ██║██╔████╔██║   File Integrity Monitor       ║
║   ██╔══╝  ██║██║╚██╔╝██║   Version {ver}               ║
║   ██║     ██║██║ ╚═╝ ██║   Cybersecurity Portfolio Tool ║
║   ╚═╝     ╚═╝╚═╝     ╚═╝                                ║
╚══════════════════════════════════════════════════════════╝
"""


# ─────────────────────────────────────────────
#  LOGGING SETUP
# ─────────────────────────────────────────────

def setup_logging() -> logging.Logger:
    """
    Configure logging to write to both console and a log file.
    Returns a Logger object used throughout the program.
    """
    os.makedirs("logs", exist_ok=True)

    logger = logging.getLogger("FIM")
    logger.setLevel(logging.DEBUG)

    # Console handler — shows INFO and above
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_fmt = logging.Formatter(
        "%(asctime)s  [%(levelname)s]  %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    console_handler.setFormatter(console_fmt)

    # File handler — records everything including DEBUG
    file_handler = logging.FileHandler(LOG_FILE, encoding="utf-8")
    file_handler.setLevel(logging.DEBUG)
    file_fmt = logging.Formatter(
        "%(asctime)s | %(levelname)-8s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    file_handler.setFormatter(file_fmt)

    logger.addHandler(console_handler)
    logger.addHandler(file_handler)
    return logger


logger = setup_logging()


# ─────────────────────────────────────────────
#  CORE HASHING FUNCTIONS
# ─────────────────────────────────────────────

def compute_sha256(filepath: str) -> Optional[str]:
    """
    Compute the SHA-256 hash of a file.

    SHA-256 is a cryptographic hash function that produces a unique
    256-bit (64 hex character) fingerprint for every file. Even changing
    ONE byte in a file produces a completely different hash — making it
    perfect for detecting tampering.

    Args:
        filepath: Full path to the file to hash

    Returns:
        64-character hex string of the SHA-256 hash, or None if error

    Example:
        hash = compute_sha256("/etc/passwd")
        # Returns: "e3b0c44298fc1c149afbf4c8996fb92..."
    """
    sha256 = hashlib.sha256()

    try:
        # Read file in 64KB chunks — handles large files without
        # loading them entirely into RAM
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                sha256.update(chunk)
        return sha256.hexdigest()

    except PermissionError:
        logger.warning(f"Permission denied reading: {filepath}")
        return None
    except FileNotFoundError:
        logger.warning(f"File not found during hash: {filepath}")
        return None
    except Exception as e:
        logger.error(f"Error hashing {filepath}: {e}")
        return None


def get_file_metadata(filepath: str) -> Dict:
    """
    Collect metadata about a file: size, timestamps, permissions.

    This metadata helps investigators understand WHEN a file changed
    and gives extra evidence alongside the hash comparison.

    Args:
        filepath: Full path to the file

    Returns:
        Dictionary with size, modified time, permissions, owner
    """
    try:
        stat = os.stat(filepath)
        return {
            "size_bytes"    : stat.st_size,
            "modified_time" : datetime.datetime.fromtimestamp(
                                  stat.st_mtime
                              ).isoformat(),
            "permissions"   : oct(stat.st_mode)[-4:],  # e.g. "0644"
        }
    except Exception as e:
        logger.debug(f"Could not get metadata for {filepath}: {e}")
        return {}


# ─────────────────────────────────────────────
#  BASELINE MANAGEMENT
# ─────────────────────────────────────────────

def create_baseline(target_path: str) -> Dict:
    """
    Scan all files in target_path and save their SHA-256 hashes.

    This creates the "trusted baseline" — a snapshot of file hashes
    when everything is KNOWN to be safe. Future checks compare against
    this snapshot to detect any changes.

    Think of this like photographing every file's fingerprint.

    Args:
        target_path: Directory path to scan

    Returns:
        Baseline dictionary containing all file hashes + metadata
    """
    logger.info(f"Creating baseline for: {target_path}")

    if not os.path.exists(target_path):
        logger.error(f"Target path does not exist: {target_path}")
        sys.exit(1)

    baseline = {
        "meta": {
            "created_at"    : datetime.datetime.now().isoformat(),
            "target_path"   : os.path.abspath(target_path),
            "platform"      : platform.system(),
            "python_version": platform.python_version(),
            "fim_version"   : VERSION,
            "total_files"   : 0,
        },
        "files": {}
    }

    file_count = 0
    error_count = 0

    # Walk the directory tree recursively
    for root, dirs, files in os.walk(target_path):
        # Skip hidden directories (like .git)
        dirs[:] = [d for d in dirs if not d.startswith(".")]

        for filename in files:
            filepath = os.path.join(root, filename)
            abs_path = os.path.abspath(filepath)

            file_hash = compute_sha256(abs_path)

            if file_hash:
                baseline["files"][abs_path] = {
                    "hash"    : file_hash,
                    "metadata": get_file_metadata(abs_path)
                }
                file_count += 1
                logger.debug(f"  Hashed: {abs_path}")
            else:
                error_count += 1

    baseline["meta"]["total_files"] = file_count
    baseline["meta"]["error_count"] = error_count

    # Save baseline to JSON file
    os.makedirs(os.path.dirname(BASELINE_FILE) if os.path.dirname(BASELINE_FILE) else ".", exist_ok=True)
    with open(BASELINE_FILE, "w", encoding="utf-8") as f:
        json.dump(baseline, f, indent=2)

    logger.info(f"Baseline created: {file_count} files hashed, {error_count} errors")
    logger.info(f"Saved to: {BASELINE_FILE}")
    return baseline


def load_baseline() -> Optional[Dict]:
    """
    Load the previously saved baseline from disk.

    Returns:
        Baseline dictionary, or None if baseline doesn't exist
    """
    if not os.path.exists(BASELINE_FILE):
        logger.error("No baseline found! Run with --init first.")
        return None

    try:
        with open(BASELINE_FILE, "r", encoding="utf-8") as f:
            baseline = json.load(f)
        logger.info(f"Loaded baseline: {baseline['meta']['total_files']} files")
        logger.info(f"Baseline created: {baseline['meta']['created_at']}")
        return baseline

    except json.JSONDecodeError as e:
        logger.error(f"Baseline file is corrupted: {e}")
        return None


# ─────────────────────────────────────────────
#  INTEGRITY CHECKING
# ─────────────────────────────────────────────

def check_integrity(target_path: str) -> Dict:
    """
    Compare current file hashes against the baseline.

    This is the core security function. It checks every file and
    reports four types of events:

    - MODIFIED   : file exists but hash changed (potential tampering!)
    - DELETED    : file was in baseline but is now missing
    - NEW        : file exists now but wasn't in the baseline
    - UNCHANGED  : hash matches — file is safe

    Args:
        target_path: Directory to check (should match baseline path)

    Returns:
        Results dictionary with all findings
    """
    logger.info(f"Starting integrity check on: {target_path}")
    logger.info("-" * 56)

    baseline = load_baseline()
    if not baseline:
        sys.exit(1)

    # Gather current state of the filesystem
    current_files: Dict[str, str] = {}
    for root, dirs, files in os.walk(target_path):
        dirs[:] = [d for d in dirs if not d.startswith(".")]
        for filename in files:
            filepath = os.path.abspath(os.path.join(root, filename))
            file_hash = compute_sha256(filepath)
            if file_hash:
                current_files[filepath] = file_hash

    baseline_files = baseline["files"]

    # ── Compare baseline vs current ──
    results = {
        "check_time"  : datetime.datetime.now().isoformat(),
        "target_path" : target_path,
        "modified"    : [],   # CRITICAL — hash changed
        "deleted"     : [],   # WARNING  — file removed
        "new_files"   : [],   # INFO     — new file appeared
        "unchanged"   : [],   # OK       — all good
        "summary"     : {}
    }

    # Check files in baseline against current state
    for filepath, info in baseline_files.items():
        baseline_hash = info["hash"]

        if filepath not in current_files:
            # File was in baseline but is now GONE
            results["deleted"].append({
                "path"          : filepath,
                "baseline_hash" : baseline_hash,
                "event"         : "DELETED"
            })
            logger.warning(f"[DELETED]  {filepath}")

        elif current_files[filepath] != baseline_hash:
            # File exists but hash is DIFFERENT — possible tampering
            results["modified"].append({
                "path"          : filepath,
                "baseline_hash" : baseline_hash,
                "current_hash"  : current_files[filepath],
                "event"         : "MODIFIED"
            })
            logger.critical(f"[MODIFIED] {filepath}")
            logger.critical(f"           OLD: {baseline_hash}")
            logger.critical(f"           NEW: {current_files[filepath]}")

        else:
            # Hash matches — file is UNCHANGED
            results["unchanged"].append(filepath)
            logger.debug(f"[OK]       {filepath}")

    # Check for NEW files not in the baseline
    for filepath in current_files:
        if filepath not in baseline_files:
            results["new_files"].append({
                "path"  : filepath,
                "hash"  : current_files[filepath],
                "event" : "NEW"
            })
            logger.info(f"[NEW FILE] {filepath}")

    # Build summary
    results["summary"] = {
        "total_checked" : len(baseline_files),
        "unchanged"     : len(results["unchanged"]),
        "modified"      : len(results["modified"]),
        "deleted"       : len(results["deleted"]),
        "new_files"     : len(results["new_files"]),
        "alerts"        : len(results["modified"]) + len(results["deleted"]),
        "status"        : "CLEAN" if not results["modified"] and not results["deleted"] else "ALERT"
    }

    return results


# ─────────────────────────────────────────────
#  REPORTING
# ─────────────────────────────────────────────

def print_results(results: Dict) -> None:
    """
    Print a formatted summary of the integrity check results to console.
    """
    summary = results["summary"]

    print()
    print("=" * 58)
    print("  INTEGRITY CHECK RESULTS")
    print(f"  Time   : {results['check_time']}")
    print(f"  Target : {results['target_path']}")
    print("=" * 58)
    print(f"  Total files checked : {summary['total_checked']}")
    print(f"  ✅ Unchanged        : {summary['unchanged']}")
    print(f"  🆕 New files        : {summary['new_files']}")
    print(f"  ⚠️  Deleted          : {summary['deleted']}")
    print(f"  🚨 Modified         : {summary['modified']}")
    print("-" * 58)

    if summary["status"] == "CLEAN":
        print("  STATUS: ✅  ALL FILES CLEAN — No tampering detected")
    else:
        print(f"  STATUS: 🚨  ALERT — {summary['alerts']} suspicious change(s) detected!")
        print()
        if results["modified"]:
            print("  MODIFIED FILES (possible tampering):")
            for item in results["modified"]:
                print(f"    → {item['path']}")
        if results["deleted"]:
            print("  DELETED FILES:")
            for item in results["deleted"]:
                print(f"    → {item['path']}")

    print("=" * 58)
    print()


def save_report(results: Dict) -> None:
    """
    Save detailed results to a JSON report file.
    Useful for audits and incident response documentation.
    """
    os.makedirs("reports", exist_ok=True)

    # Remove the big "unchanged" list from report to keep it clean
    report = {k: v for k, v in results.items() if k != "unchanged"}
    report["unchanged_count"] = len(results.get("unchanged", []))

    with open(REPORT_FILE, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    logger.info(f"Report saved to: {REPORT_FILE}")


# ─────────────────────────────────────────────
#  CONTINUOUS MONITORING (WATCH MODE)
# ─────────────────────────────────────────────

def watch_mode(target_path: str, interval: int = 60) -> None:
    """
    Run continuous integrity checks at regular intervals.

    This is the "real-time monitoring" mode. It runs check_integrity()
    every `interval` seconds and alerts whenever something changes.

    In a real enterprise environment, this would also send email alerts
    or push to a SIEM (Security Information and Event Management) system.

    Args:
        target_path : Directory to monitor
        interval    : Seconds between each check (default: 60)
    """
    logger.info(f"Entering WATCH MODE — checking every {interval} seconds")
    logger.info("Press Ctrl+C to stop monitoring")
    logger.info("-" * 56)

    check_number = 0

    try:
        while True:
            check_number += 1
            logger.info(f"Running check #{check_number}...")

            results = check_integrity(target_path)
            print_results(results)
            save_report(results)

            if results["summary"]["status"] == "ALERT":
                logger.critical("ALERT DETECTED — See report for details")

            logger.info(f"Next check in {interval} seconds... (Ctrl+C to stop)")
            time.sleep(interval)

    except KeyboardInterrupt:
        logger.info("Watch mode stopped by user.")
        print("\n[FIM] Monitoring stopped. Goodbye.")


# ─────────────────────────────────────────────
#  COMMAND LINE INTERFACE
# ─────────────────────────────────────────────

def parse_arguments() -> argparse.Namespace:
    """
    Parse command-line arguments using argparse.

    argparse is Python's built-in library for building CLI tools.
    It automatically generates --help output and validates inputs.
    """
    parser = argparse.ArgumentParser(
        prog="fim.py",
        description="File Integrity Monitor — detect unauthorized file changes",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
EXAMPLES:
  Create baseline:
    python fim.py --init --path ./test_files

  Run a one-time check:
    python fim.py --check --path ./test_files

  Start continuous monitoring (every 30 sec):
    python fim.py --watch --path ./test_files --interval 30

  Show last report:
    python fim.py --report
        """
    )

    # Mutually exclusive group — user can only pick one mode
    mode_group = parser.add_mutually_exclusive_group(required=True)
    mode_group.add_argument(
        "--init",
        action="store_true",
        help="Create a new baseline (do this first!)"
    )
    mode_group.add_argument(
        "--check",
        action="store_true",
        help="Run a one-time integrity check"
    )
    mode_group.add_argument(
        "--watch",
        action="store_true",
        help="Start continuous real-time monitoring"
    )
    mode_group.add_argument(
        "--report",
        action="store_true",
        help="Display the last saved report"
    )

    parser.add_argument(
        "--path",
        type=str,
        default=".",
        help="Path to directory to monitor (default: current directory)"
    )
    parser.add_argument(
        "--interval",
        type=int,
        default=60,
        help="Seconds between checks in watch mode (default: 60)"
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"FIM v{VERSION}"
    )

    return parser.parse_args()


# ─────────────────────────────────────────────
#  MAIN ENTRY POINT
# ─────────────────────────────────────────────

def main() -> None:
    """
    Main function — the entry point of the program.
    Reads CLI arguments and dispatches to the right function.
    """
    print(BANNER.format(ver=VERSION))

    args = parse_arguments()

    if args.init:
        # ── MODE: Create baseline ──
        logger.info("MODE: Initialize baseline")
        baseline = create_baseline(args.path)
        print(f"\n✅ Baseline created successfully!")
        print(f"   Files hashed : {baseline['meta']['total_files']}")
        print(f"   Saved to     : {BASELINE_FILE}")
        print(f"\n➡️  Now run:  python fim.py --check --path {args.path}\n")

    elif args.check:
        # ── MODE: One-time integrity check ──
        logger.info("MODE: One-time integrity check")
        results = check_integrity(args.path)
        print_results(results)
        save_report(results)

    elif args.watch:
        # ── MODE: Continuous monitoring ──
        logger.info("MODE: Watch / continuous monitoring")
        watch_mode(args.path, args.interval)

    elif args.report:
        # ── MODE: Show last report ──
        if os.path.exists(REPORT_FILE):
            with open(REPORT_FILE, "r") as f:
                report = json.load(f)
            print(json.dumps(report, indent=2))
        else:
            logger.error("No report found. Run --check first.")


if __name__ == "__main__":
    main()
