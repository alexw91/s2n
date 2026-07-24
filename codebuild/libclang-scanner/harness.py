#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License").
# You may not use this file except in compliance with the License.
# A copy of the License is located at
#
#  http://aws.amazon.com/apache2.0
#
# or in the "license" file accompanying this file. This file is distributed
# on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
# express or implied. See the License for the specific language governing
# permissions and limitations under the License.
"""
harness.py — CLI entry point for the libclang code hardening scanner.

Parses C source files using libclang and runs all check plugins found in the
checks/ directory. Designed to be used as a CI gate with zero false positives.

Usage:
    python3 harness.py --compile-commands build/compile_commands.json \\
                       --source-dirs crypto/ tls/ utils/ tests/unit/

Exit codes:
    0  No findings (all checks pass)
    1  Findings detected (CI should fail)
    2  Configuration error or unexpected failure (CI should fail loudly)
"""
import argparse
import importlib
import json
import os
import sys
import time

# Ensure the scanner package is importable regardless of cwd
SCANNER_DIR = os.path.dirname(os.path.abspath(__file__))
if SCANNER_DIR not in sys.path:
    sys.path.insert(0, SCANNER_DIR)

from utils import (
    extract_clang_args,
    get_platform_args,
    infer_repo_root,
    is_file_in_source_dirs,
    resolve_source_dirs,
)

try:
    from clang.cindex import Index, CursorKind
except ImportError:
    print(
        "ERROR: libclang Python bindings not installed.\n"
        "Install with: pip install libclang",
        file=sys.stderr,
    )
    sys.exit(2)


def discover_checks():
    """Find and import all check modules in the checks/ directory.

    Each module must export a `check(cursor, source_file, source_dirs, findings)`
    function. Modules without this function are skipped with a warning.

    Returns a list of (module_name, check_function) tuples.
    """
    checks_dir = os.path.join(SCANNER_DIR, "checks")
    if not os.path.isdir(checks_dir):
        print(f"ERROR: checks/ directory not found at {checks_dir}", file=sys.stderr)
        sys.exit(2)

    checks = []
    for filename in sorted(os.listdir(checks_dir)):
        if not filename.endswith(".py") or filename.startswith("_"):
            continue

        module_name = filename[:-3]
        try:
            module = importlib.import_module(f"checks.{module_name}")
        except Exception as e:
            print(
                f"ERROR: Failed to import check module 'checks/{filename}': {e}",
                file=sys.stderr,
            )
            sys.exit(2)

        if not hasattr(module, "check") or not callable(module.check):
            print(
                f"WARNING: checks/{filename} has no check() function, skipping.",
                file=sys.stderr,
            )
            continue

        check_id = getattr(module, "CHECK_ID", module_name)
        checks.append((check_id, module.check))

    if not checks:
        print("ERROR: No valid check modules found in checks/", file=sys.stderr)
        sys.exit(2)

    return checks


def run_self_tests(index, platform_args, source_dirs_for_tests):
    """Run golden-file self-tests to detect libclang version incompatibility.

    Parses synthetic test files and compares findings against expected results.
    Exits with code 2 if any self-test diverges from expected.
    """
    tests_dir = os.path.join(SCANNER_DIR, "tests")
    if not os.path.isdir(tests_dir):
        return  # No self-tests present — skip silently

    expected_files = [
        f for f in os.listdir(tests_dir) if f.endswith(".expected.json")
    ]
    if not expected_files:
        return  # No golden files — skip

    checks = discover_checks()

    for expected_file in sorted(expected_files):
        base_name = expected_file.replace(".expected.json", "")
        source_file = os.path.join(tests_dir, base_name + ".c")
        expected_path = os.path.join(tests_dir, expected_file)

        if not os.path.isfile(source_file):
            print(
                f"ERROR: Self-test source file missing: {source_file}",
                file=sys.stderr,
            )
            sys.exit(2)

        with open(expected_path) as f:
            expected = json.load(f)

        # Parse the test file
        tu = index.parse(source_file, args=platform_args)
        if tu is None:
            print(
                f"ERROR: Self-test failed — could not parse {source_file}",
                file=sys.stderr,
            )
            sys.exit(2)

        # Run all checks against the test file
        findings = []
        test_source_dirs = [tests_dir]
        for _, check_fn in checks:
            check_fn(tu.cursor, source_file, test_source_dirs, findings)

        # Compare: extract just the fields that matter for comparison
        actual_set = set()
        for f in findings:
            actual_set.add((f["line"], f["column"], f["variable"], f["check_id"]))

        expected_set = set()
        for e in expected:
            expected_set.add((e["line"], e["column"], e["variable"], e["check_id"]))

        if actual_set != expected_set:
            missing = expected_set - actual_set
            extra = actual_set - expected_set
            msg_parts = [f"Self-test FAILED for {base_name}.c:"]
            if missing:
                msg_parts.append(f"  Expected but not found: {sorted(missing)}")
            if extra:
                msg_parts.append(f"  Found but not expected: {sorted(extra)}")
            msg_parts.append(
                "This likely indicates a libclang version incompatibility. "
                "Update the golden file or fix the check logic."
            )
            print("\n".join(msg_parts), file=sys.stderr)
            sys.exit(2)

    return


def scan_translation_unit(entry, index, platform_args, source_dirs, checks):
    """Parse one source file and run all checks against its AST.

    Returns (findings, errors) where errors is a list of diagnostic messages
    for files that failed to parse.
    """
    source_file = entry["file"]
    clang_args = extract_clang_args(entry) + platform_args

    tu = index.parse(source_file, args=clang_args)
    if tu is None:
        return [], [f"Failed to parse {source_file}"]

    # Check for parse errors (severity >= 3 is error, >= 4 is fatal).
    # Skip files with errors — incomplete AST could produce false negatives.
    errors = [d for d in tu.diagnostics if d.severity >= 3]
    if errors:
        msgs = [f"{d.location}: {d.spelling}" for d in errors[:3]]
        return [], msgs

    findings = []
    for _, check_fn in checks:
        check_fn(tu.cursor, source_file, source_dirs, findings)

    return findings, []


def deduplicate_findings(findings):
    """Remove duplicate findings across translation units.

    The same header file may be parsed via multiple .c files, producing
    identical findings. Deduplicate on (file, line, column, variable, check_id).
    """
    seen = set()
    unique = []
    for f in findings:
        key = (f["file"], f["line"], f["column"], f["variable"], f["check_id"])
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique


def format_findings(findings, repo_root):
    """Print findings in a human-readable format sorted by file and line."""
    sorted_findings = sorted(findings, key=lambda f: (f["file"], f["line"]))

    for f in sorted_findings:
        rel_path = os.path.relpath(f["file"], repo_root)
        print(
            f"  {rel_path}:{f['line']}:{f['column']}: "
            f"[{f['check_id']}] {f['message']}"
        )


def main():
    parser = argparse.ArgumentParser(
        description="Libclang-based code hardening scanner for C projects."
    )
    parser.add_argument(
        "--compile-commands",
        required=True,
        help="Path to compile_commands.json (from cmake -DCMAKE_EXPORT_COMPILE_COMMANDS=ON)",
    )
    parser.add_argument(
        "--source-dirs",
        nargs="+",
        required=True,
        help="Source directories to scan (relative to repo root)",
    )
    args = parser.parse_args()

    # Validate compile_commands.json
    if not os.path.isfile(args.compile_commands):
        print(
            f"ERROR: {args.compile_commands} not found.\n"
            "Generate with: cmake -S . -B build -DCMAKE_EXPORT_COMPILE_COMMANDS=ON",
            file=sys.stderr,
        )
        sys.exit(2)

    with open(args.compile_commands) as f:
        try:
            compile_db = json.load(f)
        except json.JSONDecodeError as e:
            print(
                f"ERROR: Invalid JSON in {args.compile_commands}: {e}",
                file=sys.stderr,
            )
            sys.exit(2)

    if not compile_db:
        print(
            f"ERROR: {args.compile_commands} is empty (no compilation entries).",
            file=sys.stderr,
        )
        sys.exit(2)

    # Determine repo root and resolve source directories
    repo_root = infer_repo_root(args.compile_commands)
    source_dirs = resolve_source_dirs(args.source_dirs, repo_root)

    # Platform-specific args for libclang
    platform_args = get_platform_args()

    # Create the libclang index
    index = Index.create()

    # Run self-tests first to catch libclang version incompatibility
    run_self_tests(index, platform_args, source_dirs)

    # Discover check plugins
    checks = discover_checks()
    check_names = [name for name, _ in checks]
    print(f"Checks enabled: {', '.join(check_names)}")

    # Filter compile_commands entries to source directories
    entries = []
    for entry in compile_db:
        if is_file_in_source_dirs(entry["file"], source_dirs):
            entries.append(entry)

    if not entries:
        print(
            f"ERROR: No source files found in {args.source_dirs} "
            f"(repo_root={repo_root})",
            file=sys.stderr,
        )
        sys.exit(2)

    print(f"Scanning {len(entries)} translation units...")

    # Scan all translation units
    all_findings = []
    all_errors = []
    start = time.time()

    for i, entry in enumerate(entries):
        findings, errors = scan_translation_unit(
            entry, index, platform_args, source_dirs, checks
        )
        all_findings.extend(findings)
        if errors:
            all_errors.append((os.path.relpath(entry["file"], repo_root), errors))

    elapsed = time.time() - start

    # Deduplicate findings from headers parsed via multiple translation units
    all_findings = deduplicate_findings(all_findings)

    # Report results
    print(f"\nCompleted in {elapsed:.1f}s")

    if all_errors:
        print(f"\n{len(all_errors)} file(s) had parse errors:")
        for filepath, msgs in all_errors[:10]:
            print(f"  {filepath}: {msgs[0]}")
        if len(all_errors) > 10:
            print(f"  ... and {len(all_errors) - 10} more")

    if all_findings:
        print(f"\n{len(all_findings)} finding(s):\n")
        format_findings(all_findings, repo_root)
        print(f"\n{len(all_findings)} total finding(s) across {len(entries)} files.")
        sys.exit(1)
    else:
        print("\nNo findings. All checks pass.")
        sys.exit(0)


if __name__ == "__main__":
    main()
