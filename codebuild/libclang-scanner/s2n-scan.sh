#!/usr/bin/env bash
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
#
# Run the libclang hardening scanner with s2n-tls source directories.
#
# Usage (from repo root):
#   ./codebuild/libclang-scanner/s2n-scan.sh
#
# Prerequisites:
#   pip install libclang
#   cmake -S . -B build -DCMAKE_EXPORT_COMPILE_COMMANDS=ON

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

COMPILE_COMMANDS="$REPO_ROOT/build/compile_commands.json"

if [ ! -f "$COMPILE_COMMANDS" ]; then
    echo "compile_commands.json not found. Generating..."
    cmake -S "$REPO_ROOT" -B "$REPO_ROOT/build" -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
fi

# exec replaces this shell process with the scanner. No post-scan steps are
# possible — all exit codes propagate directly to the caller.
exec python3 "$SCRIPT_DIR/harness.py" \
    --compile-commands "$COMPILE_COMMANDS" \
    --source-dirs \
        crypto/ \
        error/ \
        stuffer/ \
        tls/ \
        utils/ \
        bin/ \
        tests/LD_PRELOAD/ \
        tests/features/ \
        tests/fuzz/ \
        tests/pcap/ \
        tests/pems/ \
        tests/policy_snapshot/ \
        tests/regression/ \
        tests/testlib/ \
        tests/unit/ \
        tests/viz/
