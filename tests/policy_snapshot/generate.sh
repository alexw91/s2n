#!/bin/bash

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

set -eu

SNAPSHOTS_DIR_DEFAULT="./tests/policy_snapshot/snapshots"
SECURITY_POLICIES_C_DEFAULT="./tls/s2n_security_policies.c"
SCRIPT_DIR="$(dirname "$0")"

function display_usage {
    echo "Usage: $0 <policy_path> [snapshots_dir] [s2n_security_policies]"
    echo
    echo "Arguments:"
    echo "  policy_path                 Path to the policy util binary"
    echo "  snapshots_dir               Path to the snapshots directory"
    echo "                              (default: $SNAPSHOTS_DIR_DEFAULT)"
    echo "  s2n_security_policies       Path to the s2n_security_policies.c file"
    echo "                              (default: $SECURITY_POLICIES_C_DEFAULT)"
    echo
    exit 1
}

if [ $# -lt 1 ] || [ $# -gt 3 ] || [ "$1" == "--help" ]; then
    display_usage
fi

POLICY_BINARY="$1"
SNAPSHOTS_DIR=${2:-$SNAPSHOTS_DIR_DEFAULT}
SECURITY_POLICIES_C=${3:-$SECURITY_POLICIES_C_DEFAULT}

echo "Using snapshots directory: $SNAPSHOTS_DIR"
echo "Using policy binary: $POLICY_BINARY"
echo "Using security policy file: $SECURITY_POLICIES_C"

echo "Extracting security policy names..."
POLICIES=$(grep -o '{ .version = "[^"]*"' $SECURITY_POLICIES_C \
    | sed 's/{ .version = "\(.*\)"/\1/' | grep -v "^null$")

COUNT=$(echo "$POLICIES" | wc -l)
echo "Found $COUNT policies."

rm -rf $SNAPSHOTS_DIR
mkdir -p $SNAPSHOTS_DIR/debug_v1
mkdir -p $SNAPSHOTS_DIR/diffable_v1

for policy in $POLICIES; do
    $POLICY_BINARY $policy S2N_POLICY_FORMAT_DEBUG_V1 > $SNAPSHOTS_DIR/debug_v1/$policy
    $POLICY_BINARY $policy S2N_POLICY_FORMAT_DIFFABLE_V1 > $SNAPSHOTS_DIR/diffable_v1/$policy
    echo "Generated snapshots for $policy..."
done

echo
echo "Generating markdown files..."
bash "$SCRIPT_DIR/convert_to_markdown_file.sh" "$SNAPSHOTS_DIR/debug_v1" "$SNAPSHOTS_DIR/DebugV1.md"
bash "$SCRIPT_DIR/convert_to_markdown_file.sh" "$SNAPSHOTS_DIR/diffable_v1" "$SNAPSHOTS_DIR/DiffableV1.md"

echo "Snapshots successfully generated."
exit 0
