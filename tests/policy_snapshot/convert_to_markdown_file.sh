#!/bin/bash

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# Usage:
#   ./convert_to_markdown_file.sh ./snapshots/debug_v1 ./snapshots/DebugV1.md
#   ./convert_to_markdown_file.sh ./snapshots/diffable_v1 ./snapshots/DiffableV1.md

dir="${1:-.}"
output="${2:-output.md}"

{
for file in "$dir"/*; do
    [ -f "$file" ] || continue
    echo "## $(basename "$file")"
    echo " "
    echo '```'
    cat "$file"
    echo '```'
    echo " "
done
} > "$output"
