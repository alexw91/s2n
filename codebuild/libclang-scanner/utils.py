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
utils.py — Shared utilities for the libclang scanner framework.

Handles platform detection, compile_commands.json argument extraction,
and cross-platform libclang configuration.
"""
import os
import shlex
import subprocess
import sys


def get_platform_args():
    """Return platform-specific flags that libclang needs to find system headers.

    On macOS: locates the SDK via xcrun and the clang resource directory.
    On Linux: returns an empty list (system headers are in standard locations).

    Fails loud (exits 2) if macOS is detected but xcrun or clang is missing,
    since partial platform args produce silent parse failures.
    """
    if sys.platform != "darwin":
        return []

    args = []
    try:
        sdk = subprocess.check_output(
            ["xcrun", "--show-sdk-path"], text=True, stderr=subprocess.DEVNULL
        ).strip()
        args.extend(["-isysroot", sdk])
    except (FileNotFoundError, subprocess.CalledProcessError) as e:
        print(
            f"ERROR: macOS detected but xcrun failed: {e}\n"
            "Install Xcode Command Line Tools: xcode-select --install",
            file=sys.stderr,
        )
        sys.exit(2)

    try:
        resource_dir = subprocess.check_output(
            ["clang", "--print-resource-dir"], text=True, stderr=subprocess.DEVNULL
        ).strip()
        args.extend(["-isystem", os.path.join(resource_dir, "include")])
    except (FileNotFoundError, subprocess.CalledProcessError):
        # clang resource dir is optional — system headers via isysroot suffice
        pass

    return args


def extract_clang_args(entry):
    """Extract compiler flags from a compile_commands.json entry.

    Strips flags that are irrelevant or harmful to libclang parsing:
    - Output flags (-o, -c, -MF, -MT, -MQ)
    - Warning flags (-W*, -Werror, -pedantic)
    - Visibility and PIC flags
    - The source file itself
    - Architecture flags (-arch) that may conflict

    Keeps include paths (-I, -isystem), defines (-D), and standard flags (-std).
    """
    if "command" in entry:
        args = shlex.split(entry["command"])
    elif "arguments" in entry:
        args = list(entry["arguments"])
    else:
        return []

    source_file = entry.get("file", "")
    clang_args = []
    skip_next = False

    for i, arg in enumerate(args):
        if skip_next:
            skip_next = False
            continue
        # Skip the compiler invocation itself
        if i == 0:
            continue
        # Skip flags that take a following argument
        if arg in ("-o", "-c", "-MF", "-MT", "-MQ", "-arch"):
            skip_next = True
            continue
        # Skip the source file
        if arg == source_file:
            continue
        # Skip warning and style flags (irrelevant to AST)
        if arg.startswith(("-W", "-Wa,")) or arg in ("-pedantic", "-Werror"):
            continue
        # Skip visibility and position-independent flags
        if arg.startswith("-fvisibility") or arg == "-fPIC":
            continue
        clang_args.append(arg)

    return clang_args


def is_file_in_source_dirs(filepath, source_dirs):
    """Return True if filepath is under one of the source directories.

    Both the filepath and source_dirs should be absolute paths.
    Checks prefix matching on normalized paths.
    """
    normalized = os.path.normpath(filepath)
    for src_dir in source_dirs:
        normalized_dir = os.path.normpath(src_dir)
        if normalized.startswith(normalized_dir + os.sep) or normalized == normalized_dir:
            return True
    return False


def resolve_source_dirs(source_dirs, repo_root):
    """Convert relative source directory paths to absolute paths based on repo_root.

    Returns a list of absolute, normalized directory paths.
    Exits with code 2 if any specified directory does not exist.
    """
    resolved = []
    for d in source_dirs:
        abs_path = os.path.normpath(os.path.join(repo_root, d))
        if not os.path.isdir(abs_path):
            print(
                f"ERROR: source directory does not exist: {d} "
                f"(resolved to {abs_path})",
                file=sys.stderr,
            )
            sys.exit(2)
        resolved.append(abs_path)
    return resolved


def infer_repo_root(compile_commands_path):
    """Infer the repository root from the compile_commands.json location.

    Convention: compile_commands.json is generated in a build/ subdirectory
    of the repo root (e.g., repo/build/compile_commands.json → repo root is repo/).

    Falls back to the directory containing compile_commands.json if the parent
    doesn't look like a repo root.
    """
    db_dir = os.path.dirname(os.path.abspath(compile_commands_path))
    parent = os.path.dirname(db_dir)

    # Heuristic: if parent contains common repo markers, use it
    repo_markers = [".git", "CMakeLists.txt", "Makefile", "README.md"]
    if any(os.path.exists(os.path.join(parent, m)) for m in repo_markers):
        return parent

    return db_dir
