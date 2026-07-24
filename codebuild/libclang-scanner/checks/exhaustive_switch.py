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
exhaustive_switch — Every switch on a non-enum type must have a `default:` case.

Clang's `-Wswitch` enforces exhaustiveness for enum-typed switches at compile
time (with -Werror, a missing enum value is a build failure). But for switches
on int, uint8_t, or other non-enum types, -Wswitch provides no protection.
GCC has `-Wswitch-default` but Clang does not implement it.

This check fills that gap: any SWITCH_STMT on a non-enum type without a
DEFAULT_STMT child is flagged. Enum-typed switches are skipped because
-Wswitch -Werror already enforces compile-time exhaustiveness — adding a
default to those would actually *disable* that compiler check.

The rationale: a switch on int/uint8_t without a default case is a latent bug
if a new value is introduced that doesn't match any existing case. The silent
TLS 1.3 record drop vulnerability (penpal-12) had exactly this root cause: a
uint8_t wire value fell through a switch with no default handler.
"""
import os

from clang.cindex import CursorKind

from utils import is_file_in_source_dirs

CHECK_ID = "exhaustive-switch"


def _has_default_case(switch_cursor):
    """Return True if the switch statement contains a DEFAULT_STMT anywhere in its body.

    DEFAULT_STMT can be nested inside CASE_STMT children (because case labels
    are siblings in the AST, with default: being just another label). We need
    to search the entire subtree of the switch's compound statement.
    """
    for child in switch_cursor.get_children():
        if _find_default(child):
            return True
    return False


def _find_default(cursor):
    """Recursively search for a DEFAULT_STMT in the cursor subtree.

    Stops at nested SWITCH_STMT boundaries to avoid matching a default: in an
    inner switch as belonging to the outer switch.
    """
    if cursor.kind == CursorKind.DEFAULT_STMT:
        return True
    # Do not descend into nested switches — their defaults are their own
    if cursor.kind == CursorKind.SWITCH_STMT:
        return False
    for child in cursor.get_children():
        if _find_default(child):
            return True
    return False


def check(cursor, source_file, source_dirs, findings):
    """Walk the AST and flag switch statements without a default case.

    Args:
        cursor: clang.cindex.Cursor — the translation unit's root cursor
        source_file: str — absolute path to the file being parsed
        source_dirs: list[str] — absolute paths of directories in scope
        findings: list — append finding dicts here
    """
    seen = set()
    _walk(cursor, source_dirs, findings, seen, enclosing_function=None)


def _walk(cursor, source_dirs, findings, seen, enclosing_function):
    """Recursive AST walker that tracks the enclosing function."""
    # Track enclosing function
    if cursor.kind == CursorKind.FUNCTION_DECL:
        enclosing_function = cursor.spelling

    if cursor.kind == CursorKind.SWITCH_STMT:
        _check_switch(cursor, source_dirs, findings, seen, enclosing_function)

    for child in cursor.get_children():
        _walk(child, source_dirs, findings, seen, enclosing_function)


def _check_switch(cursor, source_dirs, findings, seen, enclosing_function):
    """Check a single SWITCH_STMT for missing default case.

    Only flags switches on non-enum types (int, uint8_t, etc.) because
    enum-typed switches are already protected by -Wswitch -Werror at compile
    time, which forces a build failure when a new enum value is unhandled.
    """
    loc = cursor.location
    if not loc.file:
        return

    filepath = loc.file.name

    # Only report findings for files under the scanned source directories
    if not is_file_in_source_dirs(filepath, source_dirs):
        return

    # Deduplicate
    key = (filepath, loc.line, loc.column)
    if key in seen:
        return
    seen.add(key)

    # Check for default case
    if _has_default_case(cursor):
        return

    # Get the switch condition's type. The first child of SWITCH_STMT is
    # the condition expression. Check if its type is an enum.
    if _condition_is_enum(cursor):
        return

    function_name = enclosing_function or "<file-scope>"

    findings.append({
        "file": filepath,
        "line": loc.line,
        "column": loc.column,
        "variable": "switch",
        "type": "switch statement",
        "function": function_name,
        "check_id": CHECK_ID,
        "message": (
            f"Switch on non-enum type without default case "
            f"in {function_name}(). "
            f"Add a default: case to handle unexpected values."
        ),
    })


def _condition_is_enum(switch_cursor):
    """Return True if the switch condition expression has an enum type.

    The first child of a SWITCH_STMT is the condition expression. In C, enum
    values are implicitly promoted to int/unsigned int for the switch, so the
    top-level expression type is often 'unsigned int' even for enum variables.
    We look through implicit casts (UNEXPOSED_EXPR children) to find the
    underlying declared type before promotion.

    If any type in the expression chain (before or after promotion) is an enum,
    -Wswitch provides compile-time exhaustiveness checking, so we skip it.
    """
    for child in switch_cursor.get_children():
        # The first child is the condition expression
        if _type_chain_contains_enum(child):
            return True
        # Only check the first child (the condition)
        break
    return False


def _type_chain_contains_enum(cursor):
    """Recursively check if cursor or its children have an enum type.

    Walks down through implicit casts (UNEXPOSED_EXPR) to find the
    pre-promotion type of the switch condition.
    """
    # Check this node's type
    if cursor.type and cursor.type.kind.name in ("ENUM", "ELABORATED"):
        # ELABORATED might be a typedef to enum — check canonical
        canonical = cursor.type.get_canonical()
        if canonical.kind.name == "ENUM":
            return True
        # Also check spelling as fallback
        if canonical.spelling.startswith("enum "):
            return True
        # For ELABORATED: resolve through the typedef declaration
        decl = cursor.type.get_declaration()
        if decl and decl.kind == CursorKind.ENUM_DECL:
            return True

    # Walk into children (implicit casts, paren exprs).
    # Note: libclang's Python bindings represent all implicit casts as
    # UNEXPOSED_EXPR. If a future libclang version exposes explicit cast kinds
    # (e.g., IMPLICIT_CAST_EXPR), this list may need updating.
    for child in cursor.get_children():
        if child.kind in (CursorKind.UNEXPOSED_EXPR, CursorKind.PAREN_EXPR,
                          CursorKind.DECL_REF_EXPR, CursorKind.MEMBER_REF_EXPR):
            if _type_chain_contains_enum(child):
                return True

    return False
