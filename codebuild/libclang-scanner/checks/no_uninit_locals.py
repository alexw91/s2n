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
no_uninit_locals — Every local variable declaration must have an initializer.

Detection uses child-cursor inspection: a VAR_DECL with an initializer will
have an expression child (INIT_LIST_EXPR, INTEGER_LITERAL, CALL_EXPR, etc.).
A VAR_DECL without an initializer will have no expression children.

This approach works uniformly for direct declarations and macro-expanded
declarations (e.g., DEFER_CLEANUP), with no name-based heuristics or
token inspection.

Fix suggestions:
  Structs/arrays: = { 0 }
  Scalars (int, uint8_t, etc.): = 0
  Pointers: = NULL
  Enums: = FIRST_VALUE
"""
import os

from clang.cindex import CursorKind

from utils import is_file_in_source_dirs

CHECK_ID = "no-uninit-locals"


def _has_expression_child(cursor):
    """Return True if the VAR_DECL cursor has a child that is an expression.

    An expression child indicates the variable has an initializer. This works
    through macro expansion because the AST is post-preprocessor.
    """
    for child in cursor.get_children():
        if child.kind.is_expression():
            return True
    return False


def check(cursor, source_file, source_dirs, findings):
    """Walk the AST and flag local variables without initializers.

    Args:
        cursor: clang.cindex.Cursor — the translation unit's root cursor
        source_file: str — absolute path to the file being parsed
        source_dirs: list[str] — absolute paths of directories in scope
        findings: list — append finding dicts here
    """
    seen = set()
    _walk(cursor, source_dirs, findings, seen)


def _walk(cursor, source_dirs, findings, seen):
    """Recursive AST walker."""
    if cursor.kind == CursorKind.VAR_DECL:
        _check_var_decl(cursor, source_dirs, findings, seen)

    for child in cursor.get_children():
        _walk(child, source_dirs, findings, seen)


def _check_var_decl(cursor, source_dirs, findings, seen):
    """Check a single VAR_DECL for missing initializer."""
    loc = cursor.location
    if not loc.file:
        return

    filepath = loc.file.name

    # Only report findings for files under the scanned source directories
    if not is_file_in_source_dirs(filepath, source_dirs):
        return

    # Deduplicate: same location can be visited via different translation units
    key = (filepath, loc.line, loc.column)
    if key in seen:
        return
    seen.add(key)

    # Must be a local variable (semantic parent is a function)
    parent = cursor.semantic_parent
    if not parent or parent.kind != CursorKind.FUNCTION_DECL:
        return

    # Check for initializer via child-cursor inspection
    if _has_expression_child(cursor):
        return

    # This variable has no initializer — report it
    rel_path = os.path.relpath(filepath, os.path.commonpath(source_dirs))
    type_spelling = cursor.type.spelling

    findings.append({
        "file": filepath,
        "line": loc.line,
        "column": loc.column,
        "variable": cursor.spelling,
        "type": type_spelling,
        "function": parent.spelling,
        "check_id": CHECK_ID,
        "message": (
            f"Uninitialized local variable '{cursor.spelling}' "
            f"(type: {type_spelling}) in {parent.spelling}(). "
            f"Initialize at declaration site."
        ),
    })
