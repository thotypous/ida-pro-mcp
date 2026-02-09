"""Re-export decompiled C files from IDA Pro.

Parses existing .c files in the rev/ directory to identify which structs,
enums, typedefs and functions they contain, then re-exports those items
fresh from IDA's current state. This is a single-step operation for the LLM.
"""

import os
import re
from typing import Annotated

from .rpc import tool, unsafe
from .sync import idasync

# ============================================================================
# C File Parser
# ============================================================================

# Matches: struct Name {, typedef struct Name {
_RE_STRUCT = re.compile(
    r"^\s*(?:typedef\s+)?struct\s+(\w+)\s*\{", re.MULTILINE
)
# Matches: enum Name {, typedef enum Name {
_RE_ENUM = re.compile(
    r"^\s*(?:typedef\s+)?enum\s+(\w+)\s*\{", re.MULTILINE
)
# Matches simple typedefs: typedef int16_t __int16;
# (but NOT typedef struct/enum, and NOT function pointers)
_RE_TYPEDEF_SIMPLE = re.compile(
    r"^\s*typedef\s+(?!struct\b|enum\b)\w[\w\s]*?(\w+)\s*;", re.MULTILINE
)
# Matches function pointer typedefs: typedef int (__cdecl *dp_process_t)(...);
_RE_TYPEDEF_FUNCPTR = re.compile(
    r"^\s*typedef\s+.*?\(\s*(?:__\w+\s+)?\*\s*(\w+)\s*\)\s*\(.*?\)\s*;",
    re.MULTILINE,
)

# Matches function separators:
#   //----- (0x8005A20) --------------------------------------------------------
#   //----- (0x8005400) b103_create --------------------------------------------------------
#   //----- (08000060) --------------------------------------------------------
_RE_SEPARATOR = re.compile(
    r"^//-----\s*\((?:0x)?([0-9a-fA-F]+)\)\s*(\w+)?\s*-+",
    re.MULTILINE,
)

# Matches function definition at column 0 (handles struct return types, __cdecl, etc.)
_RE_FUNC_DEF = re.compile(
    r"^[A-Za-z_][\w\s\*]*\b(\w+)\s*\(", re.MULTILINE
)

# Matches #include lines
_RE_INCLUDE = re.compile(r"^\s*#include\s+[<\"].*?[>\"]", re.MULTILINE)

# Matches extern declarations
_RE_EXTERN = re.compile(r"^\s*extern\s+.*?;\s*$", re.MULTILINE)

# Matches forward declarations: struct Name;
_RE_FORWARD_DECL = re.compile(r"^\s*struct\s+\w+\s*;\s*$", re.MULTILINE)

# C keywords that should not be treated as function names
_KEYWORDS = frozenset({
    "if", "while", "for", "switch", "return", "struct", "enum",
    "union", "typedef", "else", "do", "goto", "case", "default",
    "break", "continue", "sizeof", "volatile", "register", "extern",
})


def _parse_c_file(content: str) -> dict:
    """Parse a .c file and extract type names and function info.

    Returns dict with:
        includes: list of #include lines
        externs: list of extern declaration lines
        forward_decls: list of forward declaration lines
        typedefs: list of typedef names (non-struct/enum)
        type_names: list of struct/enum names (in order of appearance)
        functions: list of (address_int_or_None, name_str) tuples
        preamble_lines: list of comment/header lines before first declaration
    """
    result = {
        "includes": [],
        "externs": [],
        "forward_decls": [],
        "typedefs": [],
        "type_names": [],
        "functions": [],
        "preamble_lines": [],
    }

    # Extract includes
    result["includes"] = [m.group(0).strip() for m in _RE_INCLUDE.finditer(content)]

    # Extract extern declarations
    result["externs"] = [m.group(0).strip() for m in _RE_EXTERN.finditer(content)]

    # Extract forward declarations
    result["forward_decls"] = [
        m.group(0).strip() for m in _RE_FORWARD_DECL.finditer(content)
    ]

    # Extract type names (structs and enums) in order of appearance
    seen_types = set()
    type_entries = []  # (position, name) for ordering

    for m in _RE_STRUCT.finditer(content):
        name = m.group(1)
        if name not in seen_types:
            seen_types.add(name)
            type_entries.append((m.start(), name))

    for m in _RE_ENUM.finditer(content):
        name = m.group(1)
        if name not in seen_types:
            seen_types.add(name)
            type_entries.append((m.start(), name))

    # Sort by position to preserve file order
    type_entries.sort(key=lambda x: x[0])
    result["type_names"] = [name for _, name in type_entries]

    # Extract non-struct/enum typedefs (simple + function pointer)
    typedef_entries = []
    for m in _RE_TYPEDEF_SIMPLE.finditer(content):
        name = m.group(1)
        if name not in seen_types:
            typedef_entries.append((m.start(), name))
            seen_types.add(name)

    for m in _RE_TYPEDEF_FUNCPTR.finditer(content):
        name = m.group(1)
        if name not in seen_types:
            typedef_entries.append((m.start(), name))
            seen_types.add(name)

    typedef_entries.sort(key=lambda x: x[0])
    result["typedefs"] = [name for _, name in typedef_entries]

    # Extract functions from separators (primary method)
    for m in _RE_SEPARATOR.finditer(content):
        addr_str = m.group(1)
        func_name_in_sep = m.group(2)  # may be None
        addr_int = int(addr_str, 16)

        func_name = func_name_in_sep
        if not func_name:
            # Look for function definition in lines after separator
            after_sep = content[m.end() :]
            lines_after = after_sep.lstrip("\n").split("\n", 5)
            for line in lines_after:
                line_stripped = line.strip()
                if (
                    not line_stripped
                    or line_stripped.startswith("//")
                    or line_stripped.startswith("/*")
                ):
                    continue
                fm = _RE_FUNC_DEF.match(line_stripped)
                if fm and fm.group(1) not in _KEYWORDS:
                    func_name = fm.group(1)
                break

        result["functions"].append((addr_int, func_name))

    # Fallback: for files without separators, find functions by looking
    # for function definitions after the type/header block
    if not result["functions"]:
        # Find where the header/type block ends
        last_header_end = 0

        # After closing brace of type definitions (single line only)
        for m in re.finditer(r"^\}[^;\n]*;", content, re.MULTILINE):
            last_header_end = max(last_header_end, m.end())

        # After extern/forward/include/typedef lines
        for pattern in [
            _RE_EXTERN,
            _RE_FORWARD_DECL,
            _RE_INCLUDE,
            _RE_TYPEDEF_SIMPLE,
            _RE_TYPEDEF_FUNCPTR,
        ]:
            for m in pattern.finditer(content):
                last_header_end = max(last_header_end, m.end())

        # Skip comment lines adjacent to header
        for m in re.finditer(r"^//.*$", content, re.MULTILINE):
            if m.start() <= last_header_end + 2:
                last_header_end = max(last_header_end, m.end())

        # Find function definitions in remaining content
        remaining = content[last_header_end:]
        for m in _RE_FUNC_DEF.finditer(remaining):
            func_name = m.group(1)
            if func_name in _KEYWORDS:
                continue
            # Verify it's at column 0 in original content
            abs_pos = last_header_end + m.start()
            if abs_pos > 0 and content[abs_pos - 1] != "\n":
                continue
            result["functions"].append((None, func_name))

    # Extract preamble: comments before first declaration
    first_significant = len(content)
    for regex in [
        _RE_INCLUDE,
        _RE_STRUCT,
        _RE_ENUM,
        _RE_SEPARATOR,
        _RE_TYPEDEF_SIMPLE,
        _RE_TYPEDEF_FUNCPTR,
        _RE_FORWARD_DECL,
        _RE_EXTERN,
    ]:
        for m in regex.finditer(content):
            first_significant = min(first_significant, m.start())
            break  # only first match

    preamble = content[:first_significant].strip()
    # Remove includes from preamble (tracked separately)
    for inc in result["includes"]:
        preamble = preamble.replace(inc, "")
    preamble = preamble.strip()

    if preamble:
        result["preamble_lines"] = [
            line for line in preamble.split("\n") if line.strip()
        ]

    return result


# ============================================================================
# IDA Export Logic
# ============================================================================

_EXPORT_SCRIPT = r'''
import ida_hexrays
import ida_funcs
import ida_typeinf
import ida_lines
import idc
import os

def _decompile_to_str(ea):
    """Decompile function at ea and return pseudocode string."""
    try:
        # Clear the cached decompilation to force fresh decompilation
        # This ensures prototype changes, struct modifications, etc. are applied
        ida_hexrays.mark_cfunc_dirty(ea)
        
        cfunc = ida_hexrays.decompile(ea)
        if not cfunc:
            return None
        sv = cfunc.get_pseudocode()
        lines = []
        for sl in sv:
            text = ida_lines.tag_remove(sl.line)
            lines.append(text)
        return "\n".join(lines)
    except Exception as e:
        return f"// Decompilation failed: {e}"


def _export_type_decl(name):
    """Export a struct/enum type declaration as C text."""
    til = ida_typeinf.get_idati()
    tif = ida_typeinf.tinfo_t()
    if not tif.get_named_type(til, name):
        return f"// Type not found in IDA: {name}"

    ordinal = tif.get_ordinal()
    if ordinal > 0:
        decl = idc.print_decls(str(ordinal), 0)
        if decl:
            lines = decl.split('\n')
            filtered = [l for l in lines if not l.strip().startswith('/*')]
            while filtered and not filtered[0].strip():
                filtered.pop(0)
            while filtered and not filtered[-1].strip():
                filtered.pop()
            return '\n'.join(filtered)

    return f"// Type '{name}' exists but could not be exported"


_BUILTIN_TYPES = frozenset({
    "__int8", "__int16", "__int32", "__int64",
    "_BYTE", "_WORD", "_DWORD", "_QWORD", "_OWORD",
    "_BOOL1", "_BOOL2", "_BOOL4",
    "_UNKNOWN",
})

def _export_typedef(name):
    """Export a typedef declaration."""
    if name.lstrip("_") == "" or name in _BUILTIN_TYPES:
        return None  # Built-in IDA type, skip
    til = ida_typeinf.get_idati()
    tif = ida_typeinf.tinfo_t()
    if not tif.get_named_type(til, name):
        return None  # Silently skip types not in IDA (likely built-in)

    ordinal = tif.get_ordinal()
    if ordinal > 0:
        decl = idc.print_decls(str(ordinal), 0)
        if decl:
            lines = decl.split('\n')
            filtered = [l for l in lines if not l.strip().startswith('/*')]
            while filtered and not filtered[0].strip():
                filtered.pop(0)
            while filtered and not filtered[-1].strip():
                filtered.pop()
            return '\n'.join(filtered)

    return f"// Typedef '{name}' could not be exported"


def _resolve_func_addr(name):
    """Resolve a function name to its address."""
    ea = idc.get_name_ea_simple(name)
    if ea == idc.BADADDR:
        return None
    return ea


def resync_file(filepath, includes, externs, forward_decls, preamble_lines,
                type_names, typedefs, functions):
    """Re-export a C file with fresh IDA data."""
    parts = []

    # 1. Preamble comments
    if preamble_lines:
        for line in preamble_lines:
            parts.append(line)
        parts.append("")

    # 2. Includes
    if includes:
        for inc in includes:
            parts.append(inc)
        parts.append("")

    # 3. Extern declarations (preserved as-is)
    if externs:
        for ext in externs:
            parts.append(ext)
        parts.append("")

    # 4. Forward declarations (preserved as-is)
    if forward_decls:
        for fwd in forward_decls:
            parts.append(fwd)
        parts.append("")

    # 5. Type declarations (fresh from IDA)
    for name in type_names:
        decl = _export_type_decl(name)
        parts.append(decl)
        parts.append("")

    # 6. Typedefs (fresh from IDA)
    for name in typedefs:
        decl = _export_typedef(name)
        if decl is not None:
            parts.append(decl)
            parts.append("")

    # 7. Functions (fresh decompilation)
    for func_info in functions:
        addr = func_info[0]
        name = func_info[1]

        if addr is None and name:
            addr = _resolve_func_addr(name)

        if addr is None:
            parts.append(f"// Function not found: {name}")
            parts.append("")
            continue

        func = ida_funcs.get_func(addr)
        if not func:
            parts.append(f"// No function at {hex(addr)}")
            parts.append("")
            continue

        addr_hex = f"0x{func.start_ea:x}"
        func_name = idc.get_func_name(func.start_ea) or ""
        prefix = f"//----- ({addr_hex}) {func_name} "
        dashes = max(10, 88 - len(prefix))
        parts.append(prefix + "-" * dashes)

        code = _decompile_to_str(func.start_ea)
        if code:
            parts.append(code)
        else:
            parts.append(f"// Decompilation failed for {addr_hex}")
        parts.append("")
        parts.append("")

    # Write file
    output = "\n".join(parts)
    while "\n\n\n\n" in output:
        output = output.replace("\n\n\n\n", "\n\n\n")
    if not output.endswith("\n"):
        output += "\n"

    os.makedirs(os.path.dirname(filepath) or ".", exist_ok=True)
    with open(filepath, "w") as f:
        f.write(output)

    return f"Wrote {len(output)} bytes to {filepath}"

result = resync_file(
    FILEPATH, INCLUDES, EXTERNS, FORWARD_DECLS, PREAMBLE_LINES,
    TYPE_NAMES, TYPEDEFS, FUNCTIONS
)
print(result)
'''


# ============================================================================
# MCP Tool
# ============================================================================


@tool
@idasync
@unsafe
def resync_file(
    files: Annotated[
        list[str] | str,
        "File path(s) to re-export. Each file is parsed to identify its "
        "structs, enums, typedefs and functions, then re-exported fresh from IDA. "
        "Paths can be absolute or relative to the IDA database directory.",
    ],
    extra_types: Annotated[
        list[str] | str | None,
        "Optional type name(s) to add to the file. Use this when you declared "
        "a new struct/enum in IDA (via declare_type) and want it included in "
        "the file without editing the .c file directly. Names are appended "
        "after existing types.",
    ] = None,
) -> list[dict]:
    """Re-export decompiled C files from IDA.

Parses each .c file to find which structs/enums/typedefs and functions
it contains, then re-exports all of them fresh from IDA's current
decompiler output. The file is overwritten in place.

Use this after making changes in IDA (renaming variables, setting types,
adding comments) to update the corresponding source files in rev/.

Pass extra_types to inject new struct/enum definitions that don't yet
exist in the file (e.g. after declare_type in the same session).
"""
    import io
    import sys

    files_list = (
        files
        if isinstance(files, list)
        else [f.strip() for f in files.split(",") if f.strip()]
    )
    results = []

    for filepath in files_list:
        try:
            # Resolve relative paths against IDA database directory
            if not os.path.isabs(filepath):
                import ida_loader

                db_path = ida_loader.get_path(ida_loader.PATH_TYPE_IDB)
                if db_path:
                    db_dir = os.path.dirname(db_path)
                    for base in [db_dir, os.path.dirname(db_dir)]:
                        candidate = os.path.join(base, filepath)
                        if os.path.exists(candidate):
                            filepath = candidate
                            break

            if not os.path.exists(filepath):
                results.append(
                    {"file": filepath, "error": f"File not found: {filepath}"}
                )
                continue

            # Read and parse existing file
            with open(filepath, "r") as f:
                content = f.read()

            parsed = _parse_c_file(content)

            # Merge extra_types into parsed type_names (avoid duplicates)
            if extra_types:
                et = (
                    extra_types
                    if isinstance(extra_types, list)
                    else [t.strip() for t in extra_types.split(",") if t.strip()]
                )
                existing = set(parsed["type_names"] + parsed["typedefs"])
                for t in et:
                    if t not in existing:
                        parsed["type_names"].append(t)
                        existing.add(t)

            functions_list = [[addr, name] for addr, name in parsed["functions"]]

            # Execute the export script in IDA context
            stdout_capture = io.StringIO()
            stderr_capture = io.StringIO()
            old_stdout = sys.stdout
            old_stderr = sys.stderr

            try:
                sys.stdout = stdout_capture
                sys.stderr = stderr_capture

                exec_globals = {
                    "__builtins__": __builtins__,
                    "FILEPATH": filepath,
                    "INCLUDES": parsed["includes"],
                    "EXTERNS": parsed["externs"],
                    "FORWARD_DECLS": parsed["forward_decls"],
                    "PREAMBLE_LINES": parsed["preamble_lines"],
                    "TYPE_NAMES": parsed["type_names"],
                    "TYPEDEFS": parsed["typedefs"],
                    "FUNCTIONS": functions_list,
                }

                exec(_EXPORT_SCRIPT, exec_globals)
            finally:
                sys.stdout = old_stdout
                sys.stderr = old_stderr

            stdout_text = stdout_capture.getvalue().strip()
            stderr_text = stderr_capture.getvalue().strip()

            result_entry = {
                "file": filepath,
                "types_exported": parsed["type_names"] + parsed["typedefs"],
                "functions_exported": [
                    {"addr": hex(a) if a else None, "name": n}
                    for a, n in parsed["functions"]
                ],
                "result": stdout_text,
            }
            if stderr_text:
                result_entry["warnings"] = stderr_text

            results.append(result_entry)

        except Exception as e:
            import traceback

            results.append(
                {
                    "file": filepath,
                    "error": str(e),
                    "traceback": traceback.format_exc(),
                }
            )

    return results
