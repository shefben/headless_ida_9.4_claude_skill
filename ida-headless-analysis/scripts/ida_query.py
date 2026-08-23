"""Token-bounded IDA query CLI.

All commands enter IDA through _ida_session.open_database(), which enforces:
    auto_analysis=True -> ida_auto.auto_wait() -> init_hexrays_plugin()

Exact literal string searches use raw byte scanning by default for speed on large databases.
"""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

from _ida_session import open_database, decompile_raw
from _common import parse_ea, safe_text, regex_filter, ensure_state

DEFAULT_LIMIT = 30
PSEUDOCODE_LIMIT = 180
DISASM_LIMIT = 80
MICROCODE_LIMIT = 120


def _metadata(db) -> dict[str, Any]:
    out: dict[str, Any] = {}
    meta = getattr(db, "metadata", None)
    for field in ("architecture", "bitness", "md5", "sha256", "file_size", "base_address"):
        value = None
        if meta is not None and hasattr(meta, field):
            value = getattr(meta, field)
        elif hasattr(db, field):
            value = getattr(db, field)
        if value is not None:
            out[field] = safe_text(value)
    out["database_path"] = safe_text(getattr(db, "path", ""))
    return out


def _function_name(db, ea: int) -> str:
    try:
        f = db.functions.get_at(ea)
        if f and hasattr(db.functions, "get_name"):
            name = db.functions.get_name(f)
            if name:
                return safe_text(name)
    except Exception:
        pass
    try:
        name = db.names.get_at(ea)
        if name:
            return safe_text(name)
    except Exception:
        pass
    try:
        import ida_name
        name = ida_name.get_name(ea)
        if name:
            return name
    except Exception:
        pass
    return f"sub_{ea:x}"


def _resolve_function(db, token: str) -> int:
    try:
        ea = parse_ea(token)
        f = db.functions.get_at(ea)
        if f:
            return int(f.start_ea)
    except (ValueError, TypeError):
        pass

    try:
        f = db.functions.get_by_name(token)
        if f:
            return int(f.start_ea)
    except Exception:
        pass

    try:
        import ida_name, ida_funcs
        ea = ida_name.get_name_ea(0, token)
        if ea != -1:
            f = ida_funcs.get_func(ea)
            if f:
                return int(f.start_ea)
    except Exception:
        pass
    raise ValueError(f"Could not resolve function/address: {token}")


def _entries(db, limit: int) -> dict[str, Any]:
    rows, total = [], 0
    for e in db.entries.get_all():
        total += 1
        if len(rows) < limit:
            rows.append({"ea": hex(int(e.address)), "name": safe_text(e.name)})
    return {"items": rows, "total": total, "truncated": total > len(rows)}


def _segments(db, limit: int) -> dict[str, Any]:
    rows, total = [], 0
    for seg in db.segments.get_all():
        total += 1
        if len(rows) < limit:
            start, end = int(seg.start_ea), int(seg.end_ea)
            try:
                name = safe_text(db.segments.get_name(seg))
            except Exception:
                name = ""
            rows.append({"name": name, "start": hex(start), "end": hex(end), "size": end - start})
    return {"items": rows, "total": total, "truncated": total > len(rows)}


def _imports(db, limit: int) -> dict[str, Any]:
    """IDA Domain 0.5 import enumeration, with SDK fallback only if required."""
    rows, total = [], 0
    imports_api = getattr(db, "imports", None)
    if imports_api is not None and hasattr(imports_api, "get_all_imports"):
        for imp in imports_api.get_all_imports():
            total += 1
            if len(rows) < limit:
                rows.append({
                    "module": safe_text(getattr(imp, "module_name", "")),
                    "ea": hex(int(getattr(imp, "address"))),
                    "name": safe_text(getattr(imp, "name", "")),
                    "ordinal": int(getattr(imp, "ordinal", 0)),
                })
        return {"api": "ida-domain", "items": rows, "total": total, "truncated": total > len(rows)}

    import ida_nalt
    for i in range(ida_nalt.get_import_module_qty()):
        module = ida_nalt.get_import_module_name(i) or f"module_{i}"
        def cb(ea, name, ordinal):
            nonlocal total
            total += 1
            if len(rows) < limit:
                rows.append({"module": module, "ea": hex(int(ea)), "name": name or "", "ordinal": int(ordinal)})
            return True
        ida_nalt.enum_import_names(i, cb)
    return {"api": "idapython-fallback", "items": rows, "total": total, "truncated": total > len(rows)}


def _strings_discovery(
    db,
    limit: int,
    pattern: str | None = None,
    contains: str | None = None,
) -> dict[str, Any]:
    """Regex/fuzzy/list discovery path. Exact literals should use _fast_string_search()."""
    rows, total_matching = [], 0
    for s in db.strings.get_all():
        text = safe_text(getattr(s, "contents", ""))
        if not regex_filter(text, pattern, contains):
            continue
        total_matching += 1
        if len(rows) < limit:
            rows.append({"ea": hex(int(s.address)), "value": text[:1000]})
    return {
        "mode": "ida-string-list",
        "items": rows,
        "total": total_matching,
        "truncated": total_matching > len(rows),
    }


def _encoded_patterns(text: str, encoding: str, nul: bool) -> list[tuple[str, bytes]]:
    patterns: list[tuple[str, bytes]] = []
    if encoding == "auto":
        # ASCII and UTF-8 are identical for pure ASCII, so avoid scanning twice.
        try:
            ascii_bytes = text.encode("ascii")
            patterns.append(("ascii", ascii_bytes + (b"\x00" if nul else b"")))
        except UnicodeEncodeError:
            utf8 = text.encode("utf-8")
            patterns.append(("utf8", utf8 + (b"\x00" if nul else b"")))
        utf16 = text.encode("utf-16le")
        patterns.append(("utf16le", utf16 + (b"\x00\x00" if nul else b"")))
    elif encoding == "ascii":
        raw = text.encode("ascii")
        patterns.append(("ascii", raw + (b"\x00" if nul else b"")))
    elif encoding == "utf8":
        raw = text.encode("utf-8")
        patterns.append(("utf8", raw + (b"\x00" if nul else b"")))
    elif encoding == "utf16le":
        raw = text.encode("utf-16le")
        patterns.append(("utf16le", raw + (b"\x00\x00" if nul else b"")))
    else:
        raise ValueError(encoding)
    return patterns


def _xref_context(hit_ea: int, max_xrefs: int = 12) -> list[dict[str, Any]]:
    import idautils, ida_funcs, ida_name

    out = []
    seen = set()
    for xref in idautils.XrefsTo(hit_ea, 0):
        frm = int(xref.frm)
        if frm in seen:
            continue
        seen.add(frm)
        f = ida_funcs.get_func(frm)
        func_ea = int(f.start_ea) if f else None
        out.append({
            "from": hex(frm),
            "function_ea": hex(func_ea) if func_ea is not None else None,
            "function": (ida_name.get_name(func_ea) or f"sub_{func_ea:x}") if func_ea is not None else None,
            "is_code": bool(getattr(xref, "iscode", False)),
        })
        if len(out) >= max_xrefs:
            break
    return out


def _fast_string_search(
    db,
    text: str,
    limit: int,
    encoding: str = "auto",
    nul: bool = False,
) -> dict[str, Any]:
    """Search literal string bytes directly instead of enumerating IDA's string list.

    Uses find_bytes_between() one hit at a time so the search remains bounded even if the pattern
    is common in a huge database. Each hit is annotated with segment and xref/function context.
    """
    patterns = _encoded_patterns(text, encoding, nul)
    hits: list[dict[str, Any]] = []
    seen: set[tuple[int, str]] = set()
    reached_budget = False

    for label, pattern in patterns:
        if not pattern:
            continue
        for seg in db.segments.get_all():
            seg_start, seg_end = int(seg.start_ea), int(seg.end_ea)
            try:
                seg_name = safe_text(db.segments.get_name(seg))
            except Exception:
                seg_name = ""
            cursor = seg_start
            while cursor < seg_end:
                found = db.bytes.find_bytes_between(pattern, cursor, seg_end)
                if found is None:
                    break
                found = int(found)
                key = (found, label)
                if key not in seen:
                    seen.add(key)
                    if len(hits) >= limit:
                        reached_budget = True
                        break
                    hits.append({
                        "ea": hex(found),
                        "encoding": label,
                        "segment": seg_name,
                        "bytes": pattern.hex(" "),
                        "xrefs": _xref_context(found),
                    })
                cursor = found + 1
            if reached_budget:
                break
        if reached_budget:
            break

    return {
        "mode": "byte-search",
        "query": text,
        "encodings": [name for name, _ in patterns],
        "nul_terminated": nul,
        "items": hits,
        "returned": len(hits),
        "truncated": reached_budget,
        "note": "Exact literal search scanned encoded bytes directly; IDA string-list enumeration was not used.",
    }


def _functions(db, limit: int, pattern: str | None = None) -> dict[str, Any]:
    rows, total = [], 0
    rx = re.compile(pattern, re.I) if pattern else None
    for f in db.functions.get_all():
        ea = int(f.start_ea)
        name = _function_name(db, ea)
        if rx and not rx.search(name):
            continue
        total += 1
        if len(rows) < limit:
            end = int(getattr(f, "end_ea", ea))
            rows.append({"ea": hex(ea), "name": name, "size": max(0, end - ea)})
    return {"items": rows, "total": total, "truncated": total > len(rows)}


def _callers(db, ea: int, limit: int) -> dict[str, Any]:
    f = db.functions.get_at(ea)
    if not f:
        return {"items": [], "total": 0, "truncated": False}
    try:
        funcs = db.functions.get_callers(f)
        total = len(funcs)
        rows = [
            {"ea": hex(int(x.start_ea)), "name": _function_name(db, int(x.start_ea))}
            for x in funcs[:limit]
        ]
        return {"items": rows, "total": total, "truncated": total > len(rows)}
    except Exception:
        import idautils, ida_funcs, ida_name
        rows, seen = [], set()
        for ref in idautils.CodeRefsTo(ea, False):
            caller = ida_funcs.get_func(ref)
            start = int(caller.start_ea) if caller else int(ref)
            if start in seen:
                continue
            seen.add(start)
            if len(rows) < limit:
                rows.append({
                    "ea": hex(start),
                    "name": ida_name.get_name(start) or f"sub_{start:x}",
                    "callsite": hex(int(ref)),
                })
        return {"items": rows, "total": len(seen), "truncated": len(seen) > len(rows)}


def _callees(db, ea: int, limit: int) -> dict[str, Any]:
    f = db.functions.get_at(ea)
    if not f:
        return {"items": [], "total": 0, "truncated": False}
    try:
        funcs = db.functions.get_callees(f)
        total = len(funcs)
        rows = [
            {"ea": hex(int(x.start_ea)), "name": _function_name(db, int(x.start_ea))}
            for x in funcs[:limit]
        ]
        return {"items": rows, "total": total, "truncated": total > len(rows)}
    except Exception:
        import idautils, ida_funcs, ida_name
        rows, seen = [], set()
        for head in idautils.Heads(int(f.start_ea), int(f.end_ea)):
            for ref in idautils.CodeRefsFrom(head, False):
                callee = ida_funcs.get_func(ref)
                if not callee:
                    continue
                target = int(callee.start_ea)
                if target == int(f.start_ea) or target in seen:
                    continue
                seen.add(target)
                if len(rows) < limit:
                    rows.append({
                        "ea": hex(target),
                        "name": ida_name.get_name(target) or f"sub_{target:x}",
                        "callsite": hex(int(head)),
                    })
        return {"items": rows, "total": len(seen), "truncated": len(seen) > len(rows)}


def _cfg(db, ea: int, limit: int) -> dict[str, Any]:
    f = db.functions.get_at(ea)
    if not f:
        raise ValueError(f"No function at 0x{ea:x}")
    blocks = []
    total = 0
    try:
        flow = db.functions.get_flowchart(f)
        iterable = flow
    except Exception:
        import ida_gdl
        iterable = ida_gdl.FlowChart(f)
    for block in iterable:
        total += 1
        if len(blocks) < limit:
            try:
                succ = [hex(int(x.start_ea)) for x in block.succs()]
                pred = [hex(int(x.start_ea)) for x in block.preds()]
            except Exception:
                succ, pred = [], []
            blocks.append({
                "start": hex(int(block.start_ea)),
                "end": hex(int(block.end_ea)),
                "pred": pred,
                "succ": succ,
            })
    return {"items": blocks, "total": total, "truncated": total > len(blocks)}


def _function_summary(db, ea: int, limit: int) -> dict[str, Any]:
    f = db.functions.get_at(ea)
    if not f:
        raise ValueError(f"No function at 0x{ea:x}")
    start, end = int(f.start_ea), int(getattr(f, "end_ea", f.start_ea))
    return {
        "ea": hex(start),
        "name": _function_name(db, start),
        "size": max(0, end - start),
        "callers": _callers(db, start, min(limit, 20)),
        "callees": _callees(db, start, min(limit, 20)),
        "cfg": _cfg(db, start, min(limit, 40)),
    }


def _pseudocode(db, ea: int, line_limit: int) -> dict[str, Any]:
    """Human-readable pseudocode plus compact strings newly visible to the decompiler."""
    lines = None
    recovered_strings = []
    pseudo = getattr(db, "pseudocode", None)
    if pseudo is not None and hasattr(pseudo, "decompile"):
        try:
            fn = pseudo.decompile(ea)
            if hasattr(fn, "to_text"):
                rendered = fn.to_text()
                if isinstance(rendered, (list, tuple)):
                    lines = [safe_text(x) for x in rendered]
                else:
                    lines = safe_text(rendered).splitlines()
            if hasattr(fn, "find_strings"):
                seen = set()
                for expr in fn.find_strings():
                    value = safe_text(getattr(expr, "string", ""))
                    key = (int(getattr(expr, "ea", 0)), value)
                    if key in seen:
                        continue
                    seen.add(key)
                    recovered_strings.append({"ea": hex(key[0]), "value": value[:500]})
                    if len(recovered_strings) >= 30:
                        break
        except Exception:
            lines = None
    if lines is None and pseudo is not None and hasattr(pseudo, "get_text"):
        try:
            lines = [safe_text(x) for x in pseudo.get_text(ea)]
        except Exception:
            lines = None
    if lines is None:
        lines = decompile_raw(ea).splitlines()
    return {
        "ea": hex(ea),
        "lines": lines[:line_limit],
        "line_count": len(lines),
        "truncated": len(lines) > line_limit,
        "decompiler_string_seeds": recovered_strings,
        "note": "Use ida_ctree.py for structured facts before requesting large pseudocode dumps.",
    }

def _disasm(db, ea: int, line_limit: int) -> dict[str, Any]:
    f = db.functions.get_at(ea)
    if not f:
        raise ValueError(f"No function at 0x{ea:x}")
    try:
        lines = [safe_text(x) for x in db.functions.get_disassembly(f)]
    except Exception:
        try:
            lines = [safe_text(x) for x in db.functions.get_disassembly(ea)]
        except Exception:
            import idautils, ida_lines
            lines = []
            for head in idautils.Heads(int(f.start_ea), int(f.end_ea)):
                rendered = ida_lines.generate_disasm_line(head, 0) or ""
                lines.append(f"0x{int(head):x}: {ida_lines.tag_remove(rendered)}")
    return {
        "ea": hex(ea),
        "lines": lines[:line_limit],
        "line_count": len(lines),
        "truncated": len(lines) > line_limit,
    }


def _micro_maturity(name: str):
    from ida_domain.microcode import MicroMaturity
    table = {
        "zero": MicroMaturity.ZERO, "generated": MicroMaturity.GENERATED,
        "preoptimized": MicroMaturity.PREOPTIMIZED, "locopt": MicroMaturity.LOCOPT,
        "calls": MicroMaturity.CALLS, "glbopt1": MicroMaturity.GLBOPT1,
        "glbopt2": MicroMaturity.GLBOPT2, "glbopt3": MicroMaturity.GLBOPT3,
        "lvars": MicroMaturity.LVARS,
    }
    return table[name]


def _microcode(db, ea: int, line_limit: int, match: str | None, maturity: str = "locopt") -> dict[str, Any]:
    """Text microcode fallback. Prefer ida_dataflow.py for structured evidence."""
    f = db.functions.get_at(ea)
    if not f:
        raise ValueError(f"No function at 0x{ea:x}")
    micro = getattr(db, "microcode", None)
    if micro is None or not hasattr(micro, "get_text"):
        raise RuntimeError("ida-domain microcode API unavailable; install ida-domain >=0.5.0")
    lines = [safe_text(x) for x in micro.get_text(f, _micro_maturity(maturity))]
    if match:
        rx = re.compile(match, re.I)
        lines = [line for line in lines if rx.search(line)]
    return {
        "ea": hex(ea), "maturity": maturity, "match": match,
        "lines": lines[:line_limit], "line_count": len(lines),
        "truncated": len(lines) > line_limit,
        "note": "Textual microcode is a fallback; prefer ida_dataflow.py structured output.",
    }

def run(args) -> dict[str, Any]:
    with open_database(args.binary) as db:
        metadata = _metadata(db)
        ensure_state(args.binary, metadata)

        if args.command == "metadata":
            return metadata
        if args.command == "triage":
            return {
                "metadata": metadata,
                "segments": _segments(db, min(args.limit, 30)),
                "imports": _imports(db, args.limit),
                "exports": _entries(db, args.limit),
                # Deliberately do not dump the global string list during baseline triage.
                "string_policy": "Use `string <literal>` for byte-backed exact search; use `strings` only for discovery.",
            }
        if args.command == "string":
            return _fast_string_search(db, args.text, args.limit, args.encoding, args.nul)
        if args.command == "strings":
            return _strings_discovery(db, args.limit, args.regex, args.contains)
        if args.command == "functions":
            return _functions(db, args.limit, args.regex)

        ea = _resolve_function(db, args.target)
        if args.command == "function":
            return _function_summary(db, ea, args.limit)
        if args.command == "callers":
            return _callers(db, ea, args.limit)
        if args.command == "callees":
            return _callees(db, ea, args.limit)
        if args.command == "cfg":
            return _cfg(db, ea, args.limit)
        if args.command == "pseudocode":
            return _pseudocode(db, ea, args.lines)
        if args.command == "disasm":
            return _disasm(db, ea, args.lines)
        if args.command == "microcode":
            return _microcode(db, ea, args.lines, args.match, args.maturity)
        raise ValueError(args.command)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("binary")
    p.add_argument("--limit", type=int, default=DEFAULT_LIMIT)
    p.add_argument("--save", help="save result JSON to this path and print a compact receipt")
    sub = p.add_subparsers(dest="command", required=True)

    sub.add_parser("metadata")
    sub.add_parser("triage")

    s = sub.add_parser("string", help="FAST exact literal search using encoded bytes")
    s.add_argument("text")
    s.add_argument("--encoding", choices=("auto", "ascii", "utf8", "utf16le"), default="auto")
    s.add_argument("--nul", action="store_true", help="include expected NUL terminator in byte pattern")

    s = sub.add_parser("strings", help="IDA string-list discovery for regex/fuzzy searches")
    s.add_argument("--contains")
    s.add_argument("--regex")

    s = sub.add_parser("functions")
    s.add_argument("--regex")

    for name in ("function", "callers", "callees", "cfg"):
        s = sub.add_parser(name)
        s.add_argument("target")

    s = sub.add_parser("pseudocode")
    s.add_argument("target")
    s.add_argument("--lines", type=int, default=PSEUDOCODE_LIMIT)

    s = sub.add_parser("disasm")
    s.add_argument("target")
    s.add_argument("--lines", type=int, default=DISASM_LIMIT)

    s = sub.add_parser("microcode")
    s.add_argument("target")
    s.add_argument("--match")
    s.add_argument("--lines", type=int, default=MICROCODE_LIMIT)
    s.add_argument("--maturity", choices=("zero", "generated", "preoptimized", "locopt", "calls", "glbopt1", "glbopt2", "glbopt3", "lvars"), default="locopt")

    return p


def main() -> int:
    args = build_parser().parse_args()
    if args.limit < 1:
        raise SystemExit("--limit must be >= 1")
    result = run(args)
    text = json.dumps(result, indent=2, ensure_ascii=False, default=str)
    if args.save:
        path = Path(args.save)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text + "\n", encoding="utf-8")
        print(json.dumps({
            "saved": str(path),
            "command": args.command,
            "truncated": bool(result.get("truncated", False)) if isinstance(result, dict) else False,
        }, ensure_ascii=False))
    else:
        print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
