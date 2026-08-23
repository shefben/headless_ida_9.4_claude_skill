"""Find bounded call-reference paths between two functions/imports (Pathfinder-style headless helper).

This operates on static call/code references and optionally data references. A returned path is not
proof that runtime control flow can satisfy all conditions along that path.
"""
from __future__ import annotations

import argparse
import json
import re
from collections import deque

from _ida_session import open_database
from _common import ensure_state, safe_text
import ida_query


def resolve_endpoint(db, token: str) -> int:
    try:
        return ida_query._resolve_function(db, token)
    except Exception:
        pass
    imp_api = getattr(db, "imports", None)
    if imp_api is not None:
        try:
            imp = imp_api.get_import_by_name(token)
            if imp:
                return int(imp.address)
        except Exception:
            # Allow unqualified import names by bounded scan.
            try:
                low = token.lower()
                for imp in imp_api.get_all_imports():
                    if safe_text(getattr(imp, "name", "")).lower() == low:
                        return int(imp.address)
            except Exception:
                pass
    try:
        import ida_name
        ea = int(ida_name.get_name_ea(0, token))
        if ea >= 0:
            return ea
    except Exception:
        pass
    raise ValueError(f"Could not resolve endpoint: {token}")


def label(ea: int) -> str:
    try:
        import ida_name
        return ida_name.get_name(ea) or f"0x{ea:x}"
    except Exception:
        return f"0x{ea:x}"


def node_for_target(target: int) -> int:
    try:
        import ida_funcs
        f = ida_funcs.get_func(target)
        return int(f.start_ea) if f else int(target)
    except Exception:
        return int(target)


def successors(ea: int, include_data: bool = False):
    import idautils, ida_funcs
    f = ida_funcs.get_func(ea)
    if not f:
        return []
    out = set()
    for head in idautils.Heads(int(f.start_ea), int(f.end_ea)):
        for ref in idautils.CodeRefsFrom(head, False):
            out.add(node_for_target(int(ref)))
        if include_data:
            for ref in idautils.DataRefsFrom(head):
                out.add(node_for_target(int(ref)))
    out.discard(int(f.start_ea))
    return sorted(out)


def find_paths(source: int, target: int, *, max_depth: int, max_paths: int,
               max_nodes: int, exclude_rx=None, include_data=False, shortest_only=False):
    q = deque([[source]])
    paths = []
    best_depth = None
    expanded = 0
    seen_depth = {source: 0}
    while q and len(paths) < max_paths and expanded < max_nodes:
        path = q.popleft()
        cur = path[-1]
        depth = len(path) - 1
        if best_depth is not None and shortest_only and depth >= best_depth:
            continue
        if depth >= max_depth:
            continue
        for nxt in successors(cur, include_data=include_data):
            if nxt in path:
                continue
            if exclude_rx and exclude_rx.search(label(nxt)) and nxt != target:
                continue
            nd = depth + 1
            prev = seen_depth.get(nxt)
            if prev is not None and prev < nd and nxt != target:
                continue
            seen_depth[nxt] = nd
            expanded += 1
            np = path + [nxt]
            if nxt == target:
                if best_depth is None:
                    best_depth = nd
                if not shortest_only or nd == best_depth:
                    paths.append(np)
                continue
            if best_depth is None or not shortest_only or nd < best_depth:
                q.append(np)
    return paths, expanded, expanded >= max_nodes


def path_payload(paths):
    return [[{"ea": hex(ea), "name": label(ea)} for ea in p] for p in paths]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("binary")
    ap.add_argument("source")
    ap.add_argument("target")
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument("--shortest", action="store_true", default=True)
    mode.add_argument("--all-paths", action="store_true")
    ap.add_argument("--max-depth", type=int, default=12)
    ap.add_argument("--max-paths", type=int, default=8)
    ap.add_argument("--max-nodes", type=int, default=5000)
    ap.add_argument("--exclude-regex")
    ap.add_argument("--include-data-xrefs", action="store_true")
    args = ap.parse_args()

    with open_database(args.binary) as db:
        root = ensure_state(args.binary, ida_query._metadata(db))
        source = resolve_endpoint(db, args.source)
        target = resolve_endpoint(db, args.target)
        rx = re.compile(args.exclude_regex, re.I) if args.exclude_regex else None
        paths, expanded, capped = find_paths(
            source, target, max_depth=args.max_depth, max_paths=args.max_paths,
            max_nodes=args.max_nodes, exclude_rx=rx, include_data=args.include_data_xrefs,
            shortest_only=not args.all_paths,
        )
        payload = {
            "source": {"ea": hex(source), "name": label(source)},
            "target": {"ea": hex(target), "name": label(target)},
            "paths": path_payload(paths), "path_count": len(paths),
            "expanded_nodes": expanded, "search_capped": capped,
            "max_depth": args.max_depth, "include_data_xrefs": args.include_data_xrefs,
            "warning": "Static reference path only; verify conditions/data flow before claiming runtime reachability.",
        }
        out = root / "queries" / f"path_{source:x}_{target:x}.json"
        out.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        print(json.dumps({"saved": str(out), "paths": len(paths), "expanded_nodes": expanded,
                          "search_capped": capped, "shortest_hops": (len(paths[0])-1 if paths else None)}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
