"""Build a bounded bidirectional call graph around one function."""
from __future__ import annotations

import argparse
import json
from collections import deque

from _ida_session import open_database
from _common import ensure_state
import ida_query


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("binary")
    ap.add_argument("target")
    ap.add_argument("--depth", type=int, default=2)
    ap.add_argument("--max-nodes", type=int, default=80)
    ap.add_argument("--direction", choices=("both", "callers", "callees"), default="both")
    args = ap.parse_args()

    if not 0 <= args.depth <= 8:
        raise SystemExit("--depth must be between 0 and 8")
    if args.max_nodes < 1:
        raise SystemExit("--max-nodes must be >= 1")

    with open_database(args.binary) as db:
        root = ensure_state(args.binary, ida_query._metadata(db))
        seed = ida_query._resolve_function(db, args.target)
        q = deque([(seed, 0)])
        seen = {seed}
        nodes, edges = {}, []
        truncated = False

        while q:
            ea, depth = q.popleft()
            nodes[ea] = {"ea": hex(ea), "name": ida_query._function_name(db, ea), "depth": depth}
            if depth >= args.depth:
                continue

            neighbors = []
            if args.direction in ("both", "callers"):
                for x in ida_query._callers(db, ea, args.max_nodes)["items"]:
                    neighbors.append(("caller", int(x["ea"], 16)))
            if args.direction in ("both", "callees"):
                for x in ida_query._callees(db, ea, args.max_nodes)["items"]:
                    neighbors.append(("callee", int(x["ea"], 16)))

            for kind, other in neighbors:
                edges.append({
                    "from": hex(other if kind == "caller" else ea),
                    "to": hex(ea if kind == "caller" else other),
                })
                if other not in seen:
                    if len(seen) >= args.max_nodes:
                        truncated = True
                        continue
                    seen.add(other)
                    q.append((other, depth + 1))

        payload = {
            "seed": hex(seed),
            "depth": args.depth,
            "direction": args.direction,
            "nodes": list(nodes.values()),
            "edges": edges,
            "truncated": truncated,
        }
        out = root / "queries" / f"callgraph_{seed:x}_d{args.depth}.json"
        out.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        print(json.dumps({"saved": str(out), "nodes": len(nodes), "edges": len(edges), "truncated": truncated}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
