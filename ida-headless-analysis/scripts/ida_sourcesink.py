"""Find bounded static paths between built-in source/sink API groups.

Useful for quickly locating candidate flows. This is not a vulnerability verdict or formal taint
engine; verify actual argument/value flow on interesting paths with C-tree/microcode.
"""
from __future__ import annotations

import argparse
import json
import re

from _ida_session import open_database
from _common import ensure_state, safe_text
import ida_query
import ida_path

GROUPS = {
    "network_input": [r"(^|!)(recv|recvfrom|WSARecv|InternetReadFile|WinHttpReadData)$"],
    "file_input": [r"(^|!)(ReadFile|fread|read|pread|ifstream.*read)$"],
    "user_input": [r"(^|!)(GetCommandLineA|GetCommandLineW|getenv|ReadConsoleA|ReadConsoleW)$"],
    "process_execution": [r"(^|!)(system|popen|WinExec|ShellExecuteA|ShellExecuteW|CreateProcessA|CreateProcessW)$"],
    "unsafe_memory": [r"(^|!)(strcpy|strcat|sprintf|vsprintf|gets|memcpy|memmove)$"],
    "crypto": [r"(^|!)(BCryptDecrypt|BCryptEncrypt|CryptDecrypt|CryptEncrypt|EVP_Decrypt.*|EVP_Encrypt.*)$"],
}


def endpoints(db, group: str, limit: int = 40):
    if group not in GROUPS:
        raise ValueError(f"Unknown group {group!r}; choices: {', '.join(sorted(GROUPS))}")
    patterns = [re.compile(x, re.I) for x in GROUPS[group]]
    out, seen = [], set()
    api = getattr(db, "imports", None)
    if api is not None:
        for imp in api.get_all_imports():
            qual = f"{safe_text(imp.module_name)}!{safe_text(imp.name) or '#'+str(imp.ordinal)}"
            if any(rx.search(qual) for rx in patterns):
                ea = int(imp.address)
                if ea not in seen:
                    seen.add(ea); out.append((ea, qual))
                    if len(out) >= limit: break
    if len(out) < limit:
        # Named local wrappers are useful too, but remain bounded.
        for f in db.functions.get_all():
            ea = int(f.start_ea)
            name = ida_query._function_name(db, ea)
            if ea not in seen and any(rx.search(name) for rx in patterns):
                seen.add(ea); out.append((ea, name))
                if len(out) >= limit: break
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("binary")
    ap.add_argument("source_group", choices=sorted(GROUPS))
    ap.add_argument("sink_group", choices=sorted(GROUPS))
    ap.add_argument("--max-depth", type=int, default=12)
    ap.add_argument("--max-paths", type=int, default=12)
    ap.add_argument("--max-nodes-per-pair", type=int, default=2500)
    args = ap.parse_args()

    with open_database(args.binary) as db:
        root = ensure_state(args.binary, ida_query._metadata(db))
        sources = endpoints(db, args.source_group)
        sinks = endpoints(db, args.sink_group)
        found = []
        for sea, sname in sources:
            for tea, tname in sinks:
                paths, expanded, capped = ida_path.find_paths(
                    sea, tea, max_depth=args.max_depth, max_paths=1,
                    max_nodes=args.max_nodes_per_pair, shortest_only=True,
                )
                if paths:
                    found.append({
                        "source": {"ea": hex(sea), "name": sname},
                        "sink": {"ea": hex(tea), "name": tname},
                        "path": ida_path.path_payload(paths)[0],
                        "hops": len(paths[0]) - 1, "expanded": expanded, "capped": capped,
                    })
                    if len(found) >= args.max_paths:
                        break
            if len(found) >= args.max_paths:
                break
        found.sort(key=lambda x: x["hops"])
        payload = {
            "source_group": args.source_group, "sink_group": args.sink_group,
            "source_endpoints": len(sources), "sink_endpoints": len(sinks),
            "paths": found,
            "warning": "Candidate static call-reference paths only. Validate argument/value flow before drawing security conclusions.",
        }
        out = root / "queries" / f"sourcesink_{args.source_group}_{args.sink_group}.json"
        out.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        print(json.dumps({"saved": str(out), "source_endpoints": len(sources),
                          "sink_endpoints": len(sinks), "paths": len(found)}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
