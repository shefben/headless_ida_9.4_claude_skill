"""Controlled process capture and original-vs-reconstruction comparison.

Runs exactly the declared command with the caller's permissions. This is evidence collection, not a
sandbox. Captures are bounded and preserve missing/truncated dimensions as unknown rather than pass.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time
from typing import Any

from _common import ensure_state
from _provenance import canonical_json, semantic_id, sha256_file
from ida_evidence import record_evidence

MAX_STREAM_BYTES = 2 * 1024 * 1024
MAX_FILES = 5000


def _snapshot_path(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {"path": str(path), "state": "missing"}
    if path.is_file():
        try:
            return {"path": str(path), "state": "file", "size": path.stat().st_size, "sha256": sha256_file(path)}
        except Exception as exc:
            return {"path": str(path), "state": "error", "error": str(exc)}
    rows = []
    truncated = False
    try:
        for child in sorted(path.rglob("*")):
            if len(rows) >= MAX_FILES:
                truncated = True; break
            rel = str(child.relative_to(path))
            if child.is_symlink():
                rows.append({"path": rel, "kind": "symlink", "target": os.readlink(child)})
            elif child.is_file():
                try:
                    rows.append({"path": rel, "kind": "file", "size": child.stat().st_size, "sha256": sha256_file(child)})
                except Exception as exc:
                    rows.append({"path": rel, "kind": "error", "error": str(exc)})
            elif child.is_dir():
                rows.append({"path": rel, "kind": "dir"})
    except Exception as exc:
        return {"path": str(path), "state": "error", "error": str(exc)}
    return {"path": str(path), "state": "directory", "entries": rows, "truncated": truncated}


def _clip(data: bytes) -> tuple[str, bool, str]:
    truncated = len(data) > MAX_STREAM_BYTES
    kept = data[:MAX_STREAM_BYTES]
    return kept.decode("utf-8", errors="replace"), truncated, hashlib.sha256(data).hexdigest()


def capture(scenario: dict[str, Any]) -> dict[str, Any]:
    command = scenario.get("command")
    if not isinstance(command, list) or not command or not all(isinstance(x, str) for x in command):
        raise ValueError("scenario.command must be a non-empty string array")
    cwd = Path(scenario.get("cwd") or ".").expanduser().resolve()
    if not cwd.exists():
        raise FileNotFoundError(cwd)
    env = os.environ.copy()
    for k, v in (scenario.get("env") or {}).items():
        env[str(k)] = str(v)
    timeout = float(scenario.get("timeout_seconds", 60.0))
    if timeout <= 0 or timeout > 3600:
        raise ValueError("timeout_seconds must be >0 and <=3600")
    watched = [Path(x).expanduser().resolve() for x in scenario.get("snapshot_paths", [])]
    before = [_snapshot_path(p) for p in watched]
    started = time.time()
    timed_out = False
    proc = None
    try:
        proc = subprocess.Popen(
            command,
            cwd=str(cwd),
            env=env,
            stdin=subprocess.PIPE if scenario.get("stdin") is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
        )
        input_bytes = None if scenario.get("stdin") is None else str(scenario["stdin"]).encode("utf-8")
        try:
            out, err = proc.communicate(input=input_bytes, timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            proc.kill()
            out, err = proc.communicate()
    finally:
        ended = time.time()
    after = [_snapshot_path(p) for p in watched]
    stdout, stdout_truncated, stdout_sha = _clip(out if proc is not None else b"")
    stderr, stderr_truncated, stderr_sha = _clip(err if proc is not None else b"")
    result = {
        "capture_id": None,
        "scenario": {
            "command": command,
            "cwd": str(cwd),
            "env_names": sorted((scenario.get("env") or {}).keys()),
            "timeout_seconds": timeout,
            "snapshot_paths": [str(x) for x in watched],
        },
        "exit": {
            "returncode": None if proc is None else proc.returncode,
            "timed_out": timed_out,
            "duration_seconds": round(ended - started, 6),
        },
        "stdout": {"text": stdout, "sha256": stdout_sha, "truncated": stdout_truncated},
        "stderr": {"text": stderr, "sha256": stderr_sha, "truncated": stderr_truncated},
        "filesystem": {"before": before, "after": after},
        "limitations": [
            "process capture runs with caller permissions and is not a security sandbox",
            "network activity is not captured by this helper",
            "descendant-process cleanup is not proven unless the scenario itself establishes it",
        ],
    }
    if stdout_truncated or stderr_truncated or any(x.get("truncated") for x in before + after if isinstance(x, dict)):
        result["limitations"].append("one or more capture dimensions were truncated")
    result["capture_id"] = semantic_id("cap", {k: v for k, v in result.items() if k != "capture_id"})
    return result


def compare(left: dict[str, Any], right: dict[str, Any]) -> dict[str, Any]:
    dimensions = []
    def add(name: str, lv: Any, rv: Any, unknown: bool = False):
        status = "unknown" if unknown else ("equal" if canonical_json(lv) == canonical_json(rv) else "different")
        dimensions.append({"dimension": name, "status": status, "left": lv, "right": rv})
    add("exit.returncode", left.get("exit", {}).get("returncode"), right.get("exit", {}).get("returncode"))
    add("exit.timed_out", left.get("exit", {}).get("timed_out"), right.get("exit", {}).get("timed_out"))
    add("stdout.sha256", left.get("stdout", {}).get("sha256"), right.get("stdout", {}).get("sha256"), bool(left.get("stdout", {}).get("truncated") or right.get("stdout", {}).get("truncated")))
    add("stderr.sha256", left.get("stderr", {}).get("sha256"), right.get("stderr", {}).get("sha256"), bool(left.get("stderr", {}).get("truncated") or right.get("stderr", {}).get("truncated")))
    fs_unknown = any(x.get("truncated") for x in left.get("filesystem", {}).get("after", []) + right.get("filesystem", {}).get("after", []) if isinstance(x, dict))
    add("filesystem.after", left.get("filesystem", {}).get("after"), right.get("filesystem", {}).get("after"), fs_unknown)
    first = next((x for x in dimensions if x["status"] == "different"), None)
    unknowns = [x["dimension"] for x in dimensions if x["status"] == "unknown"]
    equivalent = first is None and not unknowns and all(x["status"] == "equal" for x in dimensions)
    return {
        "comparison_id": semantic_id("cmp", {"left": left.get("capture_id"), "right": right.get("capture_id"), "dimensions": dimensions}),
        "left_capture_id": left.get("capture_id"),
        "right_capture_id": right.get("capture_id"),
        "dimensions": dimensions,
        "first_divergence": first,
        "unknown_dimensions": unknowns,
        "equivalent_within_declared_dimensions": equivalent,
    }


def _read(path: str) -> Any:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("capture"); c.add_argument("scenario"); c.add_argument("--out"); c.add_argument("--subject")
    x = sub.add_parser("compare"); x.add_argument("left"); x.add_argument("right"); x.add_argument("--out"); x.add_argument("--subject")
    args = ap.parse_args()
    if args.cmd == "capture":
        scenario = _read(args.scenario); result = capture(scenario)
        out = Path(args.out) if args.out else Path(args.scenario).with_suffix(".capture.json")
        out.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        evidence = None
        if args.subject:
            evidence = record_evidence(args.subject, operation="capture_process", result=result, parameters={"scenario": result["scenario"]}, confidence="observed", authority="controlled-replay", predicate_type="ida.runtime.capture", limitations=result["limitations"])
        print(json.dumps({"saved": str(out), "capture_id": result["capture_id"], "evidence_id": None if evidence is None else evidence["evidence_id"]}, indent=2)); return 0
    left = _read(args.left); right = _read(args.right); result = compare(left, right)
    out = Path(args.out) if args.out else Path(args.right).with_suffix(".comparison.json")
    out.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    evidence = None
    if args.subject:
        evidence = record_evidence(args.subject, operation="compare_process_captures", result=result, parameters={"left": left.get("capture_id"), "right": right.get("capture_id")}, confidence="derived", authority="controlled-replay", predicate_type="ida.runtime.comparison")
    print(json.dumps({"saved": str(out), "comparison_id": result["comparison_id"], "evidence_id": None if evidence is None else evidence["evidence_id"], "first_divergence": result["first_divergence"]}, indent=2)); return 0


if __name__ == "__main__":
    raise SystemExit(main())
