"""Deterministic reverse-engineering evidence, uncertainty, completion, and reconstruction ledger.

This is the persistent epistemic layer around IDA. It keeps observations distinct from inference,
tracks contradictions instead of erasing them, revisions unresolved questions optimistically, and
fails closed when reconstruction proof is incomplete.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import platform
from pathlib import Path
import sqlite3
import time
from typing import Any, Iterable

from _common import (
    binary_id,
    binary_sha256,
    project_id,
    project_root,
    state_root,
)
from _provenance import (
    canonical_json,
    evidence_id as compute_evidence_id,
    load_analysis_profile,
    semantic_id,
)

AUTHORITIES = {
    "shipped-artifact",
    "controlled-replay",
    "historical-reference",
    "external-service",
    "analyst-inference",
}
CONFIDENCE_KINDS = {"observed", "derived", "inferred"}
UNKNOWN_STATUSES = {"open", "investigating", "blocked", "contradicted", "resolved"}
COMPLETION_STATUSES = {"pass", "fail", "unsupported", "truncated", "unknown"}

SCHEMA = r'''
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS metadata(key TEXT PRIMARY KEY,value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS entities(id INTEGER PRIMARY KEY, kind TEXT NOT NULL, key TEXT NOT NULL, label TEXT, UNIQUE(kind,key));
CREATE TABLE IF NOT EXISTS claims(id INTEGER PRIMARY KEY, entity_id INTEGER, predicate TEXT NOT NULL, value TEXT NOT NULL, confidence REAL NOT NULL, status TEXT NOT NULL DEFAULT 'active', source TEXT, created REAL NOT NULL, FOREIGN KEY(entity_id) REFERENCES entities(id));
CREATE TABLE IF NOT EXISTS evidence(id INTEGER PRIMARY KEY, claim_id INTEGER NOT NULL, kind TEXT, detail TEXT NOT NULL, source TEXT, created REAL NOT NULL, FOREIGN KEY(claim_id) REFERENCES claims(id));
CREATE TABLE IF NOT EXISTS edges(id INTEGER PRIMARY KEY, src_entity INTEGER NOT NULL, relation TEXT NOT NULL, dst_entity INTEGER NOT NULL, confidence REAL NOT NULL, source TEXT, UNIQUE(src_entity,relation,dst_entity,source));
CREATE TABLE IF NOT EXISTS conflicts(id INTEGER PRIMARY KEY, claim_a INTEGER NOT NULL, claim_b INTEGER NOT NULL, reason TEXT NOT NULL, created REAL NOT NULL);
CREATE INDEX IF NOT EXISTS claims_entity_pred ON claims(entity_id,predicate,status);

CREATE TABLE IF NOT EXISTS observations(
  evidence_id TEXT PRIMARY KEY,
  subject_sha256 TEXT NOT NULL,
  subject_format TEXT,
  subject_architecture TEXT,
  subject_path TEXT,
  provider_json TEXT NOT NULL,
  analysis_profile_digest TEXT,
  predicate_type TEXT NOT NULL,
  operation TEXT NOT NULL,
  parameters_json TEXT NOT NULL,
  raw_result_json TEXT,
  normalized_result_json TEXT NOT NULL,
  confidence TEXT NOT NULL,
  authority TEXT NOT NULL,
  environment_json TEXT,
  limitations_json TEXT NOT NULL,
  locations_json TEXT NOT NULL,
  evidence_links_json TEXT NOT NULL,
  created REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS observations_operation ON observations(operation,authority,confidence);

CREATE TABLE IF NOT EXISTS unknown_heads(
  unknown_id TEXT PRIMARY KEY,
  revision INTEGER NOT NULL,
  previous_revision_digest TEXT,
  revision_digest TEXT NOT NULL,
  scope_digest TEXT NOT NULL,
  question TEXT NOT NULL,
  status TEXT NOT NULL,
  severity TEXT NOT NULL,
  domain TEXT NOT NULL,
  supporting_evidence_ids_json TEXT NOT NULL,
  contradicting_evidence_ids_json TEXT NOT NULL,
  required_authority TEXT,
  required_confidence TEXT NOT NULL,
  required_environment_json TEXT,
  recommended_probes_json TEXT NOT NULL,
  relationships_json TEXT NOT NULL,
  resolution_json TEXT,
  mutation_evidence_ids_json TEXT NOT NULL,
  updated REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS unknown_history(
  unknown_id TEXT NOT NULL,
  revision INTEGER NOT NULL,
  record_json TEXT NOT NULL,
  PRIMARY KEY(unknown_id,revision)
);

CREATE TABLE IF NOT EXISTS completion_ledgers(
  ledger_id TEXT PRIMARY KEY,
  ledger_json TEXT NOT NULL,
  created REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS obligations(
  obligation_id TEXT PRIMARY KEY,
  version INTEGER NOT NULL,
  title TEXT NOT NULL,
  spec_json TEXT NOT NULL,
  status TEXT NOT NULL,
  updated REAL NOT NULL
);
'''


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _json(value: Any) -> str:
    return canonical_json(value)


def _loads(value: str | None, default: Any) -> Any:
    if value is None:
        return default
    try:
        return json.loads(value)
    except Exception:
        return default


def _detect_format(path: str | Path) -> str:
    suffix = Path(path).suffix.lower()
    return {
        ".exe": "pe", ".dll": "pe", ".sys": "pe",
        ".elf": "elf", ".so": "elf", ".dylib": "mach-o",
        ".i64": "analysis-database", ".idb": "analysis-database",
        ".apk": "apk", ".zip": "zip", ".asar": "asar",
        ".bin": "unknown", ".rom": "unknown", ".img": "unknown",
    }.get(suffix, "unknown")


def connect(binary: str | Path):
    p = state_root(binary) / "evidence.sqlite"
    p.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(p)
    con.executescript(SCHEMA)
    con.row_factory = sqlite3.Row
    meta = {
        "project_id": project_id(binary),
        "project_root": str(project_root(binary)),
        "binary_id": binary_id(binary),
        "binary_sha256": binary_sha256(binary),
    }
    for k, v in meta.items():
        row = con.execute("SELECT value FROM metadata WHERE key=?", (k,)).fetchone()
        if row and row[0] != v:
            con.close()
            raise RuntimeError(f"Evidence DB identity mismatch for {k}: stored={row[0]!r} current={v!r}")
        con.execute("INSERT OR REPLACE INTO metadata(key,value) VALUES(?,?)", (k, v))
    con.commit()
    return p, con


def entity(con: sqlite3.Connection, kind: str, key: str, label: str | None = None) -> int:
    con.execute("INSERT OR IGNORE INTO entities(kind,key,label) VALUES(?,?,?)", (kind, key, label))
    row = con.execute("SELECT id FROM entities WHERE kind=? AND key=?", (kind, key)).fetchone()
    return int(row[0])


def add_claim(con: sqlite3.Connection, eid: int, pred: str, value: Any, confidence: float, source: str):
    now = time.time()
    encoded = _json(value) if not isinstance(value, str) else value
    old = con.execute(
        "SELECT id,value,confidence FROM claims WHERE entity_id=? AND predicate=? AND status='active'",
        (eid, pred),
    ).fetchall()
    cur = con.execute(
        "INSERT INTO claims(entity_id,predicate,value,confidence,source,created) VALUES(?,?,?,?,?,?)",
        (eid, pred, encoded, confidence, source, now),
    )
    cid = cur.lastrowid
    for oid, oval, oconf in old:
        if oval != encoded and min(float(oconf), confidence) >= .65:
            con.execute(
                "INSERT INTO conflicts(claim_a,claim_b,reason,created) VALUES(?,?,?,?)",
                (oid, cid, "same entity/predicate has incompatible active values", now),
            )
    return cid


def _manifest_architecture(binary: str | Path) -> str | None:
    manifest = state_root(binary) / "manifest.json"
    try:
        obj = json.loads(manifest.read_text(encoding="utf-8"))
        meta = obj.get("metadata") or {}
        arch = meta.get("architecture")
        return str(arch) if arch not in (None, "") else None
    except Exception:
        return None


def record_evidence(
    binary: str | Path,
    *,
    operation: str,
    result: Any,
    parameters: dict[str, Any] | None = None,
    raw_result: Any = None,
    confidence: str = "observed",
    authority: str = "shipped-artifact",
    predicate_type: str = "ida.analysis",
    limitations: Iterable[str] = (),
    locations: Iterable[Any] = (),
    evidence_links: Iterable[str] = (),
    provider: dict[str, Any] | None = None,
    environment: dict[str, Any] | None = None,
    subject_format: str | None = None,
    subject_architecture: str | None = None,
) -> dict[str, Any]:
    if confidence not in CONFIDENCE_KINDS:
        raise ValueError(f"invalid confidence: {confidence}")
    if authority not in AUTHORITIES:
        raise ValueError(f"invalid authority: {authority}")
    root = state_root(binary)
    profile = load_analysis_profile(root)
    if provider is None:
        provider = (profile or {}).get("provider") or {
            "id": "ida-headless-skill",
            "name": "IDA Headless Skill",
            "version": None,
        }
    if environment is None:
        environment = {
            "platform": platform.system(),
            "architecture": platform.machine(),
            "isolation": "none",
        }
    record = {
        "subject": {
            "sha256": binary_sha256(binary),
            "format": subject_format or _detect_format(binary),
            "architecture": subject_architecture or _manifest_architecture(binary),
            "local_path": str(Path(binary).resolve()),
        },
        "provider": provider,
        "analysis_profile_digest": (profile or {}).get("digest"),
        "predicate_type": predicate_type,
        "operation": operation,
        "parameters": parameters or {},
        "raw_result": raw_result,
        "normalized_result": result,
        "confidence": confidence,
        "authority": authority,
        "environment": environment,
        "limitations": list(limitations),
        "locations": list(locations),
        "evidence_links": sorted(set(evidence_links)),
    }
    eid = compute_evidence_id(record)
    record["evidence_id"] = eid
    _, con = connect(binary)
    con.execute(
        """INSERT OR IGNORE INTO observations(
        evidence_id,subject_sha256,subject_format,subject_architecture,subject_path,
        provider_json,analysis_profile_digest,predicate_type,operation,parameters_json,
        raw_result_json,normalized_result_json,confidence,authority,environment_json,
        limitations_json,locations_json,evidence_links_json,created)
        VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (
            eid,
            record["subject"]["sha256"], record["subject"]["format"], record["subject"]["architecture"],
            record["subject"]["local_path"], _json(provider), record["analysis_profile_digest"],
            predicate_type, operation, _json(record["parameters"]),
            None if raw_result is None else _json(raw_result), _json(result), confidence, authority,
            _json(environment), _json(record["limitations"]), _json(record["locations"]),
            _json(record["evidence_links"]), time.time(),
        ),
    )
    con.commit()
    con.close()
    return record


def _observation_from_row(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "evidence_id": row["evidence_id"],
        "subject": {
            "sha256": row["subject_sha256"],
            "format": row["subject_format"],
            "architecture": row["subject_architecture"],
            "local_path": row["subject_path"],
        },
        "provider": _loads(row["provider_json"], {}),
        "analysis_profile_digest": row["analysis_profile_digest"],
        "predicate_type": row["predicate_type"],
        "operation": row["operation"],
        "parameters": _loads(row["parameters_json"], {}),
        "raw_result": _loads(row["raw_result_json"], None),
        "normalized_result": _loads(row["normalized_result_json"], None),
        "confidence": row["confidence"],
        "authority": row["authority"],
        "environment": _loads(row["environment_json"], None),
        "limitations": _loads(row["limitations_json"], []),
        "locations": _loads(row["locations_json"], []),
        "evidence_links": _loads(row["evidence_links_json"], []),
    }


def _evidence_exists(con: sqlite3.Connection, eid: str) -> bool:
    return con.execute("SELECT 1 FROM observations WHERE evidence_id=?", (eid,)).fetchone() is not None


def _evidence_authority(con: sqlite3.Connection, eid: str) -> str | None:
    row = con.execute("SELECT authority FROM observations WHERE evidence_id=?", (eid,)).fetchone()
    return None if row is None else str(row[0])


def _normalize_question(text: str) -> str:
    return " ".join(text.split())


def _unknown_revision_digest(record: dict[str, Any]) -> str:
    projected = {k: v for k, v in record.items() if k not in {"revision_digest", "updated"}}
    return semantic_id("rev", projected).split("_", 1)[1]


def _validate_unknown(record: dict[str, Any]) -> None:
    if record["status"] not in UNKNOWN_STATUSES:
        raise ValueError(f"invalid unknown status: {record['status']}")
    if record["required_confidence"] not in CONFIDENCE_KINDS:
        raise ValueError("invalid required_confidence")
    if record.get("required_authority") not in AUTHORITIES | {None}:
        raise ValueError("invalid required_authority")
    support = set(record.get("supporting_evidence_ids") or [])
    contradict = set(record.get("contradicting_evidence_ids") or [])
    if support & contradict:
        raise ValueError("evidence cannot simultaneously support and contradict an unknown")
    if record["status"] == "contradicted" and not contradict:
        raise ValueError("contradicted unknown requires contradicting evidence")
    if (record["status"] == "resolved") != (record.get("resolution") is not None):
        raise ValueError("resolved unknown must carry a resolution, and only resolved unknowns may carry one")
    if record.get("resolution") and record["resolution"].get("disposition") == "verified":
        if not record["resolution"].get("evidence_ids"):
            raise ValueError("verified resolution requires evidence_ids")


def _store_unknown(con: sqlite3.Connection, record: dict[str, Any]) -> None:
    _validate_unknown(record)
    history = dict(record)
    con.execute(
        "INSERT OR REPLACE INTO unknown_history(unknown_id,revision,record_json) VALUES(?,?,?)",
        (record["unknown_id"], record["revision"], _json(history)),
    )
    con.execute(
        """INSERT OR REPLACE INTO unknown_heads(
        unknown_id,revision,previous_revision_digest,revision_digest,scope_digest,question,status,severity,domain,
        supporting_evidence_ids_json,contradicting_evidence_ids_json,required_authority,required_confidence,
        required_environment_json,recommended_probes_json,relationships_json,resolution_json,
        mutation_evidence_ids_json,updated) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (
            record["unknown_id"], record["revision"], record.get("previous_revision_digest"), record["revision_digest"],
            record["scope_digest"], record["question"], record["status"], record["severity"], record["domain"],
            _json(record.get("supporting_evidence_ids", [])), _json(record.get("contradicting_evidence_ids", [])),
            record.get("required_authority"), record["required_confidence"],
            None if record.get("required_environment") is None else _json(record["required_environment"]),
            _json(record.get("recommended_probes", [])), _json(record.get("relationships", [])),
            None if record.get("resolution") is None else _json(record["resolution"]),
            _json(record.get("mutation_evidence_ids", [])), time.time(),
        ),
    )


def _unknown_from_row(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "unknown_id": row["unknown_id"], "revision": row["revision"],
        "previous_revision_digest": row["previous_revision_digest"], "revision_digest": row["revision_digest"],
        "scope_digest": row["scope_digest"], "question": row["question"], "status": row["status"],
        "severity": row["severity"], "domain": row["domain"],
        "supporting_evidence_ids": _loads(row["supporting_evidence_ids_json"], []),
        "contradicting_evidence_ids": _loads(row["contradicting_evidence_ids_json"], []),
        "required_authority": row["required_authority"], "required_confidence": row["required_confidence"],
        "required_environment": _loads(row["required_environment_json"], None),
        "recommended_probes": _loads(row["recommended_probes_json"], []),
        "relationships": _loads(row["relationships_json"], []),
        "resolution": _loads(row["resolution_json"], None),
        "mutation_evidence_ids": _loads(row["mutation_evidence_ids_json"], []),
    }


def create_unknown(binary: str | Path, spec: dict[str, Any]) -> dict[str, Any]:
    question = _normalize_question(str(spec["question"]))
    scope = binary_sha256(binary)
    mutation = record_evidence(
        binary,
        operation="unknown.record",
        result={"question": question, "domain": spec.get("domain", "general")},
        parameters={},
        confidence="inferred",
        authority="analyst-inference",
        predicate_type="ida.unknown.mutation",
    )
    record = {
        "unknown_id": semantic_id("unk", {"domain": spec.get("domain", "general"), "question": question, "scope_digest": scope}),
        "revision": 1,
        "previous_revision_digest": None,
        "scope_digest": scope,
        "question": question,
        "status": "contradicted" if spec.get("contradicting_evidence_ids") else "open",
        "severity": spec.get("severity", "medium"),
        "domain": spec.get("domain", "general"),
        "supporting_evidence_ids": sorted(set(spec.get("supporting_evidence_ids", []))),
        "contradicting_evidence_ids": sorted(set(spec.get("contradicting_evidence_ids", []))),
        "required_authority": spec.get("required_authority"),
        "required_confidence": spec.get("required_confidence", "observed"),
        "required_environment": spec.get("required_environment"),
        "recommended_probes": spec.get("recommended_probes", []),
        "relationships": spec.get("relationships", []),
        "resolution": None,
        "mutation_evidence_ids": [mutation["evidence_id"]],
        "updated": _now_iso(),
    }
    record["revision_digest"] = _unknown_revision_digest(record)
    _, con = connect(binary)
    for eid in record["supporting_evidence_ids"] + record["contradicting_evidence_ids"]:
        if not _evidence_exists(con, eid):
            con.close(); raise ValueError(f"unknown references missing evidence: {eid}")
    _store_unknown(con, record)
    con.commit(); con.close()
    return record


def update_unknown(binary: str | Path, unknown_id: str, expected_revision: int, patch: dict[str, Any]) -> dict[str, Any]:
    _, con = connect(binary)
    row = con.execute("SELECT * FROM unknown_heads WHERE unknown_id=?", (unknown_id,)).fetchone()
    if row is None:
        con.close(); raise KeyError(unknown_id)
    current = _unknown_from_row(row)
    if current["revision"] != expected_revision:
        con.close(); raise RuntimeError(f"stale unknown revision: expected {expected_revision}, current {current['revision']}")
    mutable = {
        "status", "severity", "supporting_evidence_ids", "contradicting_evidence_ids",
        "required_authority", "required_confidence", "required_environment", "recommended_probes",
        "relationships", "resolution",
    }
    next_rec = dict(current)
    for k in mutable:
        if k in patch:
            next_rec[k] = patch[k]
    next_rec["supporting_evidence_ids"] = sorted(set(next_rec.get("supporting_evidence_ids", [])))
    next_rec["contradicting_evidence_ids"] = sorted(set(next_rec.get("contradicting_evidence_ids", [])))
    for eid in next_rec["supporting_evidence_ids"] + next_rec["contradicting_evidence_ids"]:
        if not _evidence_exists(con, eid):
            con.close(); raise ValueError(f"unknown references missing evidence: {eid}")
    mutation = record_evidence(
        binary,
        operation="unknown.update",
        result={"unknown_id": unknown_id, "expected_revision": expected_revision, "patch": patch},
        confidence="inferred",
        authority="analyst-inference",
        predicate_type="ida.unknown.mutation",
        evidence_links=next_rec["supporting_evidence_ids"] + next_rec["contradicting_evidence_ids"],
    )
    next_rec.update({
        "revision": expected_revision + 1,
        "previous_revision_digest": current["revision_digest"],
        "mutation_evidence_ids": sorted(set(current.get("mutation_evidence_ids", []) + [mutation["evidence_id"]])),
        "updated": _now_iso(),
    })
    next_rec["revision_digest"] = _unknown_revision_digest(next_rec)
    # Reopen because record_evidence used its own connection.
    con.close(); _, con = connect(binary)
    _store_unknown(con, next_rec)
    con.commit(); con.close()
    return next_rec


def build_completion_ledger(binary: str | Path, records: list[dict[str, Any]]) -> dict[str, Any]:
    if not records:
        raise ValueError("completion ledger requires at least one claim")
    normalized = []
    _, con = connect(binary)
    seen = set()
    for item in records:
        claim_id = str(item["claim_id"])
        if claim_id in seen:
            con.close(); raise ValueError(f"duplicate completion claim_id: {claim_id}")
        seen.add(claim_id)
        status = str(item["status"])
        if status not in COMPLETION_STATUSES:
            con.close(); raise ValueError(f"invalid completion status: {status}")
        eids = sorted(set(item.get("evidence_ids", [])))
        if not eids:
            con.close(); raise ValueError(f"completion claim {claim_id} requires evidence_ids")
        for eid in eids:
            if not _evidence_exists(con, eid):
                con.close(); raise ValueError(f"completion claim {claim_id} references missing evidence {eid}")
        normalized.append({"claim_id": claim_id, "status": status, "evidence_ids": eids})
    normalized.sort(key=lambda x: x["claim_id"])
    counts = {k: 0 for k in sorted(COMPLETION_STATUSES)}
    for item in normalized:
        counts[item["status"]] += 1
    summary = {"total": len(normalized), **counts, "complete": counts["pass"] == len(normalized)}
    ledger = {"records": normalized, "summary": summary}
    ledger["ledger_id"] = semantic_id("ecl", {"records": normalized})
    con.execute(
        "INSERT OR REPLACE INTO completion_ledgers(ledger_id,ledger_json,created) VALUES(?,?,?)",
        (ledger["ledger_id"], _json(ledger), time.time()),
    )
    con.commit(); con.close()
    return ledger


def evaluate_obligation(con: sqlite3.Connection, spec: dict[str, Any]) -> dict[str, Any]:
    missing: list[str] = []
    failures: list[str] = []
    oid = str(spec["obligation_id"])
    if spec.get("required", True) is False:
        return {"obligation_id": oid, "status": "not-required", "missing": [], "failures": []}
    owner = spec.get("owner")
    if not isinstance(owner, dict) or not owner.get("module_path") or not owner.get("symbol") or not owner.get("owner_sha256"):
        missing.append("unique implementation owner with module_path, symbol, owner_sha256")
    if spec.get("requires_parser_type") and not spec.get("parser_type"):
        missing.append("parser/schema/domain type")
    if spec.get("unavailable_authority"):
        missing.append("required authority unavailable: " + ", ".join(map(str, spec.get("unavailable_authority", []))))
    if spec.get("contradictions"):
        failures.append("unresolved contradictions")

    required_kinds = list(spec.get("required_case_kinds", []))
    for field in ("original_cases", "reconstruction_cases"):
        cases = spec.get(field, [])
        by_kind = {str(c.get("kind")): c for c in cases if isinstance(c, dict)}
        for kind in required_kinds:
            case = by_kind.get(kind)
            if case is None:
                missing.append(f"{field}:{kind}")
                continue
            eid = case.get("evidence_id")
            if not eid or not _evidence_exists(con, str(eid)):
                missing.append(f"{field}:{kind}:authenticated evidence")

    for uid in spec.get("residual_unknown_ids", []):
        row = con.execute("SELECT status FROM unknown_heads WHERE unknown_id=?", (uid,)).fetchone()
        if row is None or row[0] != "resolved":
            missing.append(f"residual unknown unresolved:{uid}")

    verifier = spec.get("verifier")
    if not isinstance(verifier, dict):
        missing.append("passing verifier")
    else:
        if verifier.get("status") == "fail":
            failures.append("verifier failed")
        elif verifier.get("status") != "pass":
            missing.append("passing verifier")
        eid = verifier.get("evidence_id")
        if not eid or not _evidence_exists(con, str(eid)):
            missing.append("verifier authenticated evidence")
        required_auth = spec.get("required_verifier_authority")
        if required_auth and verifier.get("authority") != required_auth:
            missing.append(f"verifier declared authority {required_auth}")
        if required_auth and eid and _evidence_authority(con, str(eid)) != required_auth:
            missing.append(f"verifier evidence authority {required_auth}")

    status = "failed" if failures else ("open" if missing else "ready")
    return {"obligation_id": oid, "status": status, "missing": sorted(set(missing)), "failures": sorted(set(failures))}


def upsert_obligation(binary: str | Path, spec: dict[str, Any]) -> dict[str, Any]:
    _, con = connect(binary)
    result = evaluate_obligation(con, spec)
    con.execute(
        "INSERT OR REPLACE INTO obligations(obligation_id,version,title,spec_json,status,updated) VALUES(?,?,?,?,?,?)",
        (
            spec["obligation_id"], int(spec.get("obligation_version", 1)), spec.get("title", spec["obligation_id"]),
            _json(spec), result["status"], time.time(),
        ),
    )
    con.commit(); con.close()
    return result


def _parse_json_arg(value: str | None, default: Any) -> Any:
    if value is None:
        return default
    p = Path(value)
    if p.exists() and p.is_file():
        return json.loads(p.read_text(encoding="utf-8"))
    return json.loads(value)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("binary")
    sub = ap.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("claim-add")
    a.add_argument("kind"); a.add_argument("key"); a.add_argument("predicate"); a.add_argument("value")
    a.add_argument("--confidence", type=float, default=.6); a.add_argument("--source", default="claude")
    q = sub.add_parser("query"); q.add_argument("text", nargs="?", default=""); q.add_argument("--limit", type=int, default=50)
    sub.add_parser("conflicts"); sub.add_parser("info")

    o = sub.add_parser("observe-add")
    o.add_argument("operation"); o.add_argument("result", help="JSON file or inline JSON")
    o.add_argument("--parameters"); o.add_argument("--raw-result")
    o.add_argument("--confidence", choices=sorted(CONFIDENCE_KINDS), default="observed")
    o.add_argument("--authority", choices=sorted(AUTHORITIES), default="shipped-artifact")
    o.add_argument("--predicate-type", default="ida.analysis")
    o.add_argument("--limitation", action="append", default=[]); o.add_argument("--location", action="append", default=[])
    o.add_argument("--link", action="append", default=[])
    og = sub.add_parser("observe-get"); og.add_argument("evidence_id")
    ol = sub.add_parser("observe-list"); ol.add_argument("--operation"); ol.add_argument("--limit", type=int, default=50)

    ua = sub.add_parser("unknown-add"); ua.add_argument("spec", help="JSON file or inline JSON")
    uu = sub.add_parser("unknown-update"); uu.add_argument("unknown_id"); uu.add_argument("expected_revision", type=int); uu.add_argument("patch")
    ul = sub.add_parser("unknown-list"); ul.add_argument("--status", choices=sorted(UNKNOWN_STATUSES)); ul.add_argument("--limit", type=int, default=100)

    cb = sub.add_parser("completion-build"); cb.add_argument("records", help="JSON array or file")
    cl = sub.add_parser("completion-list"); cl.add_argument("--limit", type=int, default=20)

    oa = sub.add_parser("obligation-add"); oa.add_argument("spec", help="JSON file or inline JSON")
    oe = sub.add_parser("obligation-evaluate"); oe.add_argument("obligation_id")
    sub.add_parser("obligation-list")

    args = ap.parse_args()
    path, con = connect(args.binary)

    if args.cmd == "claim-add":
        eid = entity(con, args.kind, args.key)
        cid = add_claim(con, eid, args.predicate, args.value, args.confidence, args.source)
        con.commit(); result = {"claim_id": cid}
    elif args.cmd == "query":
        like = f"%{args.text}%"
        result = [dict(r) for r in con.execute(
            "SELECT c.id,e.kind,e.key,e.label,c.predicate,c.value,c.confidence,c.status,c.source FROM claims c JOIN entities e ON e.id=c.entity_id WHERE e.key LIKE ? OR e.label LIKE ? OR c.predicate LIKE ? OR c.value LIKE ? ORDER BY c.confidence DESC LIMIT ?",
            (like, like, like, like, args.limit),
        )]
    elif args.cmd == "conflicts":
        result = [dict(r) for r in con.execute(
            "SELECT x.id,x.reason,a.value AS value_a,b.value AS value_b,a.confidence AS confidence_a,b.confidence AS confidence_b FROM conflicts x JOIN claims a ON a.id=x.claim_a JOIN claims b ON b.id=x.claim_b ORDER BY x.id DESC LIMIT 100"
        )]
    elif args.cmd == "info":
        result = {r["key"]: r["value"] for r in con.execute("SELECT key,value FROM metadata ORDER BY key")}
        result.update({
            "observations": con.execute("SELECT COUNT(*) FROM observations").fetchone()[0],
            "open_unknowns": con.execute("SELECT COUNT(*) FROM unknown_heads WHERE status!='resolved'").fetchone()[0],
            "obligations": con.execute("SELECT COUNT(*) FROM obligations").fetchone()[0],
        })
    elif args.cmd == "observe-add":
        con.close()
        result = record_evidence(
            args.binary, operation=args.operation, result=_parse_json_arg(args.result, {}),
            parameters=_parse_json_arg(args.parameters, {}), raw_result=_parse_json_arg(args.raw_result, None),
            confidence=args.confidence, authority=args.authority, predicate_type=args.predicate_type,
            limitations=args.limitation, locations=[_parse_json_arg(x, x) for x in args.location], evidence_links=args.link,
        )
        print(json.dumps({"database": str(path), "result": result}, indent=2, ensure_ascii=False)); return 0
    elif args.cmd == "observe-get":
        row = con.execute("SELECT * FROM observations WHERE evidence_id=?", (args.evidence_id,)).fetchone()
        result = None if row is None else _observation_from_row(row)
    elif args.cmd == "observe-list":
        if args.operation:
            rows = con.execute("SELECT * FROM observations WHERE operation=? ORDER BY created DESC LIMIT ?", (args.operation, args.limit))
        else:
            rows = con.execute("SELECT * FROM observations ORDER BY created DESC LIMIT ?", (args.limit,))
        result = [_observation_from_row(r) for r in rows]
    elif args.cmd == "unknown-add":
        con.close(); result = create_unknown(args.binary, _parse_json_arg(args.spec, {}))
        print(json.dumps({"database": str(path), "result": result}, indent=2, ensure_ascii=False)); return 0
    elif args.cmd == "unknown-update":
        con.close(); result = update_unknown(args.binary, args.unknown_id, args.expected_revision, _parse_json_arg(args.patch, {}))
        print(json.dumps({"database": str(path), "result": result}, indent=2, ensure_ascii=False)); return 0
    elif args.cmd == "unknown-list":
        if args.status:
            rows = con.execute("SELECT * FROM unknown_heads WHERE status=? ORDER BY updated DESC LIMIT ?", (args.status, args.limit))
        else:
            rows = con.execute("SELECT * FROM unknown_heads ORDER BY CASE status WHEN 'contradicted' THEN 0 WHEN 'blocked' THEN 1 WHEN 'investigating' THEN 2 WHEN 'open' THEN 3 ELSE 4 END, updated DESC LIMIT ?", (args.limit,))
        result = [_unknown_from_row(r) for r in rows]
    elif args.cmd == "completion-build":
        con.close(); result = build_completion_ledger(args.binary, _parse_json_arg(args.records, []))
        print(json.dumps({"database": str(path), "result": result}, indent=2, ensure_ascii=False)); return 0
    elif args.cmd == "completion-list":
        result = [_loads(r[0], {}) for r in con.execute("SELECT ledger_json FROM completion_ledgers ORDER BY created DESC LIMIT ?", (args.limit,))]
    elif args.cmd == "obligation-add":
        con.close(); spec = _parse_json_arg(args.spec, {}); result = upsert_obligation(args.binary, spec)
        print(json.dumps({"database": str(path), "result": result}, indent=2, ensure_ascii=False)); return 0
    elif args.cmd == "obligation-evaluate":
        row = con.execute("SELECT spec_json FROM obligations WHERE obligation_id=?", (args.obligation_id,)).fetchone()
        if row is None:
            result = None
        else:
            spec = json.loads(row[0]); result = evaluate_obligation(con, spec)
            con.execute("UPDATE obligations SET status=?,updated=? WHERE obligation_id=?", (result["status"], time.time(), args.obligation_id)); con.commit()
    elif args.cmd == "obligation-list":
        result = [{**dict(r), "spec": json.loads(r["spec_json"])} for r in con.execute("SELECT obligation_id,version,title,status,updated,spec_json FROM obligations ORDER BY status,obligation_id")]
    else:
        raise AssertionError(args.cmd)

    con.close()
    print(json.dumps({"database": str(path), "result": result}, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
