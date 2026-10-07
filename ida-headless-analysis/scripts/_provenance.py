"""Deterministic provenance primitives for the IDA headless skill.

This module intentionally has no IDA imports at module import time so it can be used by
pure-Python evidence, comparison, and conformance tools.
"""
from __future__ import annotations

from pathlib import Path
import hashlib
import json
import os
import platform
from typing import Any, Mapping


def canonical_json(value: Any) -> str:
    """Return a stable JSON representation used for semantic identifiers."""
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
        default=str,
    )


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: str | os.PathLike[str]) -> str:
    h = hashlib.sha256()
    with Path(path).open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def semantic_id(prefix: str, value: Any) -> str:
    return f"{prefix}_{hashlib.sha256(canonical_json(value).encode('utf-8')).hexdigest()}"


def _safe_call(fn, default=None):
    try:
        return fn()
    except Exception:
        return default


def build_analysis_profile(db: object | None = None) -> dict[str, Any]:
    """Build a provider/profile commitment inside an active IDA session.

    The profile records only analysis-affecting/version facts that can be obtained reliably.
    Missing facts remain null instead of being invented. The digest commits to all parameters.
    """
    try:
        import idaapi
        ida_version = _safe_call(lambda: idaapi.get_kernel_version(), None)
    except Exception:
        ida_version = None
    try:
        import ida_hexrays
        hexrays_version = _safe_call(lambda: ida_hexrays.get_hexrays_version(), None)
    except Exception:
        hexrays_version = None
    try:
        import ida_idp
        processor = _safe_call(lambda: ida_idp.get_idp_name(), None)
    except Exception:
        processor = None
    try:
        import ida_ida
        bitness = _safe_call(
            lambda: 64 if ida_ida.inf_is_64bit() else (32 if ida_ida.inf_is_32bit_exactly() else 16),
            None,
        )
        big_endian = _safe_call(lambda: bool(ida_ida.inf_is_be()), None)
    except Exception:
        bitness = None
        big_endian = None
    try:
        import ida_nalt
        input_file = _safe_call(lambda: ida_nalt.get_input_file_path(), None)
        imagebase = _safe_call(lambda: hex(int(ida_nalt.get_imagebase())), None)
    except Exception:
        input_file = None
        imagebase = None

    metadata = getattr(db, "metadata", None)
    domain_arch = str(getattr(metadata, "architecture", "")) or None
    domain_bitness = getattr(metadata, "bitness", None)
    if bitness is None and domain_bitness is not None:
        try:
            bitness = int(domain_bitness)
        except Exception:
            pass

    params = {
        "ida_version": ida_version,
        "hexrays_version": hexrays_version,
        "ida_domain_version": _ida_domain_version(),
        "processor": processor,
        "domain_architecture": domain_arch,
        "bitness": bitness,
        "big_endian": big_endian,
        "imagebase": imagebase,
        "auto_analysis": True,
        "hexrays_required": True,
        "input_basename": Path(input_file).name if input_file else None,
        "host_platform": platform.system(),
        "host_machine": platform.machine(),
    }
    unsigned = {
        "provider": {
            "id": "ida-pro-idalib",
            "name": "IDA Pro + Hex-Rays via ida-domain/idalib",
            "version": ida_version,
        },
        "parameters": params,
    }
    return {**unsigned, "digest": hashlib.sha256(canonical_json(unsigned).encode("utf-8")).hexdigest()}


def _ida_domain_version() -> str | None:
    try:
        import importlib.metadata
        for name in ("ida-domain", "ida_domain"):
            try:
                return importlib.metadata.version(name)
            except importlib.metadata.PackageNotFoundError:
                continue
    except Exception:
        pass
    return None


def save_analysis_profile(root: str | os.PathLike[str], db: object | None = None) -> dict[str, Any]:
    profile = build_analysis_profile(db)
    path = Path(root) / "analysis_profile.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(profile, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return profile


def load_analysis_profile(root: str | os.PathLike[str]) -> dict[str, Any] | None:
    path = Path(root) / "analysis_profile.json"
    if not path.exists():
        return None
    try:
        obj = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None
    if not isinstance(obj, dict) or not isinstance(obj.get("digest"), str):
        return None
    return obj


def evidence_semantic_projection(record: Mapping[str, Any]) -> dict[str, Any]:
    """Path-independent semantic projection for an evidence record."""
    subject = record.get("subject") or None
    if isinstance(subject, Mapping):
        subject = {
            "sha256": subject.get("sha256"),
            "format": subject.get("format"),
            "architecture": subject.get("architecture"),
        }
    return {
        "subject": subject,
        "provider": record.get("provider"),
        "analysis_profile_digest": record.get("analysis_profile_digest"),
        "predicate_type": record.get("predicate_type"),
        "operation": record.get("operation"),
        "parameters": record.get("parameters") or {},
        "raw_result": record.get("raw_result"),
        "normalized_result": record.get("normalized_result"),
        "confidence": record.get("confidence"),
        "authority": record.get("authority"),
        "environment": record.get("environment"),
        "limitations": record.get("limitations") or [],
        "locations": record.get("locations") or [],
        "evidence_links": sorted(record.get("evidence_links") or []),
    }


def evidence_id(record: Mapping[str, Any]) -> str:
    return semantic_id("ev", evidence_semantic_projection(record))
