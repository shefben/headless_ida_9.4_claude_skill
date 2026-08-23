from __future__ import annotations

from pathlib import Path
import hashlib
import json
import re
from typing import Any, Iterable


def parse_ea(value: str) -> int:
    return int(value, 0)


def safe_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


def bounded(items: Iterable[Any], limit: int) -> tuple[list[Any], bool]:
    out = []
    truncated = False
    for item in items:
        if len(out) >= limit:
            truncated = True
            break
        out.append(item)
    return out, truncated


def binary_id(path: str | Path) -> str:
    p = Path(path)
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()[:16]


def state_root(binary: str | Path, base: str | Path = ".ida-re") -> Path:
    return Path(base) / binary_id(binary)


def ensure_state(binary: str | Path, metadata: dict[str, Any] | None = None) -> Path:
    root = state_root(binary)
    for d in ("functions", "queries"):
        (root / d).mkdir(parents=True, exist_ok=True)
    manifest = root / "manifest.json"
    if not manifest.exists():
        payload = {
            "binary": str(Path(binary).resolve()),
            "binary_id": root.name,
            "metadata": metadata or {},
        }
        manifest.write_text(json.dumps(payload, indent=2, default=str) + "\n", encoding="utf-8")
    return root


def append_jsonl(path: Path, obj: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(obj, ensure_ascii=False, default=str) + "\n")


def regex_filter(text: str, pattern: str | None, contains: str | None) -> bool:
    if contains and contains.lower() not in text.lower():
        return False
    if pattern and re.search(pattern, text, flags=re.IGNORECASE) is None:
        return False
    return True
