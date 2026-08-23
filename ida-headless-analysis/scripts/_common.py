from __future__ import annotations

from pathlib import Path
import hashlib
import json
import os
import re
import subprocess
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


def _git_root(start: Path) -> Path | None:
    """Return the enclosing git worktree root without requiring GitPython."""
    try:
        proc = subprocess.run(
            ["git", "-C", str(start), "rev-parse", "--show-toplevel"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            check=False,
            timeout=3,
        )
        if proc.returncode == 0 and proc.stdout.strip():
            return Path(proc.stdout.strip()).resolve()
    except Exception:
        pass
    return None


def project_root(binary: str | Path | None = None) -> Path:
    """Resolve the logical project root for globally installed skill state.

    Resolution order:
      1. IDA_RE_PROJECT_ROOT explicit override.
      2. Enclosing git worktree for the current working directory.
      3. Enclosing git worktree for the target binary.
      4. Current working directory.

    This keeps a globally installed skill from mixing evidence between unrelated projects.
    """
    override = os.environ.get("IDA_RE_PROJECT_ROOT")
    if override:
        return Path(override).expanduser().resolve()

    cwd = Path.cwd().resolve()
    root = _git_root(cwd)
    if root is not None:
        return root

    if binary is not None:
        try:
            bp = Path(binary).expanduser().resolve()
            root = _git_root(bp.parent)
            if root is not None:
                return root
        except Exception:
            pass

    return cwd


def project_id(binary: str | Path | None = None) -> str:
    """Return a stable, human-readable project identifier.

    IDA_RE_PROJECT_ID is the authoritative override. Otherwise the identifier is derived from the
    resolved project-root path and includes a short SHA-256 suffix, preventing collisions between
    projects that share the same directory basename (for example two different repos named
    `client`).
    """
    override = os.environ.get("IDA_RE_PROJECT_ID")
    if override:
        cleaned = re.sub(r"[^A-Za-z0-9_.-]+", "_", override.strip()).strip("._")
        if cleaned:
            return cleaned[:96]

    root = project_root(binary)
    label = re.sub(r"[^A-Za-z0-9_.-]+", "_", root.name or "project").strip("._") or "project"
    digest = hashlib.sha256(str(root).encode("utf-8", errors="surrogatepass")).hexdigest()[:12]
    return f"{label}-{digest}"


def state_base(binary: str | Path | None = None, base: str | Path = ".ida-re") -> Path:
    """Project-scoped persistent state base: .ida-re/projects/<project-id>/"""
    return Path(base) / "projects" / project_id(binary)


def state_root(binary: str | Path, base: str | Path = ".ida-re") -> Path:
    """Binary state isolated by both project identity and binary content hash."""
    return state_base(binary, base) / "binaries" / binary_id(binary)


def project_database_path(binary: str | Path | None = None, base: str | Path = ".ida-re") -> Path:
    """Default SQLite project graph path for the active project."""
    return state_base(binary, base) / "project.sqlite"


def ensure_state(binary: str | Path, metadata: dict[str, Any] | None = None) -> Path:
    root = state_root(binary)
    for d in ("functions", "queries"):
        (root / d).mkdir(parents=True, exist_ok=True)

    proj_root = project_root(binary)
    proj_id = project_id(binary)
    pbase = state_base(binary)
    pbase.mkdir(parents=True, exist_ok=True)
    project_manifest = pbase / "project.json"
    if not project_manifest.exists():
        project_manifest.write_text(json.dumps({
            "project_id": proj_id,
            "project_root": str(proj_root),
            "project_database": str(project_database_path(binary)),
        }, indent=2, default=str) + "\n", encoding="utf-8")

    manifest = root / "manifest.json"
    if not manifest.exists():
        payload = {
            "binary": str(Path(binary).resolve()),
            "binary_id": root.name,
            "project_id": proj_id,
            "project_root": str(proj_root),
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
