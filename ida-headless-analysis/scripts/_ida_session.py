"""Mandatory IDA 9.4 / Hex-Rays session wrapper.

No analysis/decompilation helper should call Database.open() directly.
"""
from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path
import os
from typing import Iterator

DEFAULT_IDADIR = r"%IDA_PATH%"


def _candidate_idbs(binary: Path) -> list[Path]:
    candidates = [
        binary.with_suffix(".i64"),
        binary.with_suffix(".idb"),
        Path(str(binary) + ".i64"),
        Path(str(binary) + ".idb"),
    ]
    return list(dict.fromkeys(candidates))


def cached_database_exists(binary_path: str | os.PathLike[str]) -> bool:
    binary = Path(binary_path)
    return any(p.exists() for p in _candidate_idbs(binary))


def _ensure_environment() -> None:
    os.environ["IDADIR"] = os.environ.get("IDADIR") or DEFAULT_IDADIR
    ida_dir = Path(os.environ["IDADIR"])
    if not ida_dir.exists():
        raise RuntimeError(
            f"IDADIR does not exist: {ida_dir}. Expected dedicated headless IDA 9.4 at {DEFAULT_IDADIR}"
        )


def _enable_diagnostics() -> None:
    try:
        import idapro
        if hasattr(idapro, "enable_console_messages"):
            idapro.enable_console_messages(True)
    except Exception:
        pass


def _wait_for_auto_analysis() -> None:
    import ida_auto
    result = ida_auto.auto_wait()
    if result is False:
        raise RuntimeError("IDA automatic analysis did not complete successfully")


def _initialize_hexrays() -> None:
    import ida_hexrays
    if not ida_hexrays.init_hexrays_plugin():
        raise RuntimeError(
            "Hex-Rays initialization failed. Decompilation is forbidden unless "
            "ida_hexrays.init_hexrays_plugin() succeeds."
        )


@contextmanager
def open_database(
    binary_path: str | os.PathLike[str],
    *,
    save_on_close: bool = True,
) -> Iterator[object]:
    """Open with mandatory automatic analysis and Hex-Rays initialization.

    Invariants are intentionally reasserted for cached databases as well as new databases.
    """
    _ensure_environment()

    from ida_domain import Database
    from ida_domain.database import IdaCommandOptions

    binary = Path(binary_path)
    if not binary.exists():
        raise FileNotFoundError(binary)

    options = IdaCommandOptions(
        auto_analysis=True,
        new_database=not cached_database_exists(binary),
    )

    _enable_diagnostics()
    with Database.open(
        str(binary),
        args=options,
        save_on_close=save_on_close,
    ) as db:
        _wait_for_auto_analysis()
        _initialize_hexrays()
        yield db


def decompile_raw(func_ea: int) -> str:
    """Robust raw Hex-Rays fallback. Must be called inside open_database()."""
    import ida_hexrays

    _wait_for_auto_analysis()
    _initialize_hexrays()

    failure = ida_hexrays.hexrays_failure_t()
    cfunc = ida_hexrays.decompile(func_ea, failure)
    if not cfunc:
        raise RuntimeError(
            f"Hex-Rays decompile failed at 0x{func_ea:x}: "
            f"code={getattr(failure, 'code', None)} "
            f"errea={getattr(failure, 'errea', None)} "
            f"reason={getattr(failure, 'str', '')}"
        )
    return str(cfunc)
