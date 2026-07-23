"""Subprocess runner for the external Android toolchain.

Centralises how the pipeline invokes apktool / jadx / aapt2 / apksigner /
dexdump / strings so that:
  * missing tools degrade to a recorded, non-fatal skip rather than crashing
    the whole analysis,
  * every invocation is bounded by a wall-clock timeout,
  * stdout/stderr and exit status are captured for logging & metadata.
"""
from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from app.core.config import settings
from app.core.logging import get_logger

log = get_logger("pipeline.tools")


@dataclass
class ToolResult:
    tool: str
    ok: bool
    returncode: int | None
    stdout: str
    stderr: str
    skipped: bool = False
    reason: str | None = None

    @property
    def available(self) -> bool:
        return not self.skipped


def tool_available(binary: str) -> bool:
    """True if ``binary`` is resolvable on PATH (or is an absolute path)."""
    if Path(binary).is_absolute():
        return Path(binary).exists()
    return shutil.which(binary) is not None


def run_tool(binary: str, args: list[str], *,
             cwd: Path | None = None,
             timeout: int | None = None,
             input_text: str | None = None) -> ToolResult:
    """Run ``binary args`` and capture the result.

    Never raises on non-zero exit or a missing tool — inspect ``ok`` /
    ``skipped`` on the returned :class:`ToolResult`.
    """
    if not tool_available(binary):
        log.warning("tool unavailable, skipping: %s", binary)
        return ToolResult(tool=binary, ok=False, returncode=None, stdout="",
                          stderr="", skipped=True,
                          reason=f"{binary} not installed")

    cmd = [binary, *args]
    log.info("run: %s", " ".join(cmd))
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(cwd) if cwd else None,
            capture_output=True,
            text=True,
            timeout=timeout or settings.tool_timeout_seconds,
            input=input_text,
            check=False,
        )
    except subprocess.TimeoutExpired:
        log.error("timeout: %s", binary)
        return ToolResult(tool=binary, ok=False, returncode=None, stdout="",
                          stderr="timeout", skipped=False,
                          reason="timed out")
    except Exception as exc:  # noqa: BLE001
        log.exception("tool error: %s", binary)
        return ToolResult(tool=binary, ok=False, returncode=None, stdout="",
                          stderr=str(exc), skipped=False, reason=str(exc))

    ok = proc.returncode == 0
    if not ok:
        log.warning("%s exited %s: %s", binary, proc.returncode,
                    proc.stderr[:300])
    return ToolResult(tool=binary, ok=ok, returncode=proc.returncode,
                      stdout=proc.stdout, stderr=proc.stderr)
