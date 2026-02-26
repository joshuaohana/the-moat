"""Audit logging for The Moat — structured JSON logs."""

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


class AuditLogger:
    """Append-only JSON audit log for scan decisions."""

    def __init__(self, path: str = "./moat.log", enabled: bool = True):
        self.path = path
        self.enabled = enabled
        if enabled:
            Path(path).parent.mkdir(parents=True, exist_ok=True)

    def log(
        self,
        text_length: int,
        verdict: str,
        reason: str = "",
        layer: int = 0,
        confidence: float = 0.0,
        ms: float = 0.0,
        source: str = "",
        url: str = "",
    ) -> None:
        if not self.enabled:
            return

        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "text_length": text_length,
            "verdict": verdict,
            "reason": reason,
            "layer": layer,
            "confidence": confidence,
            "ms": round(ms, 2),
            "source": source,
            "url": url,
        }

        try:
            with open(self.path, "a") as f:
                f.write(json.dumps(entry) + "\n")
        except OSError:
            pass  # Don't crash on logging failure

    def tail(self, n: int = 20) -> list[dict]:
        """Read the last n log entries."""
        if not os.path.exists(self.path):
            return []

        try:
            with open(self.path) as f:
                lines = f.readlines()
            entries = []
            for line in lines[-n:]:
                try:
                    entries.append(json.loads(line.strip()))
                except json.JSONDecodeError:
                    continue
            return entries
        except OSError:
            return []
