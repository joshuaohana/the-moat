"""Layer 1: Pattern Engine — deterministic regex-based scanning."""

import json
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


@dataclass
class ScanResult:
    blocked: bool
    reason: str = ""
    pattern_id: str = ""
    category: str = ""
    severity: str = ""
    ms: float = 0.0


@dataclass
class Pattern:
    id: str
    name: str
    category: str
    severity: str
    regex: re.Pattern
    description: str = ""


class PatternEngine:
    """Regex-based content scanner. Runs in <1ms. Cannot be prompt-injected."""

    def __init__(self, rules_path: Optional[str] = None):
        self.patterns: list[Pattern] = []
        if rules_path is None:
            rules_path = str(Path(__file__).parent.parent.parent / "rules" / "patterns.json")
        self.load_rules(rules_path)

    def load_rules(self, path: str) -> None:
        """Load pattern rules from a JSON file."""
        with open(path) as f:
            rules = json.load(f)

        self.patterns = []
        for rule in rules:
            flags = 0
            if "IGNORECASE" in rule.get("flags", ""):
                flags |= re.IGNORECASE
            try:
                compiled = re.compile(rule["pattern"], flags)
            except re.error as e:
                print(f"Warning: Failed to compile pattern {rule['id']}: {e}")
                continue

            self.patterns.append(Pattern(
                id=rule["id"],
                name=rule["name"],
                category=rule["category"],
                severity=rule["severity"],
                regex=compiled,
            ))

    def scan(self, text: str) -> ScanResult:
        """Scan text against all patterns. Returns on first match."""
        start = time.perf_counter()

        if not text or not text.strip():
            elapsed = (time.perf_counter() - start) * 1000
            return ScanResult(blocked=False, ms=elapsed)

        for pattern in self.patterns:
            match = pattern.regex.search(text)
            if match:
                elapsed = (time.perf_counter() - start) * 1000
                return ScanResult(
                    blocked=True,
                    reason=f"{pattern.category}: {pattern.name} — matched '{match.group()}'",
                    pattern_id=pattern.id,
                    category=pattern.category,
                    severity=pattern.severity,
                    ms=elapsed,
                )

        elapsed = (time.perf_counter() - start) * 1000
        return ScanResult(blocked=False, ms=elapsed)

    def strip_hidden_content(self, text: str) -> str:
        """Remove zero-width characters and other hidden content."""
        # Zero-width characters
        zero_width = re.compile(r'[\u200b\u200c\u200d\u2060\ufeff\u00ad\u200e\u200f\u202a-\u202e\u2066-\u2069]')
        return zero_width.sub('', text)
