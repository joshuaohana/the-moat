"""Layer 1: Pattern Engine — deterministic regex-based scanning + sanitization."""

import json
import re
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional


class Verdict(str, Enum):
    ALLOW = "ALLOW"
    SANITIZE = "SANITIZE"
    BLOCK = "BLOCK"


HARD_BLOCK_PATTERN_IDS = {
    "FMT-001",   # format marker injection tokens
    "HIDDEN-001",  # zero-width / hidden unicode markers
    "CRED-001",  # obvious API key/token material
    "CRED-002",  # private key blocks
}

HARD_BLOCK_CATEGORIES = {"credential"}


@dataclass
class Finding:
    pattern_id: str
    category: str
    severity: str
    name: str
    match: str
    start: int
    end: int
    hard_block: bool


@dataclass
class ScanResult:
    verdict: Verdict
    reason: str = ""
    pattern_id: str = ""
    category: str = ""
    severity: str = ""
    findings: list[Finding] = field(default_factory=list)
    categories: list[str] = field(default_factory=list)
    sanitized_text: Optional[str] = None
    ms: float = 0.0

    @property
    def blocked(self) -> bool:
        """Legacy compatibility."""
        return self.verdict == Verdict.BLOCK


@dataclass
class Pattern:
    id: str
    name: str
    category: str
    severity: str
    regex: re.Pattern
    description: str = ""


class PatternEngine:
    """Regex-based content scanner. Runs quickly. Cannot be prompt-injected."""

    def __init__(self, rules_path: Optional[str] = None):
        self.patterns: list[Pattern] = []
        if rules_path is None:
            # Try package-internal rules first, then fall back to repo root
            pkg_rules = Path(__file__).parent / "rules" / "patterns.json"
            repo_rules = Path(__file__).parent.parent.parent / "rules" / "patterns.json"
            rules_path = str(pkg_rules if pkg_rules.exists() else repo_rules)
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

    def _is_hard_block(self, pattern: Pattern) -> bool:
        return pattern.id in HARD_BLOCK_PATTERN_IDS or pattern.category in HARD_BLOCK_CATEGORIES

    def _sanitize_text(self, text: str, findings: list[Finding]) -> str:
        if not findings:
            return text

        # Non-overlapping spans; prefer earlier spans, longer first when same start.
        ordered = sorted(findings, key=lambda f: (f.start, -(f.end - f.start)))
        merged: list[Finding] = []
        last_end = -1
        for finding in ordered:
            if finding.start >= last_end:
                merged.append(finding)
                last_end = finding.end

        out: list[str] = []
        cursor = 0
        for finding in merged:
            out.append(text[cursor:finding.start])
            out.append(f"[REDACTED:{finding.category}]")
            cursor = finding.end
        out.append(text[cursor:])
        return "".join(out)

    def scan(self, text: str) -> ScanResult:
        """Scan text against all patterns and produce ALLOW/SANITIZE/BLOCK."""
        start = time.perf_counter()

        if not text or not text.strip():
            elapsed = (time.perf_counter() - start) * 1000
            return ScanResult(verdict=Verdict.ALLOW, ms=elapsed)

        findings: list[Finding] = []
        for pattern in self.patterns:
            for match in pattern.regex.finditer(text):
                findings.append(Finding(
                    pattern_id=pattern.id,
                    category=pattern.category,
                    severity=pattern.severity,
                    name=pattern.name,
                    match=match.group(),
                    start=match.start(),
                    end=match.end(),
                    hard_block=self._is_hard_block(pattern),
                ))

        elapsed = (time.perf_counter() - start) * 1000

        if not findings:
            return ScanResult(verdict=Verdict.ALLOW, ms=elapsed)

        categories = sorted({f.category for f in findings})
        sanitized_text = self._sanitize_text(text, findings)
        first = findings[0]

        if any(f.hard_block for f in findings):
            reason = f"{first.category}: {first.name} — matched '{first.match}'"
            return ScanResult(
                verdict=Verdict.BLOCK,
                reason=reason,
                pattern_id=first.pattern_id,
                category=first.category,
                severity=first.severity,
                findings=findings,
                categories=categories,
                sanitized_text=sanitized_text,
                ms=elapsed,
            )

        reason = f"Sanitized {len(findings)} risky span(s)"
        return ScanResult(
            verdict=Verdict.SANITIZE,
            reason=reason,
            pattern_id=first.pattern_id,
            category=first.category,
            severity=first.severity,
            findings=findings,
            categories=categories,
            sanitized_text=sanitized_text,
            ms=elapsed,
        )

    def strip_hidden_content(self, text: str) -> str:
        """Remove zero-width characters and other hidden content."""
        # Zero-width characters
        zero_width = re.compile(r'[\u200b\u200c\u200d\u2060\ufeff\u00ad\u200e\u200f\u202a-\u202e\u2066-\u2069]')
        return zero_width.sub('', text)
