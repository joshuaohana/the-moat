"""The Moat HTTP server — /scan API endpoint."""

import time
from collections import defaultdict
from typing import Optional

from flask import Flask, jsonify, request

from . import __version__
from .classifier import LLMClassifier
from .config import MoatConfig, load_config
from .engine import PatternEngine, Verdict
from .logger import AuditLogger


# Simple in-memory rate limiter
class RateLimiter:
    def __init__(self, max_requests: int = 100, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window = window_seconds
        self._hits: dict[str, list[float]] = defaultdict(list)

    def is_allowed(self, key: str) -> bool:
        now = time.time()
        hits = self._hits.get(key, [])
        # Prune old entries and clean up empty keys (prevent memory leak)
        current = [t for t in hits if now - t < self.window]
        if not current:
            self._hits.pop(key, None)
        else:
            self._hits[key] = current
        if len(current) >= self.max_requests:
            return False
        self._hits.setdefault(key, []).append(now)
        return True


def _legacy_verdict(verdict: Verdict) -> str:
    if verdict == Verdict.BLOCK:
        return "BLOCKED"
    return "CLEAN"


def _serialize_findings(findings):
    return [
        {
            "pattern_id": f.pattern_id,
            "category": f.category,
            "severity": f.severity,
            "name": f.name,
            "match": f.match,
            "start": f.start,
            "end": f.end,
            "hard_block": f.hard_block,
        }
        for f in findings
    ]


def create_app(config: Optional[MoatConfig] = None) -> Flask:
    """Create the Flask app with scanner endpoints."""
    if config is None:
        config = load_config()

    app = Flask(__name__)
    engine = PatternEngine()
    audit = AuditLogger(path=config.logging.path, enabled=config.logging.enabled)
    limiter = RateLimiter(max_requests=100, window_seconds=60)

    classifier = None
    if config.layer2.enabled:
        import os
        api_key = os.environ.get(config.layer2.api_key_env)
        if api_key:
            classifier = LLMClassifier(
                model=config.layer2.model,
                api_key=api_key,
                timeout=config.layer2.timeout_ms / 1000,
                max_chars=config.layer2.max_scan_length,
                threshold=config.layer2.threshold,
            )

    @app.route("/health", methods=["GET"])
    def health():
        return jsonify({
            "status": "ok",
            "version": __version__,
            "layer1": config.layer1.enabled,
            "layer2": classifier is not None,
        })

    @app.route("/scan", methods=["POST"])
    def scan():
        # Rate limiting
        client_ip = request.remote_addr or "unknown"
        if not limiter.is_allowed(client_ip):
            return jsonify({"error": "rate limit exceeded", "retry_after_seconds": 60}), 429

        start = time.perf_counter()
        data = request.get_json(silent=True) or {}
        text = data.get("text", "")
        source = data.get("source", "")
        url = data.get("url", "")

        if not text:
            return jsonify({
                "verdict": Verdict.ALLOW.value,
                "legacy_verdict": "CLEAN",
                "blocked": False,
                "reason": "empty input",
                "layer": 0,
                "confidence": 1.0,
                "findings": [],
                "categories": [],
                "sanitized_text": None,
                "ms": 0.0,
            })

        # Truncate if needed
        if config.layer1.max_content_length and len(text) > config.layer1.max_content_length:
            text = text[:config.layer1.max_content_length]

        # Strip hidden content if configured
        if config.layer1.strip_zero_width:
            text = engine.strip_hidden_content(text)

        result = engine.scan(text) if config.layer1.enabled else None

        if result is None:
            verdict = Verdict.ALLOW
            reason = ""
            findings = []
            categories = []
            sanitized_text = None
            layer = 1
            confidence = 1.0
        else:
            verdict = result.verdict
            reason = result.reason
            findings = result.findings
            categories = result.categories
            sanitized_text = result.sanitized_text if verdict != Verdict.ALLOW else None
            layer = 1
            confidence = 1.0

        # Hard-block always from layer 1.
        if verdict == Verdict.BLOCK:
            total_ms = (time.perf_counter() - start) * 1000
            audit.log(
                text_length=len(text),
                verdict=verdict.value,
                reason=reason,
                layer=1,
                confidence=confidence,
                ms=total_ms,
                source=source,
                url=url,
            )
            return jsonify({
                "verdict": verdict.value,
                "legacy_verdict": _legacy_verdict(verdict),
                "blocked": True,
                "reason": reason,
                "layer": 1,
                "confidence": confidence,
                "findings": _serialize_findings(findings),
                "categories": categories,
                "sanitized_text": sanitized_text,
                "ms": round(total_ms, 2),
            })

        # Layer 2: Optional classifier can refine ALLOW/SANITIZE/BLOCK with rationale.
        llm_meta = None
        if classifier is not None:
            llm_result = classifier.classify(text)
            llm_meta = {
                "verdict": llm_result.verdict.value,
                "confidence": llm_result.confidence,
                "reason": llm_result.reason,
                "error": llm_result.error,
            }

            # Deterministic override policy:
            # - high-confidence BLOCK is allowed to upgrade
            # - SANITIZE can upgrade ALLOW at threshold
            # - ALLOW can de-escalate SANITIZE at threshold
            if llm_result.verdict == Verdict.BLOCK and llm_result.confidence >= config.layer2.threshold:
                verdict = Verdict.BLOCK
                reason = f"LLM classifier: {llm_result.reason}"
                layer = 2
                confidence = llm_result.confidence
            elif llm_result.verdict == Verdict.SANITIZE and llm_result.confidence >= config.layer2.threshold and verdict == Verdict.ALLOW:
                verdict = Verdict.SANITIZE
                reason = f"LLM classifier: {llm_result.reason}"
                layer = 2
                confidence = llm_result.confidence
                sanitized_text = sanitized_text or text
            elif llm_result.verdict == Verdict.ALLOW and llm_result.confidence >= config.layer2.threshold and verdict == Verdict.SANITIZE:
                verdict = Verdict.ALLOW
                reason = f"LLM classifier: {llm_result.reason}"
                layer = 2
                confidence = llm_result.confidence
                sanitized_text = None

        total_ms = (time.perf_counter() - start) * 1000
        audit.log(
            text_length=len(text),
            verdict=verdict.value,
            reason=reason,
            layer=layer,
            confidence=confidence,
            ms=total_ms,
            source=source,
            url=url,
        )
        response = {
            "verdict": verdict.value,
            "legacy_verdict": _legacy_verdict(verdict),
            "blocked": verdict == Verdict.BLOCK,
            "reason": reason,
            "layer": layer,
            "confidence": confidence,
            "findings": _serialize_findings(findings),
            "categories": categories,
            "sanitized_text": sanitized_text,
            "ms": round(total_ms, 2),
        }
        if llm_meta is not None:
            response["llm"] = llm_meta
        return jsonify(response)

    return app


def run_server(config: Optional[MoatConfig] = None):
    """Run the server."""
    if config is None:
        config = load_config()
    app = create_app(config)
    app.run(host=config.server.host, port=config.server.port)
