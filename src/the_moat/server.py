"""The Moat HTTP server — /scan API endpoint."""

import time
from typing import Optional

from flask import Flask, jsonify, request

from .classifier import LLMClassifier
from .config import MoatConfig, load_config
from .engine import PatternEngine
from .logger import AuditLogger


def create_app(config: Optional[MoatConfig] = None) -> Flask:
    """Create the Flask app with scanner endpoints."""
    if config is None:
        config = load_config()

    app = Flask(__name__)
    engine = PatternEngine()
    audit = AuditLogger(path=config.logging.path, enabled=config.logging.enabled)

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
            "version": "0.1.0",
            "layer1": config.layer1.enabled,
            "layer2": classifier is not None,
        })

    @app.route("/scan", methods=["POST"])
    def scan():
        start = time.perf_counter()
        data = request.get_json(silent=True) or {}
        text = data.get("text", "")
        source = data.get("source", "")
        url = data.get("url", "")

        if not text:
            return jsonify({
                "verdict": "CLEAN",
                "reason": "empty input",
                "layer": 0,
                "confidence": 1.0,
                "ms": 0.0,
            })

        # Truncate if needed
        if config.layer1.max_content_length and len(text) > config.layer1.max_content_length:
            text = text[:config.layer1.max_content_length]

        # Strip hidden content if configured
        if config.layer1.strip_zero_width:
            text = engine.strip_hidden_content(text)

        # Layer 1: Pattern Engine
        if config.layer1.enabled:
            result = engine.scan(text)
            if result.blocked:
                total_ms = (time.perf_counter() - start) * 1000
                audit.log(
                    text_length=len(text),
                    verdict="BLOCKED",
                    reason=result.reason,
                    layer=1,
                    confidence=1.0,
                    ms=total_ms,
                    source=source,
                    url=url,
                )
                return jsonify({
                    "verdict": "BLOCKED",
                    "reason": result.reason,
                    "layer": 1,
                    "confidence": 1.0,
                    "ms": round(total_ms, 2),
                })

        # Layer 2: LLM Classifier (only if Layer 1 passed)
        if classifier is not None:
            llm_result = classifier.classify(text)
            if llm_result.malicious and llm_result.confidence >= config.layer2.threshold:
                total_ms = (time.perf_counter() - start) * 1000
                audit.log(
                    text_length=len(text),
                    verdict="BLOCKED",
                    reason=f"LLM classifier: {llm_result.reason}",
                    layer=2,
                    confidence=llm_result.confidence,
                    ms=total_ms,
                    source=source,
                    url=url,
                )
                return jsonify({
                    "verdict": "BLOCKED",
                    "reason": f"LLM classifier: {llm_result.reason}",
                    "layer": 2,
                    "confidence": llm_result.confidence,
                    "ms": round(total_ms, 2),
                })

        # Clean
        total_ms = (time.perf_counter() - start) * 1000
        audit.log(
            text_length=len(text),
            verdict="CLEAN",
            reason="",
            layer=2 if classifier else 1,
            confidence=1.0,
            ms=total_ms,
            source=source,
            url=url,
        )
        return jsonify({
            "verdict": "CLEAN",
            "reason": "",
            "layer": 2 if classifier else 1,
            "confidence": 1.0,
            "ms": round(total_ms, 2),
        })

    return app


def run_server(config: Optional[MoatConfig] = None):
    """Run the server."""
    if config is None:
        config = load_config()
    app = create_app(config)
    app.run(host=config.server.host, port=config.server.port)
