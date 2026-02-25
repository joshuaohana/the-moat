"""Tests for the audit logger."""

import json
import os
import tempfile

import pytest
from the_moat.logger import AuditLogger


class TestAuditLogger:
    def test_log_entry(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
            path = f.name

        logger = AuditLogger(path=path)
        logger.log(text_length=100, verdict="BLOCKED", reason="test", layer=1)

        with open(path) as f:
            line = f.readline()
            entry = json.loads(line)

        os.unlink(path)

        assert entry["verdict"] == "BLOCKED"
        assert entry["reason"] == "test"
        assert entry["layer"] == 1
        assert entry["text_length"] == 100
        assert "timestamp" in entry

    def test_tail(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
            path = f.name

        logger = AuditLogger(path=path)
        for i in range(5):
            logger.log(text_length=i * 10, verdict="CLEAN", layer=1)

        entries = logger.tail(3)
        os.unlink(path)

        assert len(entries) == 3
        assert entries[-1]["text_length"] == 40

    def test_disabled_logger(self):
        logger = AuditLogger(path="/tmp/should-not-exist.log", enabled=False)
        logger.log(text_length=100, verdict="BLOCKED")
        assert not os.path.exists("/tmp/should-not-exist.log")

    def test_tail_missing_file(self):
        logger = AuditLogger(path="/tmp/definitely-not-here-12345.log", enabled=False)
        assert logger.tail() == []
