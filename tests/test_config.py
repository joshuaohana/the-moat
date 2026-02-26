"""Tests for configuration loading."""

import os
import tempfile

import pytest
from the_moat.config import MoatConfig, load_config


class TestConfigDefaults:
    def test_default_config(self):
        cfg = MoatConfig()
        assert cfg.server.host == "127.0.0.1"
        assert cfg.server.port == 9999
        assert cfg.layer1.enabled is True
        assert cfg.layer2.enabled is True
        assert cfg.layer2.model == "gpt-4.1-nano"
        assert cfg.on_suspect == "block"

    def test_load_missing_file(self):
        cfg = load_config("/nonexistent/moat.yaml")
        assert cfg.server.port == 9999  # Falls back to defaults


class TestConfigFromYAML:
    def test_load_custom_config(self):
        yaml_content = """
server:
  host: 0.0.0.0
  port: 8080

scanner:
  layer1:
    enabled: true
    max_content_length: 50000
  layer2:
    enabled: false
    model: gpt-4.1-mini

on_suspect: quarantine

bridges:
  - "owner:*"
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(yaml_content)
            f.flush()
            cfg = load_config(f.name)

        os.unlink(f.name)

        assert cfg.server.host == "0.0.0.0"
        assert cfg.server.port == 8080
        assert cfg.layer1.max_content_length == 50000
        assert cfg.layer2.enabled is False
        assert cfg.layer2.model == "gpt-4.1-mini"
        assert cfg.on_suspect == "quarantine"
        assert cfg.bridges == ["owner:*"]

    def test_load_empty_yaml(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write("")
            f.flush()
            cfg = load_config(f.name)

        os.unlink(f.name)
        assert cfg.server.port == 9999  # Defaults
