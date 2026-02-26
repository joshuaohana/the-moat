"""Configuration loader for The Moat."""

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import yaml


@dataclass
class Layer1Config:
    enabled: bool = True
    strip_hidden_text: bool = True
    strip_zero_width: bool = True
    max_content_length: int = 100000


@dataclass
class Layer2Config:
    enabled: bool = True
    provider: str = "openai"
    model: str = "gpt-4.1-nano"
    api_key_env: str = "OPENAI_API_KEY"
    threshold: float = 0.85
    timeout_ms: int = 3000
    max_scan_length: int = 2048


@dataclass
class LoggingConfig:
    enabled: bool = True
    format: str = "json"
    path: str = "./moat.log"


@dataclass
class ServerConfig:
    host: str = "127.0.0.1"
    port: int = 9999


@dataclass
class ProxyConfig:
    bind: str = "127.0.0.1"
    port: int = 9998
    connect_timeout_seconds: float = 10.0
    read_timeout_seconds: float = 30.0
    write_timeout_seconds: float = 30.0
    max_scan_body_bytes: int = 1024 * 1024
    log_https_connect: bool = True


@dataclass
class MoatConfig:
    bridges: list[str] = field(default_factory=lambda: ["owner:*", "workspace:*", "internal:*"])
    layer1: Layer1Config = field(default_factory=Layer1Config)
    layer2: Layer2Config = field(default_factory=Layer2Config)
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    server: ServerConfig = field(default_factory=ServerConfig)
    proxy: ProxyConfig = field(default_factory=ProxyConfig)
    on_suspect: str = "block"


def load_config(path: Optional[str] = None) -> MoatConfig:
    """Load config from moat.yaml. Returns defaults if file doesn't exist."""
    if path is None:
        path = os.environ.get("MOAT_CONFIG", "moat.yaml")

    config_path = Path(path)
    if not config_path.exists():
        return MoatConfig()

    with open(config_path) as f:
        raw = yaml.safe_load(f) or {}

    cfg = MoatConfig()

    if "bridges" in raw:
        cfg.bridges = raw["bridges"]

    if "scanner" in raw:
        scanner = raw["scanner"]
        if "layer1" in scanner:
            for k, v in scanner["layer1"].items():
                if hasattr(cfg.layer1, k):
                    setattr(cfg.layer1, k, v)
        if "layer2" in scanner:
            for k, v in scanner["layer2"].items():
                if hasattr(cfg.layer2, k):
                    setattr(cfg.layer2, k, v)

    if "logging" in raw:
        for k, v in raw["logging"].items():
            if hasattr(cfg.logging, k):
                setattr(cfg.logging, k, v)

    if "server" in raw:
        for k, v in raw["server"].items():
            if hasattr(cfg.server, k):
                setattr(cfg.server, k, v)

    if "proxy" in raw:
        for k, v in raw["proxy"].items():
            if hasattr(cfg.proxy, k):
                setattr(cfg.proxy, k, v)

    if "on_suspect" in raw:
        cfg.on_suspect = raw["on_suspect"]

    return cfg
