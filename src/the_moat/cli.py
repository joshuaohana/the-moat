"""CLI for The Moat."""

import json
import os
import signal
import sys

import click

from .config import load_config
from .engine import PatternEngine
from .logger import AuditLogger


PID_DIR = os.path.expanduser("~/.moat")
PID_FILE = os.path.join(PID_DIR, "moat.pid")


@click.group()
def main():
    """🏰 The Moat — The firewall for AI agents."""
    pass


@main.command()
@click.option("--config", "-c", default=None, help="Path to moat.yaml")
@click.option("--host", "-h", default=None, help="Host to bind to")
@click.option("--port", "-p", default=None, type=int, help="Port to listen on")
def start(config, host, port):
    """Start The Moat scanner server."""
    cfg = load_config(config)
    if host:
        cfg.server.host = host
    if port:
        cfg.server.port = port

    # Write PID file
    os.makedirs(PID_DIR, exist_ok=True)
    with open(PID_FILE, "w") as f:
        f.write(str(os.getpid()))

    click.echo(f"🏰 The Moat starting on {cfg.server.host}:{cfg.server.port}")
    click.echo(f"   Layer 1 (Pattern Engine): {'enabled' if cfg.layer1.enabled else 'disabled'}")
    click.echo(f"   Layer 2 (LLM Classifier): {'enabled' if cfg.layer2.enabled else 'disabled'}")
    click.echo(f"   Audit log: {cfg.logging.path if cfg.logging.enabled else 'disabled'}")
    click.echo()

    from .server import run_server
    try:
        run_server(cfg)
    finally:
        if os.path.exists(PID_FILE):
            os.remove(PID_FILE)


@main.command()
def stop():
    """Stop The Moat scanner server."""
    if not os.path.exists(PID_FILE):
        click.echo("The Moat is not running (no PID file)")
        return

    with open(PID_FILE) as f:
        pid = int(f.read().strip())

    try:
        os.kill(pid, signal.SIGTERM)
        click.echo(f"🏰 The Moat stopped (PID {pid})")
    except ProcessLookupError:
        click.echo(f"Process {pid} not found (stale PID file)")
    finally:
        if os.path.exists(PID_FILE):
            os.remove(PID_FILE)


@main.command()
def status():
    """Check if The Moat is running."""
    if not os.path.exists(PID_FILE):
        click.echo("🏰 The Moat is not running")
        sys.exit(1)

    with open(PID_FILE) as f:
        pid = int(f.read().strip())

    try:
        os.kill(pid, 0)  # Check if process exists
        click.echo(f"🏰 The Moat is running (PID {pid})")

        # Try health check
        try:
            import urllib.request
            cfg = load_config()
            url = f"http://{cfg.server.host}:{cfg.server.port}/health"
            with urllib.request.urlopen(url, timeout=2) as resp:
                data = json.loads(resp.read())
                click.echo(f"   Version: {data.get('version', '?')}")
                click.echo(f"   Layer 1: {'✅' if data.get('layer1') else '❌'}")
                click.echo(f"   Layer 2: {'✅' if data.get('layer2') else '❌'}")
        except Exception:
            pass
    except ProcessLookupError:
        click.echo(f"🏰 The Moat is not running (stale PID {pid})")
        os.remove(PID_FILE)
        sys.exit(1)


@main.command()
@click.argument("text")
def scan(text):
    """Scan text from the command line."""
    engine = PatternEngine()
    result = engine.scan(text)

    if result.blocked:
        click.echo(f"🚫 BLOCKED (Layer 1, {result.ms:.1f}ms)")
        click.echo(f"   Reason: {result.reason}")
        click.echo(f"   Pattern: {result.pattern_id}")
        sys.exit(1)
    else:
        click.echo(f"✅ CLEAN (Layer 1, {result.ms:.1f}ms)")
        click.echo("   No patterns matched")


@main.command()
@click.option("--lines", "-n", default=20, help="Number of lines to show")
def log(lines):
    """View recent audit log entries."""
    cfg = load_config()
    audit = AuditLogger(path=cfg.logging.path)
    entries = audit.tail(lines)

    if not entries:
        click.echo("No log entries found")
        return

    for entry in entries:
        verdict = "🚫" if entry.get("verdict") == "BLOCKED" else "✅"
        click.echo(
            f"{verdict} [{entry.get('timestamp', '?')[:19]}] "
            f"L{entry.get('layer', '?')} {entry.get('verdict', '?')} "
            f"({entry.get('ms', 0):.1f}ms) "
            f"{entry.get('reason', '')[:60]}"
        )


if __name__ == "__main__":
    main()
