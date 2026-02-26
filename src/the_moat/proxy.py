"""Transparent HTTP forward proxy for The Moat."""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import time
from dataclasses import dataclass
from typing import Optional

import httpx

from .config import MoatConfig, load_config
from .engine import PatternEngine, Verdict


LOG = logging.getLogger("the_moat.proxy")
AUDIT = logging.getLogger("the_moat.proxy.audit")

HOP_BY_HOP_HEADERS = {
    "connection",
    "proxy-connection",
    "keep-alive",
    "transfer-encoding",
    "upgrade",
    "te",
    "trailer",
    "proxy-authenticate",
    "proxy-authorization",
}


@dataclass
class ProxyResponse:
    status_code: int
    reason: str
    headers: dict[str, str]
    body: bytes


class MoatProxy:
    def __init__(self, config: Optional[MoatConfig] = None):
        self.config = config or load_config()
        self.engine = PatternEngine()
        self._server: Optional[asyncio.base_events.Server] = None

        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(
                connect=self.config.proxy.connect_timeout_seconds,
                read=self.config.proxy.read_timeout_seconds,
                write=self.config.proxy.write_timeout_seconds,
                pool=self.config.proxy.connect_timeout_seconds,
            ),
            follow_redirects=True,
        )

    async def close(self):
        await self._client.aclose()
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()

    async def run_forever(self):
        self._server = await asyncio.start_server(
            self._handle_client,
            host=self.config.proxy.bind,
            port=self.config.proxy.port,
        )
        LOG.info("Proxy listening on %s:%s", self.config.proxy.bind, self.config.proxy.port)
        async with self._server:
            await self._server.serve_forever()

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        start = time.perf_counter()
        peer = writer.get_extra_info("peername")
        client_ip = peer[0] if peer else "unknown"
        method = "UNKNOWN"
        destination = "unknown"
        verdict = "PASS_THROUGH"
        categories: list[str] = []

        try:
            line = await reader.readline()
            if not line:
                writer.close()
                await writer.wait_closed()
                return

            reqline = line.decode("latin-1", errors="replace").strip()
            parts = reqline.split(" ", 2)
            if len(parts) != 3:
                raise ValueError("malformed request line")
            method, target, _version = parts
            destination = target

            headers = await self._read_headers(reader)

            if method.upper() == "CONNECT":
                destination = target if self.config.proxy.log_https_connect else "<connect-hidden>"
                verdict = "CONNECT_TUNNEL"
                await self._handle_connect(target, reader, writer)
                return

            body = b""
            content_length = int(headers.get("content-length", "0") or "0")
            if content_length > 0:
                body = await reader.readexactly(content_length)

            url = self._build_target_url(target, headers)
            destination = url

            response, verdict, categories = await self._proxy_http(method, url, headers, body)
            await self._write_response(writer, response)
        except httpx.HTTPError as exc:
            response = self._bad_gateway(f"Upstream request failed: {exc}")
            verdict = "ERROR"
            await self._write_response(writer, response)
        except (ConnectionError, OSError, ValueError, asyncio.IncompleteReadError) as exc:
            response = self._bad_gateway(f"Proxy request failed: {exc}")
            verdict = "ERROR"
            try:
                await self._write_response(writer, response)
            except Exception:
                pass
        finally:
            elapsed_ms = (time.perf_counter() - start) * 1000
            self._audit_log(
                client_ip=client_ip,
                method=method,
                destination=destination,
                verdict=verdict,
                categories=categories,
                elapsed_ms=elapsed_ms,
            )
            if not writer.is_closing():
                writer.close()
                with contextlib.suppress(Exception):
                    await writer.wait_closed()

    async def _handle_connect(
        self,
        target: str,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
    ):
        if ":" not in target:
            raise ValueError("CONNECT target must be host:port")
        host, port_str = target.rsplit(":", 1)
        port = int(port_str)

        upstream_reader, upstream_writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=self.config.proxy.connect_timeout_seconds,
        )

        client_writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        await client_writer.drain()

        async def pipe(src: asyncio.StreamReader, dst: asyncio.StreamWriter):
            try:
                while not src.at_eof():
                    chunk = await src.read(16384)
                    if not chunk:
                        break
                    dst.write(chunk)
                    await dst.drain()
            finally:
                if not dst.is_closing():
                    dst.close()

        await asyncio.gather(pipe(client_reader, upstream_writer), pipe(upstream_reader, client_writer))

    async def _proxy_http(
        self,
        method: str,
        url: str,
        headers: dict[str, str],
        body: bytes,
    ) -> tuple[ProxyResponse, str, list[str]]:
        upstream_headers = {
            k: v
            for k, v in headers.items()
            if k.lower() not in HOP_BY_HOP_HEADERS and not k.lower().startswith("proxy-")
        }

        upstream = await self._client.request(method, url, headers=upstream_headers, content=body)

        resp_headers = {
            k: v
            for k, v in upstream.headers.items()
            if k.lower() not in HOP_BY_HOP_HEADERS
        }

        def set_header(name: str, value: str):
            for existing in list(resp_headers.keys()):
                if existing.lower() == name.lower():
                    resp_headers.pop(existing, None)
            resp_headers[name] = value
        response_body = upstream.content

        if not self._is_scannable(upstream.headers.get("content-type", "")):
            return (
                ProxyResponse(upstream.status_code, upstream.reason_phrase, resp_headers, response_body),
                "BINARY_PASS",
                [],
            )

        if len(response_body) > self.config.proxy.max_scan_body_bytes:
            LOG.warning(
                "Response body too large for scanning (%s bytes > %s), passing through",
                len(response_body),
                self.config.proxy.max_scan_body_bytes,
            )
            return (
                ProxyResponse(upstream.status_code, upstream.reason_phrase, resp_headers, response_body),
                "TOO_LARGE_PASS",
                [],
            )

        text = self._decode_text(response_body, upstream.headers.get("content-type", ""))
        if text is None:
            return (
                ProxyResponse(upstream.status_code, upstream.reason_phrase, resp_headers, response_body),
                "BINARY_PASS",
                [],
            )

        scan = self.engine.scan(text)
        categories = scan.categories

        if scan.verdict == Verdict.BLOCK:
            block_body = self._render_block_page(scan.reason, categories).encode("utf-8")
            block_headers = {
                "Content-Type": "text/html; charset=utf-8",
                "Content-Length": str(len(block_body)),
                "Connection": "close",
            }
            return ProxyResponse(403, "Forbidden", block_headers, block_body), "BLOCK", categories

        if scan.verdict == Verdict.SANITIZE:
            sanitized = (scan.sanitized_text or text).encode("utf-8")
            set_header("Content-Length", str(len(sanitized)))
            set_header("Content-Type", "text/plain; charset=utf-8")
            return (
                ProxyResponse(upstream.status_code, upstream.reason_phrase, resp_headers, sanitized),
                "SANITIZE",
                categories,
            )

        set_header("Content-Length", str(len(response_body)))
        return (
            ProxyResponse(upstream.status_code, upstream.reason_phrase, resp_headers, response_body),
            "ALLOW",
            categories,
        )

    async def _read_headers(self, reader: asyncio.StreamReader) -> dict[str, str]:
        headers: dict[str, str] = {}
        while True:
            line = await reader.readline()
            if line in (b"\r\n", b"\n", b""):
                break
            text = line.decode("latin-1", errors="replace")
            if ":" not in text:
                continue
            key, value = text.split(":", 1)
            headers[key.strip().lower()] = value.strip()
        return headers

    def _build_target_url(self, target: str, headers: dict[str, str]) -> str:
        if target.startswith("http://") or target.startswith("https://"):
            return target
        host = headers.get("host", "")
        if not host:
            raise ValueError("missing Host header")
        path = target if target.startswith("/") else f"/{target}"
        return f"http://{host}{path}"

    async def _write_response(self, writer: asyncio.StreamWriter, response: ProxyResponse):
        status_line = f"HTTP/1.1 {response.status_code} {response.reason}\r\n"
        writer.write(status_line.encode("latin-1"))
        for key, value in response.headers.items():
            writer.write(f"{key}: {value}\r\n".encode("latin-1"))
        writer.write(b"\r\n")
        writer.write(response.body)
        await writer.drain()

    def _is_scannable(self, content_type: str) -> bool:
        ct = content_type.lower()
        return (
            ct.startswith("text/")
            or "json" in ct
            or "xml" in ct
            or "javascript" in ct
            or "x-www-form-urlencoded" in ct
            or ct == ""
        )

    def _decode_text(self, payload: bytes, content_type: str) -> Optional[str]:
        charset = "utf-8"
        parts = [p.strip() for p in content_type.split(";")]
        for part in parts[1:]:
            if part.lower().startswith("charset="):
                charset = part.split("=", 1)[1].strip()
                break
        try:
            return payload.decode(charset)
        except (LookupError, UnicodeDecodeError):
            return None

    def _render_block_page(self, reason: str, categories: list[str]) -> str:
        cats = ", ".join(categories) if categories else "unknown"
        return (
            "<html><head><title>The Moat blocked content</title></head>"
            "<body><h1>Blocked by The Moat</h1>"
            "<p>The response was blocked because it matched a high-risk pattern.</p>"
            f"<p><strong>Reason:</strong> {reason}</p>"
            f"<p><strong>Categories:</strong> {cats}</p>"
            "</body></html>"
        )

    def _bad_gateway(self, message: str) -> ProxyResponse:
        body = (
            "<html><head><title>502 Bad Gateway</title></head>"
            "<body><h1>The Moat proxy could not reach the destination</h1>"
            f"<p>{message}</p></body></html>"
        ).encode("utf-8")
        return ProxyResponse(
            status_code=502,
            reason="Bad Gateway",
            headers={
                "Content-Type": "text/html; charset=utf-8",
                "Content-Length": str(len(body)),
                "Connection": "close",
            },
            body=body,
        )

    def _audit_log(
        self,
        client_ip: str,
        method: str,
        destination: str,
        verdict: str,
        categories: list[str],
        elapsed_ms: float,
    ):
        event = {
            "event": "proxy_request",
            "client_ip": client_ip,
            "method": method,
            "destination": destination,
            "verdict": verdict,
            "categories": categories,
            "timing_ms": round(elapsed_ms, 2),
        }
        AUDIT.info(json.dumps(event))


def run_proxy(config: Optional[MoatConfig] = None):
    cfg = config or load_config()
    proxy = MoatProxy(cfg)
    try:
        asyncio.run(proxy.run_forever())
    finally:
        with contextlib.suppress(Exception):
            asyncio.run(proxy.close())


def configure_proxy_logging(level: str = "INFO"):
    logging.basicConfig(level=getattr(logging, level.upper(), logging.INFO))
