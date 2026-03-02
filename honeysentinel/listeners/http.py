from __future__ import annotations

import asyncio
import uuid
from collections.abc import Awaitable, Callable

from honeysentinel.config import HttpListenerConfig
from honeysentinel.events import Event
from honeysentinel.util import redact_body, redact_headers, safe_decode

EventCallback = Callable[[Event], Awaitable[None]]


class RawHttpListener:
    def __init__(self, cfg: HttpListenerConfig, on_event: EventCallback) -> None:
        self.cfg = cfg
        self.on_event = on_event
        self.server: asyncio.base_events.Server | None = None

    async def start(self) -> None:
        self.server = await asyncio.start_server(
            self._handle, host=self.cfg.host, port=self.cfg.port
        )

    async def stop(self) -> None:
        if self.server:
            self.server.close()
            await self.server.wait_closed()

    async def _emit(self, event: Event) -> None:
        await self.on_event(event)

    async def _handle(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        peer = writer.get_extra_info("peername") or ("0.0.0.0", 0)
        src_ip, src_port = str(peer[0]), int(peer[1])
        session_id = str(uuid.uuid4())
        try:
            req_line = safe_decode(await asyncio.wait_for(reader.readline(), timeout=5)).strip()
            parts = req_line.split(" ")
            method, path = (parts[0], parts[1]) if len(parts) >= 2 else ("GET", "/")

            headers: dict[str, str] = {}
            for _ in range(self.cfg.max_headers):
                line = safe_decode(await asyncio.wait_for(reader.readline(), timeout=5)).strip()
                if not line:
                    break
                if ":" in line:
                    k, v = line.split(":", 1)
                    headers[k.strip()] = v.strip()

            content_length = min(
                int(headers.get("Content-Length", "0")), self.cfg.max_body_bytes
            )
            body = b""
            if content_length > 0:
                body = await asyncio.wait_for(reader.readexactly(content_length), timeout=5)

            body_meta = redact_body(headers.get("Content-Type", ""), body)
            await self._emit(
                Event(
                    event_type="http_request",
                    src_ip=src_ip,
                    src_port=src_port,
                    dst_port=self.cfg.port,
                    listener="http_raw",
                    session_id=session_id,
                    message=f"HTTP {method} {path}",
                    data={
                        "method": method,
                        "path": path,
                        "headers": redact_headers(headers),
                        "body_preview": body_meta["preview"],
                        "body_len": body_meta["body_len"],
                        "body_sha256": body_meta["sha256"],
                    },
                )
            )

            interesting = ["/", "/admin", "/login", "/wp-", "/phpmyadmin"]
            status_line = "HTTP/1.1 401 Unauthorized"
            if not any(x in path for x in interesting):
                status_line = "HTTP/1.1 404 Not Found"
            body_resp = b"Unauthorized\n" if "401" in status_line else b"Not Found\n"
            headers_resp = (
                f"{status_line}\r\n"
                f"Content-Length: {len(body_resp)}\r\n"
                "Connection: close\r\n\r\n"
            ).encode()
            writer.write(headers_resp + body_resp)
            await writer.drain()
        except Exception:
            writer.write(
                b"HTTP/1.1 400 Bad Request\r\n"
                b"Content-Length: 0\r\n"
                b"Connection: close\r\n\r\n"
            )
            await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()
