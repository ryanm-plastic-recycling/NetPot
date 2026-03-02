from __future__ import annotations

import asyncio
import uuid
from collections.abc import Awaitable, Callable

from honeysentinel.config import PrivacyConfig, TcpListenerConfig
from honeysentinel.events import Event
from honeysentinel.util import preview_bytes, redact_telnet_password, safe_decode, sha256_hex

EventCallback = Callable[[Event], Awaitable[None]]


class TcpListener:
    def __init__(
        self,
        cfg: TcpListenerConfig,
        privacy: PrivacyConfig,
        on_event: EventCallback,
    ) -> None:
        self.cfg = cfg
        self.privacy = privacy
        self.on_event = on_event
        self.server: asyncio.base_events.Server | None = None

    async def start(self) -> None:
        self.server = await asyncio.start_server(
            self._handle_client, host=self.cfg.host, port=self.cfg.port
        )

    async def stop(self) -> None:
        if self.server:
            self.server.close()
            await self.server.wait_closed()

    async def _emit(self, event: Event) -> None:
        await self.on_event(event)

    async def _handle_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        peer = writer.get_extra_info("peername") or ("0.0.0.0", 0)
        src_ip, src_port = str(peer[0]), int(peer[1])
        session = str(uuid.uuid4())

        await self._emit(
            Event(
                event_type="connection_open",
                src_ip=src_ip,
                src_port=src_port,
                dst_port=self.cfg.port,
                listener=self.cfg.name,
                session_id=session,
                message="TCP connection opened",
                data={"mode": self.cfg.mode},
            )
        )

        if self.cfg.banner:
            writer.write((self.cfg.banner + "\r\n").encode())
            await writer.drain()

        try:
            mode = self.cfg.mode.lower()
            if mode == "ssh":
                line = await asyncio.wait_for(reader.readline(), timeout=5)
                await self._emit(
                    Event(
                        event_type="ssh_client_banner",
                        src_ip=src_ip,
                        src_port=src_port,
                        dst_port=self.cfg.port,
                        listener=self.cfg.name,
                        session_id=session,
                        message="SSH banner received",
                        data={"line": safe_decode(line[:512]).strip()},
                    )
                )
            elif mode == "telnet":
                writer.write(b"login: ")
                await writer.drain()
                username = safe_decode(
                    await asyncio.wait_for(reader.readline(), timeout=8)
                ).strip()
                writer.write(b"Password: ")
                await writer.drain()
                password_input = safe_decode(
                    await asyncio.wait_for(reader.readline(), timeout=8)
                ).strip()
                await self._emit(
                    Event(
                        event_type="telnet_auth_attempt",
                        src_ip=src_ip,
                        src_port=src_port,
                        dst_port=self.cfg.port,
                        listener=self.cfg.name,
                        session_id=session,
                        message="Telnet-style auth prompt interaction",
                        data={
                            "username": username[:128],
                            "password": redact_telnet_password(password_input),
                        },
                    )
                )
            elif mode == "smtp":
                writer.write(b"220 honeysentinel ESMTP\r\n")
                await writer.drain()
                for _ in range(4):
                    smtp_line = safe_decode(
                        await asyncio.wait_for(reader.readline(), timeout=8)
                    ).strip()[:512]
                    if not smtp_line:
                        break
                    await self._emit(
                        Event(
                            event_type="smtp_line",
                            src_ip=src_ip,
                            src_port=src_port,
                            dst_port=self.cfg.port,
                            listener=self.cfg.name,
                            session_id=session,
                            message="SMTP command",
                            data={"line": smtp_line},
                        )
                    )
                    upper = smtp_line.upper()
                    if upper.startswith("DATA"):
                        writer.write(b"354 End data with <CR><LF>.<CR><LF>\r\n")
                    elif upper.startswith("QUIT"):
                        writer.write(b"221 Bye\r\n")
                        break
                    else:
                        writer.write(b"250 OK\r\n")
                    await writer.drain()
            elif mode == "redis":
                data = await asyncio.wait_for(reader.read(self.cfg.max_bytes), timeout=5)
                writer.write(b"-ERR unknown command\r\n")
                await writer.drain()
                await self._emit(
                    Event(
                        event_type="redis_line",
                        src_ip=src_ip,
                        src_port=src_port,
                        dst_port=self.cfg.port,
                        listener=self.cfg.name,
                        session_id=session,
                        message="Redis probe",
                        data={"sha256": sha256_hex(data), "bytes_in": len(data)},
                    )
                )
            else:
                data = await asyncio.wait_for(reader.read(self.cfg.max_bytes), timeout=5)
                payload: dict[str, object] = {
                    "sha256": sha256_hex(data),
                    "bytes_in": len(data),
                }
                if self.privacy.store_tcp_payload_preview and data:
                    payload["payload_preview"] = preview_bytes(
                        data, self.privacy.tcp_payload_preview_bytes
                    )
                await self._emit(
                    Event(
                        event_type="tcp_summary",
                        src_ip=src_ip,
                        src_port=src_port,
                        dst_port=self.cfg.port,
                        listener=self.cfg.name,
                        session_id=session,
                        message="TCP data summary",
                        data=payload,
                    )
                )
        except TimeoutError:
            await self._emit(
                Event(
                    event_type="connection_timeout",
                    src_ip=src_ip,
                    src_port=src_port,
                    dst_port=self.cfg.port,
                    listener=self.cfg.name,
                    session_id=session,
                    message="Connection timed out",
                    data={},
                )
            )
        finally:
            writer.close()
            await writer.wait_closed()
