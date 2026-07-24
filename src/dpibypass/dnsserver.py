"""Yerel DNS sunucusu: sistemin tüm DNS trafiğini DoH'a köprüler.

Çekirdek kuralları 53 numaralı porta giden her şeyi buraya yönlendirir.
Yanıtlar Cloudflare (yedek: Google, Quad9) üzerinden şifreli olarak alınır,
böylece DNS düzeyindeki engelleme ve yanıt zehirlenmesi ortadan kalkar.

Ayrıca engelli alan adlarının çözümlenen IP'leri, güvenlik duvarı kümesine
otomatik olarak eklenir; şeffaf vekil böylece doğru hedefleri yakalar.
"""

from __future__ import annotations

import asyncio
import logging
import socket
import struct
from typing import Callable, Optional

from .resolver import Resolver

log = logging.getLogger("dpibypass.dnssrv")


def _servfail(wire: bytes) -> bytes:
    if len(wire) < 12:
        return b""
    qid = wire[:2]
    flags = struct.unpack_from("!H", wire, 2)[0]
    flags = (flags & 0x0100) | 0x8000 | 0x0002  # QR=1, RCODE=SERVFAIL
    return qid + struct.pack("!H", flags) + wire[4:6] + b"\x00\x00\x00\x00\x00\x00" \
        + wire[12:]


class DnsServer:
    def __init__(self, resolver: Resolver, port: int,
                 on_answer: Optional[Callable[[str, list[str]], None]] = None) -> None:
        self.resolver = resolver
        self.port = port
        self.on_answer = on_answer
        self._udp_transports: list[asyncio.DatagramTransport] = []
        self._tcp_servers: list[asyncio.base_events.Server] = []
        self.stats = {"udp": 0, "tcp": 0, "error": 0}

    # -- yaşam döngüsü -----------------------------------------------------
    async def start(self) -> None:
        loop = asyncio.get_running_loop()
        server = self

        class _Proto(asyncio.DatagramProtocol):
            def connection_made(self, transport):
                self.transport = transport

            def datagram_received(self, data: bytes, addr):
                asyncio.ensure_future(server._handle_udp(self.transport, data, addr))

        for host in ("127.0.0.1", "::1"):
            try:
                transport, _ = await loop.create_datagram_endpoint(
                    _Proto,
                    local_addr=(host, self.port),
                    family=socket.AF_INET6 if ":" in host else socket.AF_INET,
                )
                self._udp_transports.append(transport)
            except OSError as exc:
                log.warning("DNS UDP %s:%d dinlenemedi: %s", host, self.port, exc)
            try:
                srv = await asyncio.start_server(
                    self._handle_tcp, host, self.port,
                    family=socket.AF_INET6 if ":" in host else socket.AF_INET,
                )
                self._tcp_servers.append(srv)
            except OSError as exc:
                log.warning("DNS TCP %s:%d dinlenemedi: %s", host, self.port, exc)
        if not self._udp_transports:
            raise OSError(f"DNS sunucusu {self.port} portunda başlatılamadı")
        log.info("Yerel DNS köprüsü 127.0.0.1:%d üzerinde (DoH: Cloudflare → "
                 "Google → Quad9)", self.port)

    async def stop(self) -> None:
        for transport in self._udp_transports:
            transport.close()
        self._udp_transports.clear()
        for srv in self._tcp_servers:
            srv.close()
        self._tcp_servers.clear()

    # -- işleyiciler -------------------------------------------------------
    async def _resolve(self, wire: bytes) -> bytes:
        try:
            raw, msg = await self.resolver.resolve_wire_cached(wire)
        except Exception as exc:
            self.stats["error"] += 1
            log.debug("DNS çözümlemesi başarısız: %s", exc)
            return _servfail(wire)
        if self.on_answer and msg.question:
            try:
                self.on_answer(msg.question, msg.addresses())
            except Exception:  # geri çağırım asla sunucuyu düşürmesin
                log.debug("on_answer geri çağırımı hata verdi", exc_info=True)
        return raw

    async def _handle_udp(self, transport: asyncio.DatagramTransport,
                          data: bytes, addr) -> None:
        self.stats["udp"] += 1
        response = await self._resolve(data)
        if response:
            # UDP yanıtı 512 baytı aşarsa kısaltılmış (TC) işaretlenmeli
            if len(response) > 512:
                flags = struct.unpack_from("!H", response, 2)[0] | 0x0200
                response = response[:2] + struct.pack("!H", flags) + response[4:512]
            try:
                transport.sendto(response, addr)
            except OSError:
                pass

    async def _handle_tcp(self, reader: asyncio.StreamReader,
                          writer: asyncio.StreamWriter) -> None:
        self.stats["tcp"] += 1
        try:
            while True:
                header = await reader.readexactly(2)
                length = struct.unpack("!H", header)[0]
                wire = await reader.readexactly(length)
                response = await self._resolve(wire)
                if not response:
                    break
                writer.write(struct.pack("!H", len(response)) + response)
                await writer.drain()
        except (asyncio.IncompleteReadError, ConnectionError, OSError):
            pass
        finally:
            try:
                writer.close()
            except Exception:
                pass
