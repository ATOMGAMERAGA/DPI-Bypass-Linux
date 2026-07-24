"""Şeffaf TCP vekil sunucusu.

Çekirdek, engelli hedeflere giden 80/443 bağlantılarını buraya yönlendirir.
Vekil, ilk istemci verisini seçili stratejiye göre yeniden şekillendirip
gerçek sunucuya iletir; sonrasında iki yönü olduğu gibi kopyalar.

Bağlantı başına ek maliyet yalnızca bir yerel geri döngü kopyasıdır; ping,
UDP oyun trafiği ve diğer protokoller yönlendirilmediği için etkilenmez.
"""

from __future__ import annotations

import asyncio
import logging
import socket
import struct
from typing import Awaitable, Callable, Optional

from . import desync, tlsutil
from .strategies import Strategy
from .util import mark_socket

log = logging.getLogger("dpibypass.proxy")

SO_ORIGINAL_DST = 80
IP6T_SO_ORIGINAL_DST = 80
BUFSIZE = 65536


def original_dst(sock: socket.socket) -> tuple[str, int] | None:
    """Yönlendirmeden önceki asıl hedefi çekirdekten öğren."""
    try:
        if sock.family == socket.AF_INET6:
            data = sock.getsockopt(socket.IPPROTO_IPV6, IP6T_SO_ORIGINAL_DST, 28)
            port = struct.unpack_from("!H", data, 2)[0]
            return socket.inet_ntop(socket.AF_INET6, data[8:24]), port
        data = sock.getsockopt(socket.SOL_IP, SO_ORIGINAL_DST, 16)
        port = struct.unpack_from("!H", data, 2)[0]
        return socket.inet_ntop(socket.AF_INET, data[4:8]), port
    except OSError as exc:
        log.debug("SO_ORIGINAL_DST okunamadı: %s", exc)
        return None


class TransparentProxy:
    def __init__(
        self,
        port: int,
        get_strategy: Callable[[], Optional[Strategy]],
        should_bypass: Callable[[str, str], bool],
        on_result: Optional[Callable[[str, bool, bool, str], Awaitable[None]]] = None,
    ) -> None:
        self.port = port
        self.get_strategy = get_strategy
        self.should_bypass = should_bypass
        self.on_result = on_result
        self._servers: list[asyncio.base_events.Server] = []
        self._tasks: set[asyncio.Task] = set()
        self.stats = {
            "connections": 0,
            "bypassed": 0,
            "direct": 0,
            "failed": 0,
            "bytes_up": 0,
            "bytes_down": 0,
        }

    # -- yaşam döngüsü -----------------------------------------------------
    async def start(self) -> None:
        loop = asyncio.get_running_loop()
        listening = []
        for family, addr in ((socket.AF_INET, "127.0.0.1"), (socket.AF_INET6, "::1")):
            try:
                sock = socket.socket(family, socket.SOCK_STREAM)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                if family == socket.AF_INET6:
                    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                sock.bind((addr, self.port))
                sock.listen(512)
                sock.setblocking(False)
            except OSError as exc:
                log.warning("%s:%d dinlenemedi: %s", addr, self.port, exc)
                continue
            task = asyncio.ensure_future(self._accept_loop(loop, sock))
            self._tasks.add(task)
            listening.append(f"{addr}:{self.port}")
        if not listening:
            raise OSError(f"vekil {self.port} portunda dinleyemedi")
        log.info("Şeffaf vekil dinliyor: %s", ", ".join(listening))

    async def stop(self) -> None:
        for task in list(self._tasks):
            task.cancel()
        self._tasks.clear()

    # -- kabul döngüsü -----------------------------------------------------
    async def _accept_loop(self, loop: asyncio.AbstractEventLoop,
                           listener: socket.socket) -> None:
        try:
            while True:
                try:
                    client, _peer = await loop.sock_accept(listener)
                except OSError as exc:
                    log.debug("accept hatası: %s", exc)
                    await asyncio.sleep(0.1)
                    continue
                client.setblocking(False)
                task = asyncio.ensure_future(self._handle(loop, client))
                self._tasks.add(task)
                task.add_done_callback(self._tasks.discard)
        except asyncio.CancelledError:
            pass
        finally:
            try:
                listener.close()
            except OSError:
                pass

    # -- bağlantı işleme ---------------------------------------------------
    async def _handle(self, loop: asyncio.AbstractEventLoop,
                      client: socket.socket) -> None:
        upstream: socket.socket | None = None
        host = ""
        bypassed = False
        try:
            dst = original_dst(client)
            if dst is None:
                return
            dst_ip, dst_port = dst
            if dst_port == self.port and dst_ip in ("127.0.0.1", "::1"):
                return  # kendimize yönlendirme: döngüyü kes

            self.stats["connections"] += 1
            try:
                client.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            except OSError:
                pass

            # İlk istemci verisini bekle (TLS ClientHello / HTTP isteği)
            first = b""
            try:
                first = await asyncio.wait_for(loop.sock_recv(client, BUFSIZE), 4.0)
            except asyncio.TimeoutError:
                first = b""
            if first == b"":
                # Sunucunun önce konuştuğu protokol ya da kapanmış bağlantı
                pass

            host = self._peek_host(first) or dst_ip
            strategy = self.get_strategy()
            bypassed = bool(first) and strategy is not None and \
                self.should_bypass(host, dst_ip)

            upstream = await self._connect(loop, dst_ip, dst_port)

            if first:
                if bypassed and strategy is not None:
                    try:
                        await desync.send_first_payload(loop, upstream, first, strategy)
                        self.stats["bypassed"] += 1
                    except OSError as exc:
                        log.debug("%s için strateji uygulanamadı: %s", host, exc)
                        self.stats["failed"] += 1
                        if self.on_result:
                            await self.on_result(host, False, True, str(exc))
                        return
                else:
                    await loop.sock_sendall(upstream, first)
                    self.stats["direct"] += 1
                self.stats["bytes_up"] += len(first)

            ok = await self._splice(loop, client, upstream)
            if self.on_result and first:
                await self.on_result(host, ok, bypassed, "")
        except (OSError, asyncio.CancelledError) as exc:
            self.stats["failed"] += 1
            log.debug("bağlantı hatası (%s): %s", host, exc)
            if self.on_result and host:
                try:
                    await self.on_result(host, False, bypassed, str(exc))
                except Exception:
                    pass
        finally:
            for sock in (client, upstream):
                if sock is not None:
                    try:
                        sock.close()
                    except OSError:
                        pass

    async def _connect(self, loop: asyncio.AbstractEventLoop,
                       ip: str, port: int) -> socket.socket:
        family = socket.AF_INET6 if ":" in ip else socket.AF_INET
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.setblocking(False)
        mark_socket(sock)
        try:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except OSError:
            pass
        await asyncio.wait_for(loop.sock_connect(sock, (ip, port)), 10.0)
        return sock

    @staticmethod
    def _peek_host(data: bytes) -> str:
        if not data:
            return ""
        sni = tlsutil.sni_from_client_hello(data)
        if sni:
            return sni
        if tlsutil.looks_like_http(data):
            host, _, _ = tlsutil.parse_http_host(data)
            return host or ""
        return ""

    async def _splice(self, loop: asyncio.AbstractEventLoop,
                      client: socket.socket, upstream: socket.socket) -> bool:
        """İki yönü kopyala. İlk sunucu yanıtı alındıysa True döner."""
        got_response = asyncio.Event()

        async def pump(src: socket.socket, dst: socket.socket, downstream: bool) -> None:
            try:
                while True:
                    data = await loop.sock_recv(src, BUFSIZE)
                    if not data:
                        break
                    if downstream:
                        self.stats["bytes_down"] += len(data)
                        got_response.set()
                    else:
                        self.stats["bytes_up"] += len(data)
                    await loop.sock_sendall(dst, data)
            except (OSError, asyncio.CancelledError):
                pass
            finally:
                try:
                    dst.shutdown(socket.SHUT_WR)
                except OSError:
                    pass

        down = asyncio.ensure_future(pump(upstream, client, True))
        up = asyncio.ensure_future(pump(client, upstream, False))
        try:
            await asyncio.gather(down, up, return_exceptions=True)
        finally:
            for task in (down, up):
                if not task.done():
                    task.cancel()
        return got_response.is_set()
