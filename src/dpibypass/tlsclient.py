"""Bellek BIO tabanlı asenkron TLS istemcisi.

Standart ``asyncio`` TLS'i ClientHello'nun tel üzerine nasıl yazıldığını
denetlememize izin vermez. Burada ``ssl.MemoryBIO`` kullanarak el sıkışma
baytlarını kendimiz yazıyoruz; böylece ilk uçuşa (ClientHello) atlatma
stratejisi uygulanabiliyor. Bu, DoH sorgularının ve bağlantı testlerinin de
DPI engelini aşmasını sağlar.
"""

from __future__ import annotations

import asyncio
import logging
import socket
import ssl
from typing import Optional

from . import desync
from .strategies import Strategy
from .util import mark_socket

log = logging.getLogger("dpibypass.tls")

_ctx: ssl.SSLContext | None = None


def context() -> ssl.SSLContext:
    global _ctx
    if _ctx is None:
        ctx = ssl.create_default_context()
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
        try:
            ctx.set_alpn_protocols(["http/1.1"])
        except NotImplementedError:  # pragma: no cover
            pass
        _ctx = ctx
    return _ctx


class TLSStream:
    """Küçük bir TLS akışı: bağlan, el sıkış, gönder, al."""

    def __init__(self, loop: asyncio.AbstractEventLoop, sock: socket.socket,
                 hostname: str) -> None:
        self.loop = loop
        self.sock = sock
        self.hostname = hostname
        self._in = ssl.MemoryBIO()
        self._out = ssl.MemoryBIO()
        self._obj = context().wrap_bio(self._in, self._out, server_hostname=hostname)
        self._closed = False

    # -- iç yardımcılar ----------------------------------------------------
    async def _flush(self, strategy: Strategy | None = None) -> None:
        data = self._out.read()
        if not data:
            return
        if strategy is not None:
            await desync.send_first_payload(self.loop, self.sock, data, strategy)
        else:
            await self.loop.sock_sendall(self.sock, data)

    async def _feed(self) -> None:
        data = await self.loop.sock_recv(self.sock, 65536)
        if not data:
            self._in.write_eof()
            raise ConnectionResetError("bağlantı karşı taraftan kapatıldı")
        self._in.write(data)

    # -- genel API ---------------------------------------------------------
    async def handshake(self, strategy: Strategy | None = None) -> None:
        first_flight = True
        while True:
            try:
                self._obj.do_handshake()
            except ssl.SSLWantReadError:
                await self._flush(strategy if first_flight else None)
                first_flight = False
                await self._feed()
            else:
                await self._flush(None)
                return

    async def send(self, data: bytes) -> None:
        while data:
            try:
                sent = self._obj.write(data)
            except ssl.SSLWantReadError:
                await self._flush(None)
                await self._feed()
                continue
            data = data[sent:]
            await self._flush(None)

    async def recv(self, size: int = 65536) -> bytes:
        while True:
            try:
                return self._obj.read(size)
            except ssl.SSLWantReadError:
                await self._flush(None)
                try:
                    await self._feed()
                except ConnectionResetError:
                    return b""
            except ssl.SSLZeroReturnError:
                return b""

    async def recv_exactly(self, size: int) -> bytes:
        buf = b""
        while len(buf) < size:
            chunk = await self.recv(size - len(buf))
            if not chunk:
                break
            buf += chunk
        return buf

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            self.sock.close()
        except OSError:
            pass


async def connect_tls(ip: str, port: int, hostname: str, *,
                      strategy: Strategy | None = None,
                      timeout: float = 8.0) -> TLSStream:
    """``ip:port`` adresine bağlan ve ``hostname`` için TLS el sıkışması yap."""
    loop = asyncio.get_running_loop()
    family = socket.AF_INET6 if ":" in ip else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_STREAM)
    sock.setblocking(False)
    mark_socket(sock)
    try:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    except OSError:
        pass
    try:
        await asyncio.wait_for(loop.sock_connect(sock, (ip, port)), timeout)
        stream = TLSStream(loop, sock, hostname)
        await asyncio.wait_for(stream.handshake(strategy), timeout)
        return stream
    except Exception:
        try:
            sock.close()
        except OSError:
            pass
        raise


async def https_request(ip: str, hostname: str, method: str, path: str, *,
                        body: bytes = b"", headers: Optional[dict] = None,
                        strategy: Strategy | None = None,
                        port: int = 443,
                        timeout: float = 8.0) -> tuple[int, bytes]:
    """Tek seferlik minimal HTTPS isteği. (durum kodu, gövde) döndürür."""
    hdrs = {
        "Host": hostname,
        "User-Agent": "dpi-bypass/1.0",
        "Accept": "*/*",
        "Connection": "close",
    }
    if headers:
        hdrs.update(headers)
    if body:
        hdrs["Content-Length"] = str(len(body))

    req = f"{method} {path} HTTP/1.1\r\n".encode()
    req += "".join(f"{k}: {v}\r\n" for k, v in hdrs.items()).encode()
    req += b"\r\n" + body

    stream = await connect_tls(ip, port, hostname, strategy=strategy, timeout=timeout)
    try:
        await stream.send(req)
        buf = b""
        deadline = asyncio.get_running_loop().time() + timeout
        while b"\r\n\r\n" not in buf:
            if asyncio.get_running_loop().time() > deadline:
                raise TimeoutError("HTTP başlıkları zamanında alınamadı")
            chunk = await asyncio.wait_for(stream.recv(), timeout)
            if not chunk:
                break
            buf += chunk
        head, _, rest = buf.partition(b"\r\n\r\n")
        status = 0
        length: int | None = None
        chunked = False
        lines = head.split(b"\r\n")
        if lines and lines[0].startswith(b"HTTP/"):
            try:
                status = int(lines[0].split()[1])
            except (IndexError, ValueError):
                status = 0
        for line in lines[1:]:
            name, _, value = line.partition(b":")
            key = name.strip().lower()
            if key == b"content-length":
                try:
                    length = int(value.strip())
                except ValueError:
                    length = None
            elif key == b"transfer-encoding" and b"chunked" in value.lower():
                chunked = True

        data = rest
        if chunked:
            while not data.endswith(b"0\r\n\r\n"):
                chunk = await asyncio.wait_for(stream.recv(), timeout)
                if not chunk:
                    break
                data += chunk
            data = _dechunk(data)
        elif length is not None:
            while len(data) < length:
                chunk = await asyncio.wait_for(stream.recv(), timeout)
                if not chunk:
                    break
                data += chunk
            data = data[:length]
        return status, data
    finally:
        stream.close()


def _dechunk(data: bytes) -> bytes:
    out = b""
    while data:
        line, _, rest = data.partition(b"\r\n")
        try:
            size = int(line.split(b";")[0].strip(), 16)
        except ValueError:
            break
        if size == 0:
            break
        out += rest[:size]
        data = rest[size + 2:]
    return out
