"""Arka plan servisi ile GUI arasındaki yerel soket protokolü.

Satır başına bir JSON nesnesi. İstek ``{"cmd": ..., ...}``, yanıt
``{"ok": bool, "data"|"error": ...}``.
"""

from __future__ import annotations

import asyncio
import grp
import json
import logging
import os
import socket
from typing import Any, Awaitable, Callable

from .constants import RUN_DIR, SOCKET_GROUP, SOCKET_PATH

log = logging.getLogger("dpibypass.ipc")

Handler = Callable[[dict], Awaitable[dict]]


class IpcServer:
    def __init__(self, handler: Handler, path: str = SOCKET_PATH) -> None:
        self.handler = handler
        self.path = path
        self._server: asyncio.base_events.Server | None = None

    async def start(self) -> None:
        os.makedirs(RUN_DIR, mode=0o755, exist_ok=True)
        try:
            os.unlink(self.path)
        except FileNotFoundError:
            pass
        self._server = await asyncio.start_unix_server(self._client, path=self.path)
        self._set_permissions()
        log.info("Denetim soketi: %s", self.path)

    def _set_permissions(self) -> None:
        """Soketi ``dpi-bypass`` grubuna aç; grup yoksa herkese okunur yap."""
        try:
            gid = grp.getgrnam(SOCKET_GROUP).gr_gid
        except KeyError:
            os.chmod(self.path, 0o666)
            log.warning("'%s' grubu yok; soket herkese açık (0666) bırakıldı",
                        SOCKET_GROUP)
            return
        try:
            os.chown(self.path, 0, gid)
            os.chmod(self.path, 0o660)
        except OSError as exc:
            log.warning("soket izinleri ayarlanamadı: %s", exc)

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            try:
                await self._server.wait_closed()
            except Exception:
                pass
            self._server = None
        try:
            os.unlink(self.path)
        except OSError:
            pass

    async def _client(self, reader: asyncio.StreamReader,
                      writer: asyncio.StreamWriter) -> None:
        try:
            while True:
                line = await reader.readline()
                if not line:
                    break
                try:
                    request = json.loads(line.decode("utf-8"))
                    if not isinstance(request, dict):
                        raise ValueError("nesne bekleniyordu")
                except (ValueError, UnicodeDecodeError) as exc:
                    response = {"ok": False, "error": f"geçersiz istek: {exc}"}
                else:
                    try:
                        response = await self.handler(request)
                    except Exception as exc:  # işleyici hatası bağlantıyı düşürmesin
                        log.exception("IPC işleyici hatası")
                        response = {"ok": False, "error": str(exc)}
                writer.write(json.dumps(response, ensure_ascii=False).encode() + b"\n")
                await writer.drain()
        except (ConnectionError, asyncio.IncompleteReadError):
            pass
        finally:
            try:
                writer.close()
            except Exception:
                pass


class IpcClient:
    """Eşzamanlı istemci (GUI ve komut satırı için)."""

    def __init__(self, path: str = SOCKET_PATH, timeout: float = 30.0) -> None:
        self.path = path
        self.timeout = timeout

    def call(self, cmd: str, **kwargs: Any) -> dict:
        request = {"cmd": cmd}
        request.update(kwargs)
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        try:
            sock.connect(self.path)
            sock.sendall(json.dumps(request, ensure_ascii=False).encode() + b"\n")
            buf = b""
            while b"\n" not in buf:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                buf += chunk
            if not buf:
                return {"ok": False, "error": "servisten yanıt yok"}
            return json.loads(buf.split(b"\n", 1)[0].decode("utf-8"))
        except FileNotFoundError:
            return {"ok": False, "error": "servis çalışmıyor (soket yok)",
                    "code": "no-service"}
        except PermissionError:
            return {"ok": False, "error":
                    "sokete erişim reddedildi — kullanıcınız 'dpi-bypass' "
                    "grubunda olmayabilir", "code": "permission"}
        except (ConnectionRefusedError, OSError) as exc:
            return {"ok": False, "error": f"servise bağlanılamadı: {exc}",
                    "code": "no-service"}
        except json.JSONDecodeError as exc:
            return {"ok": False, "error": f"bozuk yanıt: {exc}"}
        finally:
            try:
                sock.close()
            except OSError:
                pass

    def available(self) -> bool:
        return os.path.exists(self.path)
