"""Ağ değişikliği izleyicisi.

Çekirdekten gelen netlink olayları (arayüz yukarı/aşağı, adres ve rota
değişiklikleri) anında yakalanır. Kablosuz ağ adı değiştiğinde — örneğin
"atom" ağından "atoms hotspot" ağına geçildiğinde — parmak izi değişir ve
arka planda yeni ağ için yöntem araması hemen başlatılır.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import socket
from dataclasses import dataclass
from typing import Awaitable, Callable

from .isps import current_ssid, default_route, link_type_of

log = logging.getLogger("dpibypass.netmon")

NETLINK_ROUTE = 0
RTMGRP_LINK = 0x1
RTMGRP_IPV4_IFADDR = 0x10
RTMGRP_IPV4_ROUTE = 0x40
RTMGRP_IPV6_IFADDR = 0x100
RTMGRP_IPV6_ROUTE = 0x400
GROUPS = (RTMGRP_LINK | RTMGRP_IPV4_IFADDR | RTMGRP_IPV4_ROUTE
          | RTMGRP_IPV6_IFADDR | RTMGRP_IPV6_ROUTE)


@dataclass
class NetworkFingerprint:
    interface: str = ""
    gateway: str = ""
    gateway_mac: str = ""
    ssid: str = ""
    link_type: str = ""

    @property
    def key(self) -> str:
        raw = "|".join([self.interface, self.gateway, self.gateway_mac,
                        self.ssid, self.link_type])
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    @property
    def name(self) -> str:
        """İnsan tarafından okunabilir ağ adı."""
        if self.ssid:
            return self.ssid
        if self.link_type == "mobile":
            return f"Mobil veri ({self.interface})"
        if self.interface:
            return f"{self.interface} ({self.gateway or 'ağ geçidi yok'})"
        return "bağlantı yok"

    def is_online(self) -> bool:
        return bool(self.interface and self.gateway)

    def to_dict(self) -> dict:
        return {"interface": self.interface, "gateway": self.gateway,
                "ssid": self.ssid, "link_type": self.link_type,
                "key": self.key, "name": self.name}


def gateway_mac(gateway: str) -> str:
    """Ağ geçidinin MAC adresi — aynı SSID'li farklı ağları ayırt eder."""
    if not gateway:
        return ""
    try:
        with open("/proc/net/arp", "r", encoding="ascii") as fh:
            for line in fh.readlines()[1:]:
                fields = line.split()
                if fields and fields[0] == gateway and len(fields) > 3:
                    mac = fields[3]
                    return "" if mac == "00:00:00:00:00:00" else mac
    except OSError:
        pass
    return ""


def fingerprint() -> NetworkFingerprint:
    iface, gw = default_route()
    fp = NetworkFingerprint(interface=iface, gateway=gw)
    fp.link_type = link_type_of(iface)
    if fp.link_type == "wifi":
        fp.ssid = current_ssid(iface)
    fp.gateway_mac = gateway_mac(gw)
    return fp


class NetworkMonitor:
    """Netlink olaylarını dinler, sakinleşme süresinden sonra geri çağırır."""

    def __init__(self, on_change: Callable[[NetworkFingerprint], Awaitable[None]],
                 debounce: float = 1.5, poll_interval: float = 20.0) -> None:
        self.on_change = on_change
        self.debounce = debounce
        self.poll_interval = poll_interval
        self.current = NetworkFingerprint()
        self._sock: socket.socket | None = None
        self._tasks: list[asyncio.Task] = []
        self._wake = asyncio.Event()
        self._running = False

    async def start(self) -> None:
        self.current = fingerprint()
        log.info("Başlangıç ağı: %s [%s]", self.current.name, self.current.key)
        self._running = True
        loop = asyncio.get_running_loop()
        try:
            sock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_ROUTE)
            sock.bind((0, GROUPS))
            sock.setblocking(False)
            self._sock = sock
            loop.add_reader(sock.fileno(), self._on_netlink)
        except OSError as exc:
            log.warning("netlink dinlenemedi (%s); yalnızca yoklama yapılacak", exc)
        self._tasks.append(asyncio.ensure_future(self._loop()))

    def _on_netlink(self) -> None:
        try:
            while True:
                data = self._sock.recv(65536, socket.MSG_DONTWAIT)  # type: ignore[union-attr]
                if not data:
                    break
        except BlockingIOError:
            pass
        except OSError:
            pass
        self._wake.set()

    async def _loop(self) -> None:
        while self._running:
            try:
                await asyncio.wait_for(self._wake.wait(), self.poll_interval)
                # olay geldi: değişiklikler durulana kadar bekle
                while True:
                    self._wake.clear()
                    try:
                        await asyncio.wait_for(self._wake.wait(), self.debounce)
                    except asyncio.TimeoutError:
                        break
            except asyncio.TimeoutError:
                pass  # düzenli yoklama
            except asyncio.CancelledError:
                return
            await self._check()

    async def _check(self) -> None:
        new = fingerprint()
        if new.key == self.current.key:
            return
        old = self.current
        self.current = new
        log.info("Ağ değişti: %s → %s", old.name or "-", new.name or "-")
        try:
            await self.on_change(new)
        except Exception:
            log.exception("ağ değişikliği işleyicisi hata verdi")

    async def force_check(self) -> None:
        await self._check()

    async def stop(self) -> None:
        self._running = False
        if self._sock is not None:
            try:
                asyncio.get_running_loop().remove_reader(self._sock.fileno())
            except (OSError, RuntimeError):
                pass
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None
        for task in self._tasks:
            task.cancel()
        self._tasks.clear()
