"""Küçük yardımcılar."""

from __future__ import annotations

import ipaddress
import logging
import os
import shutil
import socket
import subprocess
from typing import Iterable, Sequence

from .constants import FWMARK

log = logging.getLogger("dpibypass.util")

SO_MARK = 36  # linux/asm-generic/socket.h


def which(name: str) -> str | None:
    return shutil.which(name)


def run(cmd: Sequence[str], *, check: bool = False, timeout: int = 20,
        input_text: str | None = None,
        capture: bool = True) -> subprocess.CompletedProcess:
    """Komutu çalıştır, çıktıyı yakala. Hata fırlatmaz (check=True olmadıkça).

    ``capture=False``, çıktının ve girdinin çağıran uçbirime bağlı kalmasını
    sağlar; pkexec gibi kullanıcıya parola soran komutlar için gerekir.
    """
    log.debug("run: %s", " ".join(cmd))
    try:
        return subprocess.run(
            list(cmd),
            capture_output=capture,
            text=True,
            timeout=timeout,
            check=check,
            input=input_text,
        )
    except FileNotFoundError:
        return subprocess.CompletedProcess(cmd, 127, "", "komut bulunamadı")
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(cmd, 124, "", "zaman aşımı")


def mark_socket(sock: socket.socket) -> None:
    """Kendi çıkış trafiğimizi yönlendirme döngüsünden muaf tut."""
    try:
        sock.setsockopt(socket.SOL_SOCKET, SO_MARK, FWMARK)
    except OSError as exc:  # root değilsek veya çekirdek desteklemiyorsa
        log.debug("SO_MARK ayarlanamadı: %s", exc)


def is_root() -> bool:
    return os.geteuid() == 0


def is_private_ip(addr: str) -> bool:
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def domain_matches(host: str, domains: Iterable[str]) -> bool:
    """host, verilen alan adlarından birine eşit ya da alt alan adı mı?"""
    host = (host or "").strip(".").lower()
    if not host:
        return False
    for dom in domains:
        dom = dom.strip(".").lower()
        if not dom:
            continue
        if host == dom or host.endswith("." + dom):
            return True
    return False


def ensure_dir(path: str, mode: int = 0o755) -> None:
    os.makedirs(path, mode=mode, exist_ok=True)


def human_bytes(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024.0:
            return f"{n:.1f} {unit}"
        n /= 1024.0
    return f"{n:.1f} PB"
