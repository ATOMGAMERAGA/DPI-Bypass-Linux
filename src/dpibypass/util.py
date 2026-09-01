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
SO_BINDTODEVICE = 25  # linux/asm-generic/socket.h


def which(name: str) -> str | None:
    return shutil.which(name)


def run(cmd: Sequence[str], *, check: bool = False, timeout: int = 20,
        input_text: str | None = None,
        capture: bool = True,
        env: dict | None = None) -> subprocess.CompletedProcess:
    """Komutu çalıştır, çıktıyı yakala. Hata fırlatmaz (check=True olmadıkça).

    ``capture=False``, çıktının ve girdinin çağıran uçbirime bağlı kalmasını
    sağlar; pkexec gibi kullanıcıya parola soran komutlar için gerekir.

    ``env`` verilirse mevcut ortamın ÜZERİNE yazılır (tamamen değiştirmez);
    ölçüm komutlarını ``LC_ALL=C`` ile çalıştırmak için kullanılır: yerelleşmiş
    ``ping`` çıktısı ondalık ayırıcıyı ve özet satırlarını değiştirebilir.
    """
    log.debug("run: %s", " ".join(cmd))
    child_env = None
    if env:
        child_env = dict(os.environ)
        child_env.update({str(key): str(value) for key, value in env.items()})
    try:
        return subprocess.run(
            list(cmd),
            capture_output=capture,
            text=True,
            timeout=timeout,
            check=check,
            input=input_text,
            env=child_env,
        )
    except FileNotFoundError:
        return subprocess.CompletedProcess(cmd, 127, "", "komut bulunamadı")
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(cmd, 124, "", "zaman aşımı")


def mark_socket(sock: socket.socket) -> bool:
    """Kendi çıkış trafiğimizi yönlendirme döngüsünden muaf tut.

    Döner: işaret gerçekten konabildi mi. Ölçüm yolları bu sonucu kontrol
    ETMELİDİR — işaretlenmemiş bir soket şeffaf yönlendirmeye düşüp yerel
    proxy'ye bağlanabilir ve o zaman ölçülen şey ağ RTT'si değildir.
    """
    try:
        sock.setsockopt(socket.SOL_SOCKET, SO_MARK, FWMARK)
    except OSError as exc:  # root değilsek veya çekirdek desteklemiyorsa
        log.debug("SO_MARK ayarlanamadı: %s", exc)
        return False
    return True


def bind_to_device(sock: socket.socket, interface: str) -> bool:
    """``SO_BINDTODEVICE`` — yalnız doğrulanmış bağlamda kullanılmalıdır.

    Çağıran, hedefe giden gerçek rotanın bu arayüzden geçtiğini önceden
    doğrulamış olmalıdır. VPN veya policy routing varken fiziksel arayüze
    zorla bağlanmak trafiği tünelin dışına sızdırır; bu yüzden bu yardımcı
    kendi başına rota kararı vermez, yalnız isteneni uygular ve sonucu
    bildirir.
    """
    if not interface:
        return False
    try:
        sock.setsockopt(socket.SOL_SOCKET, SO_BINDTODEVICE,
                        interface.encode("ascii") + b"\0")
    except (OSError, UnicodeEncodeError) as exc:
        log.debug("SO_BINDTODEVICE ayarlanamadı (%s): %s", interface, exc)
        return False
    return True


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
