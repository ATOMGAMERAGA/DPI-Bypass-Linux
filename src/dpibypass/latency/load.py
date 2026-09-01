"""İzinli, bütçeli ve iptal edilebilir kontrollü yük üretimi.

Bufferbloat ancak hat **doyurulduğunda** ölçülebilir. Boşta alınan RTT bunu
göstermez. Ama kullanıcının hattını habersiz doldurmak da kabul edilemez;
bu yüzden burada her şey kilit altındadır:

* Varsayılan **kapalı**. Açılmadan önce amaç, azami süre, azami toplam veri
  ve hedef açıkça gösterilir.
* Hedef **kullanıcıya ait ya da yük testi için açıkça izinli** olmalıdır.
  Genel DNS çözücülerine, ölçüm referanslarına ve rastgele internet
  sunucularına yük gönderilmez — bunlar reddedilir.
* Ölçümlü/mobil bağlantıda ayrı ve açık onay istenir.
* Bütçe (süre ve toplam bayt) sert sınırdır; dolduğunda yük derhal durur.
* Yük hiç uygulanmadıysa sonuçta "bufferbloat ölçüldü" YAZILMAZ.

Yük hedefi yoksa: hafif ölçüm ve kullanıcının elle girdiği bant genişliği
ile devam edilir, sonucun güveni abartılmaz.
"""

from __future__ import annotations

import ipaddress
import logging
import socket
import threading
import time
from dataclasses import dataclass, field

from ..util import mark_socket

log = logging.getLogger("dpibypass.latency.load")

LOAD_MODES = ("http-download", "http-upload", "tcp-sink", "tcp-source")

#: Yük gönderilmesi kesinlikle reddedilen adresler: ölçüm referanslarımız ve
#: yaygın genel DNS çözücüleri. Bunlar kimsenin yük testi sunucusu değildir.
FORBIDDEN_ADDRESSES = frozenset({
    "1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "149.112.112.112",
    "208.67.222.222", "208.67.220.220", "94.140.14.14", "94.140.15.15",
    "2606:4700:4700::1111", "2606:4700:4700::1001",
    "2001:4860:4860::8888", "2001:4860:4860::8844",
    "2620:fe::fe", "2620:fe::9",
})

#: Varsayılan bütçe. Kullanıcı yükseltebilir ama sert üst sınır aşılamaz.
DEFAULT_MAX_SECONDS = 12
DEFAULT_MAX_BYTES = 64 * 1024 * 1024      # 64 MB
HARD_MAX_SECONDS = 60
HARD_MAX_BYTES = 512 * 1024 * 1024        # 512 MB

_CHUNK = 64 * 1024


class LoadError(RuntimeError):
    pass


@dataclass
class LoadBudget:
    max_seconds: int = DEFAULT_MAX_SECONDS
    max_bytes: int = DEFAULT_MAX_BYTES
    streams: int = 3

    def clamped(self) -> "LoadBudget":
        return LoadBudget(
            max_seconds=max(1, min(HARD_MAX_SECONDS, int(self.max_seconds))),
            max_bytes=max(1024, min(HARD_MAX_BYTES, int(self.max_bytes))),
            streams=max(1, min(8, int(self.streams))),
        )

    def to_dict(self) -> dict:
        return {"max_seconds": self.max_seconds, "max_bytes": self.max_bytes,
                "streams": self.streams}


@dataclass
class LoadTarget:
    """Kullanıcının yük testi için izin verdiği sunucu."""

    host: str = ""
    port: int = 0
    mode: str = "http-download"
    path: str = "/"
    #: Kullanıcı bu sunucunun kendisine ait ya da yük testine izinli olduğunu
    #: açıkça onayladı mı? Onaysız yük başlamaz.
    owned: bool = False
    #: Ölçümlü/mobil bağlantıda ayrıca istenen onay.
    metered_ack: bool = False

    def validate(self, metered: bool = False) -> str:
        if self.mode not in LOAD_MODES:
            return f"desteklenmeyen yük kipi: {self.mode}"
        if not self.host:
            return "yük testi sunucusu tanımlı değil"
        if not 1 <= int(self.port or 0) <= 65535:
            return "yük testi sunucusu için geçerli bir port gerekiyor"
        if not self.owned:
            return ("yük testi yalnız size ait ya da yük testine açıkça izin "
                    "veren bir sunucuya yapılabilir; onay verilmedi")
        if metered and not self.metered_ack:
            return ("ölçümlü/mobil bağlantı: yük testi için ayrı onay "
                    "gerekiyor")
        blocked = _forbidden(self.host)
        if blocked:
            return blocked
        return ""

    def to_dict(self) -> dict:
        return {"host": self.host, "port": int(self.port or 0),
                "mode": self.mode, "path": self.path, "owned": self.owned,
                "metered_ack": self.metered_ack}

    @classmethod
    def from_dict(cls, data: dict) -> "LoadTarget":
        if not isinstance(data, dict):
            raise ValueError("geçersiz yük hedefi")
        try:
            port = int(data.get("port", 0) or 0)
        except (TypeError, ValueError):
            raise ValueError("geçersiz yük hedefi portu")
        path = str(data.get("path", "/") or "/")
        if not path.startswith("/") or len(path) > 512 or any(
                char in path for char in "\r\n \t"):
            raise ValueError("geçersiz yük hedefi yolu")
        return cls(host=str(data.get("host", ""))[:253], port=port,
                   mode=str(data.get("mode", "http-download")), path=path,
                   owned=bool(data.get("owned")),
                   metered_ack=bool(data.get("metered_ack")))


def _forbidden(host: str) -> str:
    candidate = host.strip().lower()
    if candidate in FORBIDDEN_ADDRESSES:
        return (f"{host} bir genel altyapı adresidir; buraya yük testi "
                f"gönderilmez")
    try:
        parsed = ipaddress.ip_address(candidate)
    except ValueError:
        return ""
    if parsed.is_multicast or parsed.is_reserved or parsed.is_unspecified:
        return f"{host} yük testi için geçerli bir hedef değil"
    return ""


def describe(target: LoadTarget, budget: LoadBudget) -> str:
    """Kullanıcıya yük başlamadan gösterilecek özet."""
    clamped = budget.clamped()
    return (f"Yük testi: {target.mode} → {target.host}:{target.port} · "
            f"en çok {clamped.max_seconds} sn · en çok "
            f"{clamped.max_bytes // (1024 * 1024)} MB · "
            f"{clamped.streams} eşzamanlı akış")


@dataclass
class LoadResult:
    started: bool = False
    bytes_moved: int = 0
    seconds: float = 0.0
    errors: list = field(default_factory=list)
    stopped_reason: str = ""

    @property
    def throughput_kbit(self) -> float:
        if self.seconds <= 0 or self.bytes_moved <= 0:
            return 0.0
        return round(self.bytes_moved * 8.0 / 1000.0 / self.seconds, 1)

    def to_dict(self) -> dict:
        return {"started": self.started, "bytes_moved": self.bytes_moved,
                "seconds": round(self.seconds, 2),
                "throughput_kbit": self.throughput_kbit,
                "errors": list(self.errors),
                "stopped_reason": self.stopped_reason}


class LoadGenerator:
    """Bütçeli yük üreticisi. ``stop()`` her zaman ve derhal geçerlidir."""

    def __init__(self, target: LoadTarget, budget: LoadBudget,
                 connect: "object | None" = None) -> None:
        self.target = target
        self.budget = budget.clamped()
        self.result = LoadResult()
        self._connect = connect or self._real_connect
        self._stop = threading.Event()
        self._threads: list = []
        self._lock = threading.Lock()
        self._started_at = 0.0

    # -- bağlantı ---------------------------------------------------------- #
    @staticmethod
    def _real_connect(host: str, port: int):
        sock = socket.create_connection((host, port), timeout=5)
        mark_socket(sock)
        sock.settimeout(5)
        return sock

    # -- yaşam döngüsü ------------------------------------------------------ #
    def start(self, metered: bool = False) -> LoadResult:
        problem = self.target.validate(metered=metered)
        if problem:
            self.result.errors.append(problem)
            self.result.stopped_reason = "izin yok"
            return self.result
        self._started_at = time.monotonic()
        self.result.started = True
        for _index in range(self.budget.streams):
            thread = threading.Thread(target=self._worker, daemon=True)
            thread.start()
            self._threads.append(thread)
        return self.result

    def stop(self, reason: str = "istendi") -> LoadResult:
        self._stop.set()
        for thread in self._threads:
            thread.join(timeout=3.0)
        self._threads = []
        if self.result.started:
            self.result.seconds = time.monotonic() - self._started_at
            if not self.result.stopped_reason:
                self.result.stopped_reason = reason
        return self.result

    def exhausted(self) -> bool:
        if not self.result.started:
            return True
        if self._stop.is_set():
            return True
        if time.monotonic() - self._started_at >= self.budget.max_seconds:
            self.result.stopped_reason = "süre bütçesi doldu"
            return True
        with self._lock:
            if self.result.bytes_moved >= self.budget.max_bytes:
                self.result.stopped_reason = "veri bütçesi doldu"
                return True
        return False

    def _account(self, count: int) -> None:
        with self._lock:
            self.result.bytes_moved += int(count)

    # -- işçi --------------------------------------------------------------- #
    def _worker(self) -> None:
        sock = None
        try:
            sock = self._connect(self.target.host, self.target.port)
            mode = self.target.mode
            if mode == "http-download":
                self._http_download(sock)
            elif mode == "http-upload":
                self._http_upload(sock)
            elif mode == "tcp-sink":
                self._raw_send(sock)
            else:
                self._raw_recv(sock)
        except OSError as exc:
            with self._lock:
                message = f"yük akışı başarısız: {exc}"
                if message not in self.result.errors:
                    self.result.errors.append(message)
        finally:
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass

    def _request(self, sock, verb: str, extra: str = "") -> None:
        request = (f"{verb} {self.target.path} HTTP/1.1\r\n"
                   f"Host: {self.target.host}\r\n"
                   f"User-Agent: dpi-bypass-latency/1\r\n"
                   f"Connection: close\r\n{extra}\r\n")
        sock.sendall(request.encode("ascii", "ignore"))

    def _http_download(self, sock) -> None:
        self._request(sock, "GET")
        self._raw_recv(sock)

    def _http_upload(self, sock) -> None:
        self._request(sock, "POST", "Transfer-Encoding: chunked\r\n")
        payload = b"\x00" * _CHUNK
        header = (f"{_CHUNK:x}\r\n").encode("ascii")
        while not self.exhausted():
            sock.sendall(header + payload + b"\r\n")
            self._account(_CHUNK)
        try:
            sock.sendall(b"0\r\n\r\n")
        except OSError:
            pass

    def _raw_send(self, sock) -> None:
        payload = b"\x00" * _CHUNK
        while not self.exhausted():
            sock.sendall(payload)
            self._account(_CHUNK)

    def _raw_recv(self, sock) -> None:
        while not self.exhausted():
            chunk = sock.recv(_CHUNK)
            if not chunk:
                self.result.stopped_reason = \
                    self.result.stopped_reason or "sunucu bağlantıyı kapattı"
                return
            self._account(len(chunk))
