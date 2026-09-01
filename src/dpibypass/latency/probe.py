"""Ölçüm: hedef çözümleme, yol doğrulama ve protokol başına örnekleme.

Kurallar
--------
* **Hedef kimliği sabitlenir.** Ad bir kez çözülür, IP sabitlenir ve bütün
  karşılaştırma boyunca aynı IP ölçülür. DNS süresi ayrı bir metriktir ve
  RTT'ye karıştırılmaz.
* **Yöntemler karıştırılmaz.** ICMP RTT, TCP connect (SYN→SYN/ACK), UDP
  yankı ve TLS el sıkışması ayrı metriklerdir. TCP bağlantı hatasına "paket
  kaybı" denmez.
* **Yol doğrulanır.** ``ip route get`` ile hedefe giden gerçek arayüz ve
  kaynak adres okunur. Ölçüm beklenen arayüzden çıkmıyorsa ölçüm geçersiz
  sayılır; yanlış yol optimize edilmez.
* **Soket işareti kontrol edilir.** ``SO_MARK`` konamazsa TCP/TLS ölçümü
  kendi şeffaf proxy'mize düşebilir; o durumda örnek toplanmaz.
* **Gerçek gönderim sayısı kullanılır.** ``ping`` özetindeki "N packets
  transmitted" değeri esas alınır; planlanan ``count`` varsayılmaz.
"""

from __future__ import annotations

import concurrent.futures
import ipaddress
import json
import logging
import re
import socket
import ssl
import time
from dataclasses import dataclass, field
from typing import Callable, Sequence

from ..util import bind_to_device, mark_socket, run, which
from .metrics import (CONDITION_IDLE, EndpointSamples, EndpointSpec,
                      ERROR_NO_REPLY, ERROR_PARSE, ERROR_PROCESS,
                      ERROR_REFUSED, ERROR_TIMEOUT, ERROR_UNREACHABLE,
                      LatencyMeasurement, METHOD_ICMP, METHOD_TCP_CONNECT,
                      METHOD_TLS_HANDSHAKE, METHOD_UDP_ECHO, ROLE_GATEWAY,
                      ROLE_REFERENCE, ROLE_USER, valid_hostname, valid_port)

log = logging.getLogger("dpibypass.latency.probe")

#: Ölçüm komutları her zaman C yereliyle çalışır: yerelleşmiş ``ping``
#: ondalık ayırıcıyı ("12,3 ms") ve özet satırlarını değiştirebilir.
PROBE_ENV = {"LC_ALL": "C", "LANG": "C", "LANGUAGE": "C"}

#: "time=12.3 ms" ve "time<1 ms" — ikisi de geçerli yanıt.
_PING_TIME_RE = re.compile(r"\btime[=<]\s*([0-9]+(?:\.[0-9]+)?)\s*ms", re.I)
#: Yinelenen yanıtlar ayrı sayılır; alınan paket sayısını şişirmemeli.
_PING_DUP_RE = re.compile(r"\(DUP!\)")
_PING_SUMMARY_RE = re.compile(
    r"(\d+)\s+packets transmitted,\s*(\d+)\s*(?:packets\s+)?received", re.I)
_PING_ERRORS_RE = re.compile(r"\+(\d+)\s+errors", re.I)
_PING_DUPS_RE = re.compile(r"\+(\d+)\s+duplicates", re.I)
_PING_UNREACH_RE = re.compile(
    r"(Destination .*Unreachable|Network is unreachable|"
    r"No route to host|unknown host|Name or service not known)", re.I)

#: Kullanıcı hedefinde desteklenen protokoller. Sessiz port taraması yok:
#: her hedefin protokolü ve portu kullanıcı tarafından belirtilir.
USER_PROTOCOLS = ("icmp", "tcp", "udp", "tls")
_PROTOCOL_METHOD = {
    "icmp": METHOD_ICMP,
    "tcp": METHOD_TCP_CONNECT,
    "udp": METHOD_UDP_ECHO,
    "tls": METHOD_TLS_HANDSHAKE,
}

#: Kullanıcı hedefi yokken kullanılan **genel ağ göstergesi** hedefleri.
#: Bunlar oyun ping'i değildir ve öyle etiketlenmez.
REFERENCE_TARGETS = (("1.1.1.1", 443), ("8.8.8.8", 443))


# --------------------------------------------------------------------------- #
# hedef tanımı
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class TargetSpec:
    """Kullanıcının tanımladığı ölçüm hedefi (henüz çözülmemiş)."""

    host: str
    port: int = 0
    protocol: str = "icmp"
    family: str = "auto"          # "auto" | "ipv4" | "ipv6"
    label: str = ""
    role: str = ROLE_USER

    def validate(self) -> str:
        """Boş dize = geçerli; aksi halde kullanıcıya gösterilecek hata."""
        if self.protocol not in USER_PROTOCOLS:
            return f"desteklenmeyen protokol: {self.protocol}"
        if self.family not in ("auto", "ipv4", "ipv6"):
            return f"desteklenmeyen adres ailesi: {self.family}"
        if not self.host or not valid_hostname(self.host):
            try:
                ipaddress.ip_address(self.host)
            except ValueError:
                return f"geçersiz hedef adı: {self.host!r}"
        if self.protocol == "icmp":
            if self.port not in (0, None):
                return "ICMP hedefinde port kullanılmaz"
        elif not valid_port(self.port):
            return f"{self.protocol} hedefi için geçerli bir port gerekiyor"
        if len(self.label) > 120:
            return "hedef etiketi çok uzun"
        return ""

    def to_dict(self) -> dict:
        return {"host": self.host, "port": int(self.port or 0),
                "protocol": self.protocol, "family": self.family,
                "label": self.label, "role": self.role}

    @classmethod
    def from_dict(cls, data: dict) -> "TargetSpec":
        if not isinstance(data, dict):
            raise ValueError("geçersiz hedef tanımı")
        try:
            port = int(data.get("port", 0) or 0)
        except (TypeError, ValueError):
            raise ValueError("geçersiz hedef portu")
        target = cls(host=str(data.get("host", ""))[:253], port=port,
                     protocol=str(data.get("protocol", "icmp")),
                     family=str(data.get("family", "auto")),
                     label=str(data.get("label", ""))[:120],
                     role=str(data.get("role", ROLE_USER)))
        problem = target.validate()
        if problem:
            raise ValueError(problem)
        return target


@dataclass
class PathInfo:
    """``ip route get`` sonucu: hedefe giden **gerçek** yol."""

    interface: str = ""
    source: str = ""
    gateway: str = ""
    ok: bool = False
    reason: str = ""


@dataclass
class ProbePlan:
    """Bir ölçüm bloğunun tam tanımı; koşul ve hedefler burada sabitlenir."""

    endpoints: list = field(default_factory=list)     # list[EndpointSpec]
    gateway: str = ""
    interface: str = ""
    condition: str = CONDITION_IDLE
    samples: int = 8
    rounds: int = 1
    warmup: bool = False
    #: Bloğun kimliği; eşleştirilmiş analizde hangi bloğa ait olduğu.
    block: int = 0
    arm: str = ""
    path_verified: bool = True
    notes: list = field(default_factory=list)


# --------------------------------------------------------------------------- #
# yol ve çözümleme
# --------------------------------------------------------------------------- #
class PathResolver:
    """Rota keşfi: tek default-route satırına güvenmez, hedefe göre sorar."""

    def __init__(self, runner: Callable = run,
                 which_fn: Callable[[str], "str | None"] = which) -> None:
        self.runner = runner
        self.which = which_fn

    def route_to(self, address: str) -> PathInfo:
        """Hedefe giden arayüz ve kaynak adresi."""
        if self.which("ip") is None:
            return PathInfo(reason="ip aracı yok; rota doğrulanamadı")
        family = "-6" if _is_v6(address) else "-4"
        result = self.runner(["ip", family, "-j", "route", "get", address],
                             timeout=5, env=PROBE_ENV)
        info = self._parse_json_route(_stdout(result)) \
            if _rc(result) == 0 else PathInfo()
        if info.ok:
            return info
        # -j desteklenmiyorsa (eski iproute2) dar ve testli metin yolu.
        result = self.runner(["ip", family, "route", "get", address],
                             timeout=5, env=PROBE_ENV)
        if _rc(result) != 0:
            return PathInfo(reason="hedefe giden rota bulunamadı")
        return self._parse_text_route(_stdout(result))

    @staticmethod
    def _parse_json_route(output: str) -> PathInfo:
        try:
            data = json.loads(output)
        except ValueError:
            return PathInfo()
        if not isinstance(data, list) or not data:
            return PathInfo()
        entry = data[0]
        if not isinstance(entry, dict):
            return PathInfo()
        iface = str(entry.get("dev", "") or "")
        if not iface:
            return PathInfo()
        return PathInfo(interface=iface, source=str(entry.get("prefsrc", "") or ""),
                        gateway=str(entry.get("gateway", "") or ""), ok=True)

    @staticmethod
    def _parse_text_route(output: str) -> PathInfo:
        text = " ".join(output.split())
        dev = re.search(r"\bdev\s+([A-Za-z0-9_.@-]{1,15})", text)
        if dev is None:
            return PathInfo(reason="rota çıktısı ayrıştırılamadı")
        src = re.search(r"\bsrc\s+(\S+)", text)
        via = re.search(r"\bvia\s+(\S+)", text)
        return PathInfo(interface=dev.group(1),
                        source=src.group(1) if src else "",
                        gateway=via.group(1) if via else "", ok=True)


def _is_v6(address: str) -> bool:
    try:
        return ipaddress.ip_address(address).version == 6
    except ValueError:
        return ":" in address


def _rc(result) -> int:
    return int(getattr(result, "returncode", 1) or 0)


def _stdout(result) -> str:
    return str(getattr(result, "stdout", "") or "")


def _ifindex(interface: str) -> int:
    try:
        return socket.if_nametoindex(interface)
    except (OSError, ValueError):
        return 0


@dataclass
class ResolvedTarget:
    spec: EndpointSpec
    dns_ms: float | None = None
    path: PathInfo = field(default_factory=PathInfo)
    error: str = ""


class TargetResolver:
    """Adı bir kez çözer, IP'yi sabitler, DNS süresini ayrı raporlar."""

    def __init__(self, resolver: Callable | None = None,
                 path_resolver: PathResolver | None = None) -> None:
        self._getaddrinfo = resolver or socket.getaddrinfo
        self.paths = path_resolver or PathResolver()

    def resolve(self, target: TargetSpec,
                expected_interface: str = "") -> ResolvedTarget:
        problem = target.validate()
        if problem:
            return ResolvedTarget(spec=EndpointSpec(host=target.host),
                                  error=problem)
        family = {"ipv4": socket.AF_INET, "ipv6": socket.AF_INET6,
                  "auto": socket.AF_UNSPEC}[target.family]
        literal = _literal(target.host)
        dns_ms = None
        if literal is not None:
            address, version = literal
        else:
            started = time.perf_counter()
            try:
                infos = self._getaddrinfo(target.host, target.port or None,
                                          family, socket.SOCK_STREAM)
            except (OSError, socket.gaierror) as exc:
                return ResolvedTarget(spec=EndpointSpec(host=target.host),
                                      error=f"ad çözülemedi: {exc}")
            # DNS süresi RTT DEĞİLDİR; ayrı metrik olarak taşınır.
            dns_ms = round((time.perf_counter() - started) * 1000.0, 3)
            if not infos:
                return ResolvedTarget(spec=EndpointSpec(host=target.host),
                                      error="ad hiçbir adrese çözülmedi")
            sockaddr = infos[0][4]
            address = str(sockaddr[0])
            version = 6 if infos[0][0] == socket.AF_INET6 else 4

        path = self.paths.route_to(address)
        interface = path.interface or expected_interface
        spec = EndpointSpec(
            host=target.host, address=address,
            family="ipv6" if version == 6 else "ipv4",
            port=int(target.port or 0),
            method=_PROTOCOL_METHOD[target.protocol],
            interface=interface, ifindex=_ifindex(interface),
            source=path.source, role=target.role,
            label=target.label or _default_label(target),
        )
        return ResolvedTarget(spec=spec, dns_ms=dns_ms, path=path)


def _literal(host: str):
    try:
        parsed = ipaddress.ip_address(host)
    except ValueError:
        return None
    return str(parsed), parsed.version


def _default_label(target: TargetSpec) -> str:
    if target.protocol == "icmp":
        return f"{target.host} (ICMP)"
    return f"{target.host}:{target.port} ({target.protocol.upper()})"


# --------------------------------------------------------------------------- #
# ping çıktısı
# --------------------------------------------------------------------------- #
@dataclass
class PingOutcome:
    rtt_ms: list = field(default_factory=list)
    transmitted: int = 0
    received: int = 0
    duplicates: int = 0
    errors: dict = field(default_factory=dict)


def parse_ping(output: str, returncode: int, planned: int) -> PingOutcome:
    """``ping`` çıktısını dayanıklı biçimde ayrıştır.

    Ele alınanlar: ``time<1 ms``, yinelenen yanıtlar ``(DUP!)``, eksik özet
    satırı, süreç zaman aşımı (rc 124), erişilemez hedef ve kısmen geçerli
    çıktı. Kısmi çıktı ASLA atılmaz: alınan gerçek örnekler korunur.
    """
    outcome = PingOutcome()
    lines = output.splitlines()
    for line in lines:
        match = _PING_TIME_RE.search(line)
        if match is None:
            continue
        if _PING_DUP_RE.search(line):
            # Yinelenen yanıt: alınan paket sayısını şişirmemeli.
            outcome.duplicates += 1
            continue
        try:
            outcome.rtt_ms.append(float(match.group(1)))
        except ValueError:
            outcome.errors[ERROR_PARSE] = outcome.errors.get(ERROR_PARSE, 0) + 1

    summary = _PING_SUMMARY_RE.search(output)
    if summary is not None:
        outcome.transmitted = int(summary.group(1))
        outcome.received = int(summary.group(2))
        errors = _PING_ERRORS_RE.search(output)
        if errors:
            outcome.errors[ERROR_UNREACHABLE] = int(errors.group(1))
        dups = _PING_DUPS_RE.search(output)
        if dups:
            outcome.duplicates = max(outcome.duplicates, int(dups.group(1)))
    else:
        # Özet yok: süreç yarıda kesilmiş olabilir. Planlanan sayıyı gerçek
        # gönderim varsaymak yerine, en az gördüğümüz yanıt kadar gönderildiği
        # kesindir; rc 124 (timeout) durumunda bunu ayrıca işaretleriz.
        outcome.transmitted = max(len(outcome.rtt_ms), 0)
        if returncode == 124:
            outcome.errors[ERROR_PROCESS] = 1
            outcome.transmitted = max(outcome.transmitted, 1)
        elif returncode == 127:
            outcome.errors[ERROR_PROCESS] = 1
        elif _PING_UNREACH_RE.search(output):
            outcome.errors[ERROR_UNREACHABLE] = \
                outcome.errors.get(ERROR_UNREACHABLE, 0) + 1
            outcome.transmitted = max(outcome.transmitted, planned)
        else:
            outcome.errors[ERROR_PARSE] = outcome.errors.get(ERROR_PARSE, 0) + 1
        outcome.received = len(outcome.rtt_ms)

    # Özet "received" diyor ama o kadar RTT satırı ayrıştıramadıysak fark
    # bir ayrıştırma boşluğudur; sessizce yutulmaz. İstatistik yalnızca
    # gerçekten okunmuş RTT değerleriyle kurulur.
    parsed = len(outcome.rtt_ms)
    if outcome.received > parsed:
        outcome.errors[ERROR_PARSE] = (outcome.errors.get(ERROR_PARSE, 0)
                                       + outcome.received - parsed)
    outcome.received = parsed
    accounted = parsed + sum(outcome.errors.get(kind, 0)
                             for kind in (ERROR_UNREACHABLE, ERROR_PARSE))
    missing = max(0, outcome.transmitted - accounted)
    if missing:
        outcome.errors[ERROR_TIMEOUT] = outcome.errors.get(ERROR_TIMEOUT, 0) + missing
    return outcome


# --------------------------------------------------------------------------- #
# probe
# --------------------------------------------------------------------------- #
class LatencyProbe:
    """Plan verilen hedeflerden protokol başına örnek toplar."""

    def __init__(self, runner: Callable = run,
                 which_fn: Callable[[str], "str | None"] = which,
                 samples: int = 8, deadline: int = 5,
                 rounds: int = 1, warmup: bool = False,
                 interval: float = 0.2, quiet_seconds: float = 3.0,
                 first_packet_count: int = 3) -> None:
        self.runner = runner
        self.which = which_fn
        self.samples = max(3, int(samples))
        self.deadline = max(2, int(deadline))
        self.rounds = max(1, int(rounds))
        self.warmup = bool(warmup)
        self.interval = float(interval)
        #: ``first-packet`` koşulunda ölçümden önceki kontrollü sessizlik.
        self.quiet_seconds = max(0.5, float(quiet_seconds))
        self.first_packet_count = max(1, int(first_packet_count))

    # -- ICMP ------------------------------------------------------------- #
    def _ping(self, spec: EndpointSpec, count: int) -> PingOutcome:
        if self.which("ping") is None:
            outcome = PingOutcome()
            outcome.errors[ERROR_PROCESS] = 1
            return outcome
        # Süre sınırı örnek sayısına göre ölçeklenir. Sabit bir ``-w`` ile
        # uzun örnek dizileri sessizce kesilir ve elde ettiğimiz şey
        # planladığımızdan az örnek olurdu; bu da p95 iddiasını zayıflatır.
        deadline = max(self.deadline, int(count * self.interval) + 3)
        cmd = ["ping", "-n", "-4" if spec.family == "ipv4" else "-6",
               "-c", str(count), "-i", f"{self.interval:g}",
               "-W", "1", "-w", str(deadline)]
        if spec.interface:
            cmd.extend(["-I", spec.interface])
        cmd.append(spec.address)
        result = self.runner(cmd, timeout=deadline + 3, env=PROBE_ENV)
        return parse_ping(_stdout(result), _rc(result), count)

    # -- TCP connect ------------------------------------------------------- #
    def _tcp(self, spec: EndpointSpec, count: int,
             block: EndpointSamples) -> None:
        family = socket.AF_INET6 if spec.family == "ipv6" else socket.AF_INET
        for _index in range(count):
            sock = None
            try:
                sock = socket.socket(family, socket.SOCK_STREAM)
                sock.settimeout(1.5)
                # İşaret konamazsa ölçüm kendi şeffaf yönlendirmemize düşebilir
                # ve o zaman ölçtüğümüz şey ağ RTT'si değil, yerel proxy'nin
                # connect süresidir. Böyle bir örneği toplamıyoruz.
                if not mark_socket(sock):
                    block.add_error(ERROR_PROCESS)
                    continue
                if spec.interface and not bind_to_device(sock, spec.interface):
                    # Bağlanamamak ölümcül değil: rota zaten doğrulandı.
                    log.debug("%s arayüzüne bağlanılamadı; rota doğrulandığı "
                              "için ölçüme devam ediliyor", spec.interface)
                started = time.perf_counter()
                sock.connect((spec.address, spec.port))
                block.rtt_ms.append((time.perf_counter() - started) * 1000.0)
            except socket.timeout:
                block.add_error(ERROR_TIMEOUT)
            except ConnectionRefusedError:
                block.add_error(ERROR_REFUSED)
            except OSError as exc:
                block.add_error(ERROR_UNREACHABLE if exc.errno else ERROR_PROCESS)
            finally:
                block.sent += 1
                if sock is not None:
                    try:
                        sock.close()
                    except OSError:
                        pass

    # -- TLS el sıkışması --------------------------------------------------- #
    def _tls(self, spec: EndpointSpec, count: int,
             block: EndpointSamples) -> None:
        family = socket.AF_INET6 if spec.family == "ipv6" else socket.AF_INET
        # IP sabitlenir ama SNI ve sertifika doğrulaması KORUNUR: ölçüm için
        # güvenliği gevşetmeyiz.
        context = ssl.create_default_context()
        for _index in range(count):
            sock = None
            wrapped = None
            try:
                sock = socket.socket(family, socket.SOCK_STREAM)
                sock.settimeout(3.0)
                if not mark_socket(sock):
                    block.add_error(ERROR_PROCESS)
                    continue
                started = time.perf_counter()
                sock.connect((spec.address, spec.port))
                wrapped = context.wrap_socket(sock, server_hostname=spec.host)
                block.rtt_ms.append((time.perf_counter() - started) * 1000.0)
            except socket.timeout:
                block.add_error(ERROR_TIMEOUT)
            except ssl.SSLError:
                block.add_error(ERROR_REFUSED)
            except ConnectionRefusedError:
                block.add_error(ERROR_REFUSED)
            except OSError:
                block.add_error(ERROR_UNREACHABLE)
            finally:
                block.sent += 1
                for handle in (wrapped, sock):
                    if handle is not None:
                        try:
                            handle.close()
                        except OSError:
                            pass

    # -- UDP yankı ---------------------------------------------------------- #
    def _udp(self, spec: EndpointSpec, count: int,
             block: EndpointSamples, payload: bytes = b"\x00") -> None:
        """Yalnız GERÇEKTEN yanıt veren endpoint'te RTT ölçer.

        Açık bir UDP portuna veri göndermek tek başına RTT ölçümü değildir:
        yanıt gelmezse örnek yoktur ve bu ``no-reply`` olarak raporlanır,
        "paket kaybı" diye değil.
        """
        family = socket.AF_INET6 if spec.family == "ipv6" else socket.AF_INET
        for _index in range(count):
            sock = None
            try:
                sock = socket.socket(family, socket.SOCK_DGRAM)
                sock.settimeout(1.5)
                if not mark_socket(sock):
                    block.add_error(ERROR_PROCESS)
                    continue
                started = time.perf_counter()
                sock.sendto(payload, (spec.address, spec.port))
                sock.recvfrom(2048)
                block.rtt_ms.append((time.perf_counter() - started) * 1000.0)
            except socket.timeout:
                block.add_error(ERROR_NO_REPLY)
            except ConnectionRefusedError:
                block.add_error(ERROR_REFUSED)
            except OSError:
                block.add_error(ERROR_UNREACHABLE)
            finally:
                block.sent += 1
                if sock is not None:
                    try:
                        sock.close()
                    except OSError:
                        pass

    # -- tek endpoint ------------------------------------------------------- #
    def sample_endpoint(self, spec: EndpointSpec, count: int,
                        dns_ms: float | None = None) -> EndpointSamples:
        block = EndpointSamples(spec=spec, dns_ms=dns_ms)
        if spec.method == METHOD_ICMP:
            outcome = self._ping(spec, count)
            block.rtt_ms.extend(outcome.rtt_ms)
            block.sent = outcome.transmitted or count
            for kind, value in outcome.errors.items():
                block.add_error(kind, value)
        elif spec.method == METHOD_TCP_CONNECT:
            self._tcp(spec, count, block)
        elif spec.method == METHOD_TLS_HANDSHAKE:
            self._tls(spec, count, block)
        elif spec.method == METHOD_UDP_ECHO:
            self._udp(spec, count, block)
        else:
            block.add_error(ERROR_PROCESS)
        return block

    def _warm(self, plan: ProbePlan) -> None:
        """Rota/ARP açılışını ölçüme karıştırma.

        Not: ısınma turu **koşula bağlıdır**. ``first-packet`` koşulunda ilk
        paketler ölçümün konusudur ve atılmaz.
        """
        for spec in plan.endpoints[:2]:
            try:
                self.sample_endpoint(spec, 2)
            except Exception as exc:
                log.debug("ısınma turu başarısız: %s", exc)

    def _quiet(self, seconds: float) -> None:
        """Kontrollü sessizlik: Wi-Fi güç tasarrufunun uyumasına izin ver.

        Sürekli probe trafiği uyku davranışını DEĞİŞTİRİR: hiç susmayan bir
        ölçüm, güç tasarrufunun ilk-paket cezasını hiçbir zaman göremez.
        Bu yüzden ``first-packet`` koşulunda önce gerçekten susulur.
        """
        deadline = time.monotonic() + max(0.0, seconds)
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return
            time.sleep(min(0.25, remaining))

    def measure_first_packet(self, plan: ProbePlan) -> LatencyMeasurement:
        """Bekleme sonrası ilk paketleri ayrı ölç.

        Her endpoint için, sessizlik süresinin ardından yalnız
        ``first_packet_count`` kadar paket gönderilir; ısınma yapılmaz ve
        ilk paketler atılmaz. Sonuç ayrı bir koşul olarak etiketlenir ve
        boşta ölçümle karıştırılmaz.

        Uyarı: bu ölçüm sürücüye bağlıdır. Bazı sürücüler dinamik güç
        tasarrufunu farklı zamanlarda uygular; tek bir yüksek ilk-paket
        değeri tek başına "güç tasarrufu suçlu" kanıtı değildir.
        """
        merged: dict = {}
        for _round in range(max(1, plan.rounds)):
            for spec in plan.endpoints:
                self._quiet(self.quiet_seconds)
                block = self.sample_endpoint(spec, self.first_packet_count)
                existing = merged.get(spec.key)
                if existing is None:
                    merged[spec.key] = block
                    continue
                existing.rtt_ms.extend(block.rtt_ms)
                existing.sent += block.sent
                for kind, value in block.errors.items():
                    existing.add_error(kind, value)
        measurement = LatencyMeasurement.from_blocks(
            [merged[spec.key] for spec in plan.endpoints if spec.key in merged],
            condition="first-packet", rounds=plan.rounds,
            path_verified=plan.path_verified,
            notes=list(plan.notes) + [
                f"her hedef için {self.quiet_seconds:g} sn sessizlik sonrası "
                f"ilk {self.first_packet_count} paket ölçüldü; ısınma "
                f"yapılmadı"])
        measurement.block = plan.block
        measurement.arm = plan.arm
        return measurement

    # -- ölçüm bloğu -------------------------------------------------------- #
    def measure(self, plan: ProbePlan) -> LatencyMeasurement:
        """Planı uygula ve endpoint bazında özetlenmiş bir ölçüm bloğu döndür."""
        if plan.condition == "first-packet":
            return self.measure_first_packet(plan)
        if self.warmup and plan.warmup:
            self._warm(plan)

        merged: dict = {}
        for _round in range(max(1, plan.rounds)):
            # Hedefler EŞZAMANLI örneklenir. Bu yalnız hız için değil:
            # eşleştirilmiş analizde bütün endpoint'lerin aynı zaman
            # penceresini görmesi gerekir, yoksa hedefler arasındaki fark
            # ağın o anki durumundan kaynaklanır.
            workers = max(1, min(4, len(plan.endpoints)))
            with concurrent.futures.ThreadPoolExecutor(
                    max_workers=workers) as pool:
                jobs = [(spec, pool.submit(self.sample_endpoint, spec,
                                           plan.samples))
                        for spec in plan.endpoints]
                for spec, future in jobs:
                    try:
                        block = future.result()
                    except Exception as exc:
                        log.debug("%s örneklenemedi: %s", spec.display, exc)
                        block = EndpointSamples(spec=spec, sent=plan.samples)
                        block.add_error(ERROR_PROCESS, plan.samples)
                    existing = merged.get(spec.key)
                    if existing is None:
                        merged[spec.key] = block
                        continue
                    existing.rtt_ms.extend(block.rtt_ms)
                    existing.sent += block.sent
                    for kind, value in block.errors.items():
                        existing.add_error(kind, value)

        gateway_block = None
        if plan.gateway:
            gateway_spec = EndpointSpec(
                host=plan.gateway, address=plan.gateway,
                family="ipv6" if _is_v6(plan.gateway) else "ipv4",
                method=METHOD_ICMP, interface=plan.interface,
                ifindex=_ifindex(plan.interface), role=ROLE_GATEWAY,
                label=f"ağ geçidi {plan.gateway}")
            gateway_block = self.sample_endpoint(gateway_spec, plan.samples)

        measurement = LatencyMeasurement.from_blocks(
            [merged[spec.key] for spec in plan.endpoints if spec.key in merged],
            gateway_block=gateway_block, condition=plan.condition,
            rounds=plan.rounds, path_verified=plan.path_verified,
            notes=plan.notes)
        measurement.block = plan.block
        measurement.arm = plan.arm
        return measurement


# --------------------------------------------------------------------------- #
# plan kurulumu
# --------------------------------------------------------------------------- #
def build_plan(targets: Sequence[TargetSpec], interface: str, gateway: str,
               resolver: TargetResolver | None = None,
               condition: str = CONDITION_IDLE, samples: int = 8,
               rounds: int = 1, warmup: bool = True,
               require_interface: bool = True) -> ProbePlan:
    """Hedefleri çöz, yolu doğrula ve ölçüm planını sabitle.

    Yol doğrulaması başarısızsa plan ``path_verified=False`` ile döner:
    motor böyle bir ölçümü karar için kullanmaz. Hedefin gerçek rotası
    beklenen arayüzden geçmiyorsa (VPN, policy routing, çoklu rota) hedef
    plana **alınmaz** ve nedeni not edilir — trafiği tünelin dışına
    zorlamayız.
    """
    resolver = resolver or TargetResolver()
    plan = ProbePlan(gateway=gateway, interface=interface, condition=condition,
                     samples=samples, rounds=rounds, warmup=warmup)
    for target in targets:
        resolved = resolver.resolve(target, expected_interface=interface)
        if resolved.error:
            plan.notes.append(f"{target.host}: {resolved.error}")
            continue
        path = resolved.path
        if not path.ok:
            plan.notes.append(
                f"{target.host}: hedefe giden rota doğrulanamadı"
                + (f" ({path.reason})" if path.reason else ""))
            plan.path_verified = False
            continue
        if require_interface and interface and path.interface != interface:
            plan.notes.append(
                f"{target.host}: trafik {path.interface} üzerinden gidiyor, "
                f"optimize edilen arayüz {interface}; hedef ölçüme alınmadı")
            continue
        plan.endpoints.append(resolved.spec)
        if resolved.dns_ms is not None:
            plan.notes.append(
                f"{target.host}: DNS çözümlemesi {resolved.dns_ms:g} ms "
                f"(RTT'ye dahil değil)")
    if not plan.endpoints:
        plan.path_verified = False
        plan.notes.append("ölçülebilecek doğrulanmış hedef kalmadı")
    return plan


def reference_targets() -> list:
    """Kullanıcı hedefi yokken kullanılan genel ağ göstergeleri."""
    return [TargetSpec(host=host, port=0, protocol="icmp",
                       family="ipv4", role=ROLE_REFERENCE,
                       label=f"{host} (genel ağ göstergesi)")
            for host, _port in REFERENCE_TARGETS]
