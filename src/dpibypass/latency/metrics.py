"""Ölçüm veri modeli: hedef kimliği, endpoint başına örnekler ve özetler.

Tasarımın çekirdeği tek bir kuraldır: **farklı hedeflerin örnekleri tek bir
havuzda birleştirilmez.** Her endpoint kendi ``sent``/``received`` sayısını,
kendi hata dökümünü ve kendi özet istatistiğini taşır. Toplu (``remote``)
özet yalnızca geriye dönük uyumluluk ve ekran içindir; kararlar endpoint
bazında ve ``analysis`` modülündeki eşleştirilmiş karşılaştırmayla verilir.

Neden: iki hedefin yanıt *ağırlığı* değiştiğinde (hızlı hedef daha çok, yavaş
hedef daha az yanıtladığında) havuzlanmış median hiçbir endpoint'in RTT'si
iyileşmeden düşer. Bu, ölçülen değil uydurulan bir kazançtır.

Jitter tanımı
-------------
``jitter_ms`` = tek bir endpoint'in **kendi** örnek dizisindeki ardışık
farkların mutlak değer ortalaması (RFC 3393 anlamında IPDV'nin ortalama
mutlak değeri). Farklı endpoint'lerin doğal RTT farkı jitter değildir ve
bu hesaba asla girmez. Standart sapma ya da p95−min ile karıştırılmamalıdır;
``spread_ms`` (p95 − min) ayrı ve yalnızca bağlamsal bir göstergedir.
"""

from __future__ import annotations

import hashlib
import math
import re
import statistics
from dataclasses import asdict, dataclass, field
from typing import Sequence

#: Ölçüm koşulları. Boşta ve yük altındaki sonuçlar asla karıştırılmaz.
CONDITION_IDLE = "idle"
CONDITION_FIRST_PACKET = "first-packet"
CONDITION_LOAD_UP = "load-up"
CONDITION_LOAD_DOWN = "load-down"
CONDITION_LOAD_BOTH = "load-both"
CONDITION_NATURAL = "natural-traffic"
CONDITIONS = (CONDITION_IDLE, CONDITION_FIRST_PACKET, CONDITION_LOAD_UP,
              CONDITION_LOAD_DOWN, CONDITION_LOAD_BOTH, CONDITION_NATURAL)

#: Ölçüm yöntemleri. Bunlar **farklı metriklerdir**, birbirinin yerine
#: geçmez ve karşılaştırmada karıştırılmaz.
METHOD_ICMP = "icmp"            # saf ağ RTT'si
METHOD_TCP_CONNECT = "tcp-connect"   # SYN→SYN/ACK; el sıkışma süresi
METHOD_UDP_ECHO = "udp-echo"    # yalnız gerçekten yanıtlayan endpoint
METHOD_TLS_HANDSHAKE = "tls-handshake"
METHODS = (METHOD_ICMP, METHOD_TCP_CONNECT, METHOD_UDP_ECHO,
           METHOD_TLS_HANDSHAKE)

#: Endpoint rolleri. ``user`` kullanıcının seçtiği gerçek hedeftir ve
#: birincil karardır; ``reference`` yalnızca genel ağ göstergesidir ve
#: "oyun ping'i" diye sunulmaz.
ROLE_USER = "user"
ROLE_REFERENCE = "reference"
ROLE_GATEWAY = "gateway"

#: Hata türleri ayrı sayılır: TCP bağlantı hatası "paket kaybı" değildir.
ERROR_TIMEOUT = "timeout"
ERROR_UNREACHABLE = "unreachable"
ERROR_REFUSED = "refused"
ERROR_PARSE = "parse"
ERROR_PROCESS = "process"
ERROR_NO_REPLY = "no-reply"
ERROR_KINDS = (ERROR_TIMEOUT, ERROR_UNREACHABLE, ERROR_REFUSED, ERROR_PARSE,
               ERROR_PROCESS, ERROR_NO_REPLY)

_HOST_RE = re.compile(
    r"^(?=.{1,253}\Z)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(?:\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.?\Z")


def valid_hostname(host: str) -> bool:
    """Hedef adı DNS'e sorulabilecek biçimde mi? (Tarama yapmaz.)"""
    return bool(host) and len(host) <= 253 and bool(_HOST_RE.match(host))


def valid_port(port: object) -> bool:
    try:
        value = int(port)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return False
    return 1 <= value <= 65535


@dataclass(frozen=True)
class EndpointSpec:
    """Ölçüm hedefinin **tam** kimliği.

    Karşılaştırma boyunca bu alanların hepsi sabitlenir. Biri bile değişirse
    (adres ailesi, çözülen IP, arayüz, kaynak adresi, protokol, port) eski
    taban geçersizdir ve yeni baseline alınır: farklı bir yol ölçülüyordur.
    """

    host: str = ""            # kullanıcının yazdığı ad ya da IP
    address: str = ""         # sabitlenmiş IP; karşılaştırma bununla yapılır
    family: str = "ipv4"      # "ipv4" | "ipv6"
    port: int = 0             # ICMP için 0
    method: str = METHOD_ICMP
    interface: str = ""
    ifindex: int = 0
    source: str = ""          # ölçümün çıktığı kaynak adres
    role: str = ROLE_REFERENCE
    label: str = ""

    @property
    def key(self) -> str:
        raw = "|".join([self.address, self.family, str(self.port), self.method,
                        self.interface, str(self.ifindex), self.source])
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]

    @property
    def display(self) -> str:
        if self.label:
            return self.label
        if self.port:
            return f"{self.host or self.address}:{self.port}"
        return self.host or self.address

    def comparable_with(self, other: "EndpointSpec") -> bool:
        """İki ölçüm aynı yolu mu ölçtü? Değilse karşılaştırılamaz."""
        return (self.address == other.address and self.family == other.family
                and self.port == other.port and self.method == other.method
                and self.interface == other.interface
                and self.ifindex == other.ifindex
                and self.source == other.source)

    def to_dict(self) -> dict:
        data = asdict(self)
        data["key"] = self.key
        data["display"] = self.display
        return data

    @classmethod
    def from_dict(cls, data: dict) -> "EndpointSpec":
        if not isinstance(data, dict):
            raise ValueError("geçersiz endpoint kimliği")
        port = data.get("port", 0)
        try:
            port = int(port)
        except (TypeError, ValueError):
            raise ValueError("geçersiz endpoint portu")
        if not 0 <= port <= 65535:
            raise ValueError("geçersiz endpoint portu")
        method = data.get("method", METHOD_ICMP)
        if method not in METHODS:
            raise ValueError(f"bilinmeyen ölçüm yöntemi: {method!r}")
        family = data.get("family", "ipv4")
        if family not in ("ipv4", "ipv6"):
            raise ValueError("geçersiz adres ailesi")
        role = data.get("role", ROLE_REFERENCE)
        if role not in (ROLE_USER, ROLE_REFERENCE, ROLE_GATEWAY):
            raise ValueError("geçersiz endpoint rolü")
        try:
            ifindex = int(data.get("ifindex", 0) or 0)
        except (TypeError, ValueError):
            raise ValueError("geçersiz ifindex")
        return cls(
            host=str(data.get("host", ""))[:253],
            address=str(data.get("address", ""))[:64],
            family=family, port=port, method=method,
            interface=str(data.get("interface", ""))[:16],
            ifindex=ifindex,
            source=str(data.get("source", ""))[:64],
            role=role, label=str(data.get("label", ""))[:120],
        )


@dataclass
class EndpointSamples:
    """Tek bir endpoint'in ham ölçüm bloğu.

    ``sent`` **gerçekten gönderilen** sayıdır; planlanan ``count`` değil.
    Süreç zaman aşımına uğrarsa ya da komut hiç çalışmazsa bu ayrımı
    kaybetmemek için hata türleri ayrı sayılır.
    """

    spec: EndpointSpec
    rtt_ms: list = field(default_factory=list)
    sent: int = 0
    errors: dict = field(default_factory=dict)
    dns_ms: float | None = None
    block: int = 0
    arm: str = ""

    @property
    def received(self) -> int:
        return len(self.rtt_ms)

    def add_error(self, kind: str, count: int = 1) -> None:
        if kind not in ERROR_KINDS:
            kind = ERROR_PROCESS
        self.errors[kind] = int(self.errors.get(kind, 0)) + int(count)

    def stats(self) -> "EndpointStats":
        return EndpointStats.from_samples(self)


@dataclass
class EndpointStats:
    """Tek endpoint'in özeti. Havuzlama YOK."""

    spec: EndpointSpec = field(default_factory=EndpointSpec)
    sent: int = 0
    received: int = 0
    minimum_ms: float | None = None
    median_ms: float | None = None
    p95_ms: float | None = None
    #: Ardışık mutlak farkların ortalaması — yalnız bu endpoint içinde.
    jitter_ms: float | None = None
    #: p95 − min. Doygunluk testi DEĞİLDİR; gözlenen yayılımdır.
    spread_ms: float | None = None
    #: Yanıt gelmeyen oran. TCP/UDP için "başarısızlık oranı" anlamındadır;
    #: ICMP dışında buna "paket kaybı" denmez (bkz. ``loss_label``).
    failure_rate: float = 100.0
    errors: dict = field(default_factory=dict)
    dns_ms: float | None = None
    #: p95/p99 iddiası için yeterli örnek var mı?
    p95_reliable: bool = False

    #: p95'in anlamlı olabilmesi için gereken asgari örnek sayısı.
    P95_MIN_SAMPLES = 20

    @property
    def responded(self) -> bool:
        return self.received > 0

    @property
    def loss_label(self) -> str:
        return ("paket kaybı" if self.spec.method == METHOD_ICMP
                else "başarısızlık oranı")

    @classmethod
    def from_samples(cls, block: EndpointSamples) -> "EndpointStats":
        values = [float(value) for value in block.rtt_ms if value >= 0]
        sent = max(int(block.sent), 0)
        received = len(values)
        rate = 100.0 if sent <= 0 else max(0.0, (sent - received) * 100.0 / sent)
        if not values:
            return cls(spec=block.spec, sent=sent, received=0,
                       failure_rate=round(rate, 2), errors=dict(block.errors),
                       dns_ms=block.dns_ms)
        ordered = sorted(values)
        p95_index = max(0, math.ceil(len(ordered) * 0.95) - 1)
        differences = [abs(values[index] - values[index - 1])
                       for index in range(1, len(values))]
        return cls(
            spec=block.spec, sent=sent, received=received,
            minimum_ms=round(ordered[0], 3),
            median_ms=round(float(statistics.median(values)), 3),
            p95_ms=round(ordered[p95_index], 3),
            jitter_ms=round(float(statistics.mean(differences))
                            if differences else 0.0, 3),
            spread_ms=round(ordered[p95_index] - ordered[0], 3),
            failure_rate=round(rate, 2),
            errors=dict(block.errors),
            dns_ms=block.dns_ms,
            p95_reliable=received >= cls.P95_MIN_SAMPLES,
        )

    def metric(self, name: str) -> float | None:
        return {"median_ms": self.median_ms, "p95_ms": self.p95_ms,
                "jitter_ms": self.jitter_ms, "minimum_ms": self.minimum_ms,
                "failure_rate": self.failure_rate}.get(name)

    def to_dict(self) -> dict:
        return {
            "endpoint": self.spec.to_dict(),
            "sent": self.sent, "received": self.received,
            "minimum_ms": self.minimum_ms, "median_ms": self.median_ms,
            "p95_ms": self.p95_ms, "jitter_ms": self.jitter_ms,
            "spread_ms": self.spread_ms,
            "failure_rate": self.failure_rate,
            "loss_label": self.loss_label,
            "errors": dict(self.errors),
            "dns_ms": self.dns_ms,
            "p95_reliable": self.p95_reliable,
        }


@dataclass
class LatencyStats:
    """Ekran ve geriye dönük uyumluluk için **sabit ağırlıklı** özet.

    Her endpoint'e eşit ağırlık verilir: bir hedefin çok, diğerinin az yanıt
    vermesi özeti kaydıramaz. Hiç yanıt vermeyen endpoint özete girmez ama
    ``coverage`` üzerinden görünür kalır — "yavaş hedef sustu" bir iyileşme
    değil, kapsam kaybıdır.

    Bu sınıf karar vermek için kullanılmaz; kararlar ``analysis`` modülünde
    endpoint bazında ve eşleştirilmiş bloklarla verilir.
    """

    sent: int = 0
    received: int = 0
    median_ms: float | None = None
    minimum_ms: float | None = None
    p95_ms: float | None = None
    jitter_ms: float | None = None
    spread_ms: float | None = None
    packet_loss: float = 100.0
    #: Yanıt veren endpoint sayısı / toplam endpoint sayısı.
    coverage: float = 0.0
    endpoints_total: int = 0
    endpoints_responding: int = 0
    p95_reliable: bool = False

    @classmethod
    def from_endpoints(cls, stats: Sequence[EndpointStats]) -> "LatencyStats":
        total = len(stats)
        answered = [item for item in stats if item.responded]
        sent = sum(item.sent for item in stats)
        received = sum(item.received for item in stats)
        if not answered:
            return cls(sent=sent, received=received, packet_loss=100.0,
                       coverage=0.0, endpoints_total=total,
                       endpoints_responding=0)

        def mean_of(name: str) -> float | None:
            values = [item.metric(name) for item in answered]
            usable = [value for value in values if value is not None]
            return round(float(statistics.mean(usable)), 3) if usable else None

        minimums = [item.minimum_ms for item in answered
                    if item.minimum_ms is not None]
        # Kayıp/başarısızlık oranı da endpoint başına eşit ağırlıklıdır:
        # tüm endpoint'ler (yanıtsızlar dahil) sayılır, yoksa susan hedef
        # kaybı gizlerdi.
        loss = round(float(statistics.mean(
            [item.failure_rate for item in stats])), 2) if stats else 100.0
        p95 = mean_of("p95_ms")
        minimum = round(min(minimums), 3) if minimums else None
        return cls(
            sent=sent, received=received,
            median_ms=mean_of("median_ms"),
            minimum_ms=minimum,
            p95_ms=p95,
            jitter_ms=mean_of("jitter_ms"),
            spread_ms=(round(p95 - minimum, 3)
                       if p95 is not None and minimum is not None else None),
            packet_loss=loss,
            coverage=round(len(answered) / total, 3) if total else 0.0,
            endpoints_total=total,
            endpoints_responding=len(answered),
            p95_reliable=all(item.p95_reliable for item in answered),
        )

    @classmethod
    def from_samples(cls, samples: Sequence[float], sent: int) -> "LatencyStats":
        """Tek bir endpoint dizisinden özet (ağ geçidi ve testler için)."""
        block = EndpointSamples(spec=EndpointSpec(),
                                rtt_ms=[float(value) for value in samples],
                                sent=int(sent))
        single = EndpointStats.from_samples(block)
        stats = cls.from_endpoints([single])
        stats.sent = int(sent)
        stats.received = single.received
        stats.packet_loss = single.failure_rate
        return stats

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class LatencyMeasurement:
    """Bir koşulda, sabitlenmiş hedef kümesiyle alınmış tek ölçüm bloğu."""

    method: str = METHOD_ICMP
    gateway: LatencyStats = field(default_factory=LatencyStats)
    remote: LatencyStats = field(default_factory=LatencyStats)
    targets: list = field(default_factory=list)
    measured_at: float = 0.0
    rounds: int = 1
    condition: str = CONDITION_IDLE
    endpoints: list = field(default_factory=list)   # list[EndpointStats]
    gateway_endpoint: EndpointStats | None = None
    #: Ölçüm sırasında yolun doğrulanıp doğrulanmadığı. False ise bu ölçüm
    #: karar için kullanılmaz: yanlış arayüzü/yolu ölçmüş olabiliriz.
    path_verified: bool = True
    notes: list = field(default_factory=list)
    block: int = 0
    arm: str = ""

    def __post_init__(self) -> None:
        if not self.measured_at:
            import time as _time
            self.measured_at = _time.time()

    @property
    def connected(self) -> bool:
        return self.remote.received > 0

    @property
    def user_endpoints(self) -> list:
        return [item for item in self.endpoints if item.spec.role == ROLE_USER]

    @property
    def primary_endpoints(self) -> list:
        """Karar birincil olarak kullanıcının hedeflerine dayanır."""
        return self.user_endpoints or list(self.endpoints)

    def endpoint_map(self) -> dict:
        return {item.spec.key: item for item in self.endpoints}

    def comparable_with(self, other: "LatencyMeasurement") -> tuple[bool, str]:
        """İki ölçüm aynı metriği, aynı koşulda, aynı yolda mı aldı?"""
        if self.condition != other.condition:
            return False, "ölçüm koşulu değişti"
        if self.method != other.method:
            return False, "ölçüm yöntemi değişti"
        if not self.path_verified or not other.path_verified:
            return False, "ölçüm yolu doğrulanamadı"
        mine, theirs = self.endpoint_map(), other.endpoint_map()
        shared = set(mine) & set(theirs)
        if not shared:
            return False, "ortak ölçüm hedefi yok"
        for key in shared:
            if not mine[key].spec.comparable_with(theirs[key].spec):
                return False, "hedef kimliği değişti"
        return True, ""

    def to_dict(self) -> dict:
        return {
            "method": self.method,
            "gateway": self.gateway.to_dict(),
            "remote": self.remote.to_dict(),
            "targets": list(self.targets),
            "measured_at": self.measured_at,
            "rounds": self.rounds,
            "condition": self.condition,
            "endpoints": [item.to_dict() for item in self.endpoints],
            "gateway_endpoint": (self.gateway_endpoint.to_dict()
                                 if self.gateway_endpoint else None),
            "path_verified": self.path_verified,
            "notes": list(self.notes),
        }

    @classmethod
    def from_blocks(cls, blocks: Sequence[EndpointSamples],
                    gateway_block: EndpointSamples | None = None,
                    condition: str = CONDITION_IDLE,
                    rounds: int = 1, path_verified: bool = True,
                    notes: Sequence[str] = ()) -> "LatencyMeasurement":
        stats = [block.stats() for block in blocks]
        methods = {item.spec.method for item in stats}
        gateway_stats = gateway_block.stats() if gateway_block else None
        return cls(
            method=(methods.pop() if len(methods) == 1 else "mixed"),
            gateway=(LatencyStats.from_endpoints([gateway_stats])
                     if gateway_stats else LatencyStats()),
            remote=LatencyStats.from_endpoints(stats),
            targets=[item.spec.display for item in stats],
            rounds=rounds, condition=condition, endpoints=stats,
            gateway_endpoint=gateway_stats,
            path_verified=path_verified, notes=list(notes),
        )
