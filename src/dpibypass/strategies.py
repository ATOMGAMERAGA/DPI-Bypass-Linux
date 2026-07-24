"""Atlatma stratejileri kataloğu.

Her strateji, bir TCP bağlantısındaki *ilk* istemci verisinin (TLS
ClientHello ya da HTTP isteği) tel üzerine nasıl konulacağını tarif eder.
``fake`` dışındaki tüm kipler yalnızca soket seçenekleriyle, ham soket
gerektirmeden çalışır.

Kullanılan teknikler
--------------------
``tlsrec``   ClientHello birden çok TLS kaydına bölünür. TLS açısından
             tamamen geçerlidir; kayıt katmanını birleştirmeyen DPI'lar
             SNI'yi bulamaz.
``split``    İlk veri ayrı TCP segmentlerine bölünür (TCP_NODELAY ile).
``disorder`` Baştaki parça düşük TTL ile gönderilir: DPI görür, sunucuya
             ulaşmaz. Ardından ikinci parça normal TTL ile gider; çekirdek
             kayıp ilk parçayı normal TTL ile yeniden gönderir. Böylece DPI
             akışı sırasız/eksik görür, sunucu ise eksiksiz alır.
``oob``      Parçaların arasına MSG_OOB ile "acil" bayt konur. Akışı satır
             içi birleştiren DPI bu baytı veriye katıp SNI'yi bozar; hedef
             sunucunun TCP yığını ise acil baytı akıştan düşürür.
``disoob``   disorder + oob birlikte.
``fake``     Gerçek veriden önce, zararsız bir SNI taşıyan sahte bir
             ClientHello ham soketle ve gerçek verinin sıra numarasıyla
             düşük TTL kullanılarak gönderilir. Sunucuya ulaşmaz, DPI
             görür. Çekirdek gönderim kuyruğuna hiç girmediği için gerçek
             veri bozulmaz. (CAP_NET_RAW gerekir.)
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Strategy:
    name: str
    label: str
    mode: str = "split"                     # none|split|disorder|oob|disoob|fake
    split: tuple[str, ...] = ()             # TCP segment kesme noktaları
    tlsrec: tuple[str, ...] = ()            # TLS kayıt kesme noktaları
    ttl: int = 4                            # sahte/sırasız parçalar için TTL
    fake_sni: str = "www.google.com"
    delay: float = 0.0                      # parçalar arası gecikme (saniye)
    http_mangle: bool = True                # HTTP'de Host başlığını kurcala
    requires: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "label": self.label,
            "mode": self.mode,
            "split": list(self.split),
            "tlsrec": list(self.tlsrec),
            "ttl": self.ttl,
            "delay": self.delay,
            "requires": list(self.requires),
        }


#: Katalog. Sıra, genel başarı olasılığına ve gecikme maliyetine göredir:
#: gecikmesiz olanlar (tlsrec / split) önce, yeniden iletim bekleten
#: (disorder / fake) olanlar sonra gelir.
CATALOG: tuple[Strategy, ...] = (
    Strategy(
        name="tlsrec-sni",
        label="TLS kayıt parçalama (SNI ortası)",
        mode="none",
        tlsrec=("rec:snimid",),
    ),
    Strategy(
        name="tlsrec-split-sni",
        label="TLS kayıt parçalama + TCP bölme",
        mode="split",
        tlsrec=("rec:snimid",),
        split=("3",),
    ),
    Strategy(
        name="split-snimid",
        label="TCP bölme (SNI ortası)",
        mode="split",
        split=("snimid",),
    ),
    Strategy(
        name="split-sni",
        label="TCP bölme (SNI başı)",
        mode="split",
        split=("sni",),
    ),
    Strategy(
        name="multisplit",
        label="Çoklu TCP bölme (1 + SNI + orta)",
        mode="split",
        split=("1", "sni", "snimid"),
    ),
    Strategy(
        name="split-2",
        label="TCP bölme (2. bayt)",
        mode="split",
        split=("2",),
    ),
    Strategy(
        name="split-delay",
        label="Gecikmeli TCP bölme (SNI ortası)",
        mode="split",
        split=("snimid",),
        delay=0.05,
    ),
    Strategy(
        name="oob-snimid",
        label="Bant dışı bayt (SNI ortası)",
        mode="oob",
        split=("snimid",),
    ),
    Strategy(
        name="disorder-snimid",
        label="Sırasız gönderim (SNI ortası)",
        mode="disorder",
        split=("snimid",),
        ttl=4,
    ),
    Strategy(
        name="disorder-sni",
        label="Sırasız gönderim (SNI başı)",
        mode="disorder",
        split=("sni",),
        ttl=3,
    ),
    Strategy(
        name="disorder-tlsrec",
        label="Sırasız gönderim + TLS kayıt parçalama",
        mode="disorder",
        tlsrec=("rec:snimid",),
        split=("3",),
        ttl=4,
    ),
    Strategy(
        name="disoob-snimid",
        label="Sırasız + bant dışı bayt",
        mode="disoob",
        split=("snimid",),
        ttl=4,
    ),
    Strategy(
        name="disorder-ttl6",
        label="Sırasız gönderim (TTL 6)",
        mode="disorder",
        split=("snimid",),
        ttl=6,
    ),
    Strategy(
        name="disorder-ttl2",
        label="Sırasız gönderim (TTL 2)",
        mode="disorder",
        split=("snimid",),
        ttl=2,
    ),
    Strategy(
        name="fake-snimid",
        label="Sahte ClientHello + bölme",
        mode="fake",
        split=("snimid",),
        ttl=4,
        requires=("rawfake",),
    ),
    Strategy(
        name="fake-ttl8",
        label="Sahte ClientHello (TTL 8)",
        mode="fake",
        split=("snimid",),
        ttl=8,
        requires=("rawfake",),
    ),
    Strategy(
        name="none",
        label="Atlatma yok (doğrudan bağlan)",
        mode="none",
        http_mangle=False,
    ),
)

BY_NAME: dict[str, Strategy] = {s.name: s for s in CATALOG}

#: Hiçbir profil eşleşmediğinde denenecek sıra.
DEFAULT_ORDER: tuple[str, ...] = tuple(s.name for s in CATALOG if s.name != "none")


def get(name: str) -> Strategy | None:
    return BY_NAME.get(name)


def order_for(preferred: list[str] | tuple[str, ...]) -> list[Strategy]:
    """Tercih listesini önce, kalan tüm stratejileri sonra sıralayan liste."""
    seen: set[str] = set()
    out: list[Strategy] = []
    for name in preferred:
        st = BY_NAME.get(name)
        if st and st.name not in seen:
            out.append(st)
            seen.add(st.name)
    for st in CATALOG:
        if st.name not in seen and st.name != "none":
            out.append(st)
            seen.add(st.name)
    return out
