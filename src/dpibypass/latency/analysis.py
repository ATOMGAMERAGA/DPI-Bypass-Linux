"""Zaman bakımından eşleştirilmiş A/B karşılaştırması ve blok bootstrap'ı.

Neden sabit eşik yetmiyor
-------------------------
Eski motor ``max(2 ms, %5)`` gibi sabit etki eşikleri kullanıyordu. Bunun iki
yönlü hatası var:

* **Yanlış negatif:** gerçekten tekrarlanan 10 → 9 ms kazanç, tek başına 2 ms
  duvarına takılıp "kazanç yok" sayılıyordu.
* **Yanlış pozitif:** ölçüm sırasında ağın kendiliğinden iyileşmesi (ya da
  hedeflerin yanıt ağırlığının kayması) eşiği geçip adaya mal edilebiliyordu.

Çözüm eşiği sıfırlamak değil; **ölçüm tasarımını** düzeltmek:

1. Aday, taban ölçümüyle *zaman içinde iç içe* karşılaştırılır (ABBA blokları).
   Her B ölçümünün hemen komşusundaki A ölçümleriyle eşleştirilmesi, yavaş ağ
   sürüklenmesini (drift) fark hesabından düşürür.
2. Aday sırası dengelenir (ABBA), böylece doğal iyileşme sıranın sonundaki
   ayara yazılamaz.
3. Karar, blok düzeyindeki farkların **blok bootstrap** güven aralığına
   dayanır. Ardışık ve birbiriyle korelasyonlu paketler binlerce bağımsız
   gözlem sayılmaz; bağımsız birim *blok çiftidir*.
4. Aynı prosedür kontrol-kontrol (A/A) verisine de uygulanır. A/A'da da
   "anlamlı fark" çıkıyorsa bu koşuda yöntem güvenilir değildir; sonuç
   ``inconclusive`` olur, kazanan seçilmez.

Bütün bunlar endpoint **bazında** yapılır: hiçbir aşamada farklı hedeflerin
örnekleri havuzlanmaz.
"""

from __future__ import annotations

import logging
import random
import statistics
from dataclasses import dataclass, field
from typing import Sequence

from .metrics import (LatencyMeasurement, ROLE_USER, EndpointStats)

log = logging.getLogger("dpibypass.latency.analysis")

#: Karara giren metrikler. Hepsi "küçük daha iyi" yönlüdür.
PRIMARY_METRICS = ("median_ms", "p95_ms", "jitter_ms")

#: Sonuç kodları — UI metni değil, kararlı sözleşme.
OUTCOME_GAIN = "gain"
OUTCOME_NO_GAIN = "no-gain"
OUTCOME_INCONCLUSIVE = "inconclusive"
OUTCOME_REGRESSION = "regression"
OUTCOME_INCOMPARABLE = "incomparable"

#: Pratik asgari etki. 2 ms duvarı değil; ölçüm çözünürlüğünün (ping çıktısı
#: 0.001 ms hassasiyetinde) üstünde kalan, ama küçük gerçek kazançları da
#: kabul edebilen bir alt sınır.
DEFAULT_MIN_EFFECT_MS = 0.2

#: Kötüleşme toleransları. Kazanç eşiğinden daha dar tutulur: şüphede
#: kalırsak değişikliği reddederiz.
DEFAULT_REGRESSION_TOLERANCE = {
    "median_ms": 0.5,
    "p95_ms": 1.0,
    "jitter_ms": 0.5,
}

#: Başarısızlık/kayıp oranındaki kabul edilebilir artış (yüzde puan).
DEFAULT_LOSS_TOLERANCE = 0.5


@dataclass
class MetricDelta:
    """Bir endpoint × metrik için eşleştirilmiş fark özeti.

    ``delta_ms`` = ortalama (B − A). **Negatif değer iyileşmedir.**
    """

    endpoint_key: str
    endpoint_label: str
    metric: str
    delta_ms: float
    ci_low: float
    ci_high: float
    pairs: int
    role: str = ""
    #: Güven aralığı tamamen sıfırın altında mı? (iyileşme)
    improved: bool = False
    #: Güven aralığı tamamen toleransın üstünde mi? (kötüleşme)
    regressed: bool = False

    def to_dict(self) -> dict:
        return {
            "endpoint": self.endpoint_key, "label": self.endpoint_label,
            "metric": self.metric, "delta_ms": round(self.delta_ms, 3),
            "ci_low": round(self.ci_low, 3), "ci_high": round(self.ci_high, 3),
            "pairs": self.pairs, "role": self.role,
            "improved": self.improved, "regressed": self.regressed,
        }


@dataclass
class ComparisonResult:
    outcome: str = OUTCOME_INCONCLUSIVE
    reason: str = ""
    deltas: list = field(default_factory=list)      # list[MetricDelta]
    pairs: int = 0
    #: A/A kontrolünde de "anlamlı" fark bulunduysa True: yöntem bu koşuda
    #: güvenilir değil.
    control_unstable: bool = False
    #: Sıralama için tek sayı; yalnız kazananlar arasında anlam taşır.
    score: float | None = None
    coverage_before: float = 0.0
    coverage_after: float = 0.0
    loss_delta: float = 0.0
    notes: list = field(default_factory=list)

    @property
    def verified(self) -> bool:
        return self.outcome == OUTCOME_GAIN

    def improvements(self) -> list:
        return [item for item in self.deltas if item.improved]

    def regressions(self) -> list:
        return [item for item in self.deltas if item.regressed]

    def to_dict(self) -> dict:
        return {
            "outcome": self.outcome, "reason": self.reason,
            "pairs": self.pairs, "control_unstable": self.control_unstable,
            "score": None if self.score is None else round(self.score, 3),
            "coverage_before": self.coverage_before,
            "coverage_after": self.coverage_after,
            "loss_delta": round(self.loss_delta, 3),
            "deltas": [item.to_dict() for item in self.deltas],
            "notes": list(self.notes),
        }


def _percentile(ordered: Sequence[float], fraction: float) -> float:
    if not ordered:
        return 0.0
    index = int(round(fraction * (len(ordered) - 1)))
    return ordered[max(0, min(len(ordered) - 1, index))]


def bootstrap_ci(deltas: Sequence[float], resamples: int = 2000,
                 confidence: float = 0.95,
                 rng: random.Random | None = None) -> tuple[float, float, float]:
    """Blok bootstrap: bağımsız birim *blok çiftidir*, tek paket değil.

    Döner: (ortalama, alt sınır, üst sınır).
    """
    values = [float(value) for value in deltas]
    if not values:
        return 0.0, 0.0, 0.0
    mean = float(statistics.mean(values))
    if len(values) == 1:
        # Tek çiftten güven aralığı çıkarılamaz: aralığı sonsuz genişlikte
        # kabul edip kararı "anlamlı değil" tarafına bırakıyoruz.
        return mean, float("-inf"), float("inf")
    generator = rng or random.Random(0)
    size = len(values)
    means = []
    for _index in range(max(200, int(resamples))):
        sample = [values[generator.randrange(size)] for _ in range(size)]
        means.append(sum(sample) / size)
    means.sort()
    tail = (1.0 - confidence) / 2.0
    return mean, _percentile(means, tail), _percentile(means, 1.0 - tail)


def _paired_series(control: Sequence[LatencyMeasurement],
                   treatment: Sequence[LatencyMeasurement],
                   endpoint_key: str, metric: str) -> list:
    """Eşleştirilmiş blok farkları (B − A); ikisi de ölçülemeyen blok atlanır."""
    series = []
    for before, after in zip(control, treatment):
        old = before.endpoint_map().get(endpoint_key)
        new = after.endpoint_map().get(endpoint_key)
        if old is None or new is None:
            continue
        old_value = old.metric(metric)
        new_value = new.metric(metric)
        if old_value is None or new_value is None:
            continue
        series.append(float(new_value) - float(old_value))
    return series


def _shared_endpoints(control: Sequence[LatencyMeasurement],
                      treatment: Sequence[LatencyMeasurement]) -> list:
    """İki koldaki bütün bloklarda ortak olan, kimliği değişmemiş hedefler."""
    maps = [item.endpoint_map() for item in list(control) + list(treatment)]
    if not maps:
        return []
    shared = set(maps[0])
    for item in maps[1:]:
        shared &= set(item)
    result = []
    for key in sorted(shared):
        specs = [item[key].spec for item in maps]
        if all(specs[0].comparable_with(spec) for spec in specs[1:]):
            result.append(key)
    return result


def _mean_coverage(measurements: Sequence[LatencyMeasurement]) -> float:
    values = [item.remote.coverage for item in measurements]
    return round(float(statistics.mean(values)), 3) if values else 0.0


def _mean_loss(measurements: Sequence[LatencyMeasurement]) -> float:
    values = [item.remote.packet_loss for item in measurements]
    return float(statistics.mean(values)) if values else 100.0


def control_noise(control: Sequence[LatencyMeasurement],
                  resamples: int = 2000, seed: int = 0) -> dict:
    """Kontrol kolunun kendi içindeki gürültü tabanını ölç (A/A).

    Kontrol blokları tek/çift diye ikiye bölünür ve **aynı ayarla** alınmış
    bu iki yarı, adaya uygulanan prosedürün aynısıyla karşılaştırılır. Çıkan
    fark, o koşuda hiçbir şey değiştirmeden bile görülebilen sürüklenme ve
    gürültüdür.

    Bu taban hem kazanç hem kötüleşme kararını kapılar: gürültü seviyesindeki
    bir fark ne "iyileşme" ne de "kötüleşme" sayılır. A/A verisinde
    sistematik bir kazanan seçilmesini engelleyen mekanizma budur.

    Döner: ``{metrik: gürültü_ms}``. Yeterli blok yoksa boş sözlük.
    """
    if len(control) < 4:
        return {}
    first = list(control[0::2])
    second = list(control[1::2])
    size = min(len(first), len(second))
    if size < 2:
        return {}
    first, second = first[:size], second[:size]
    rng = random.Random(seed ^ 0x5A5A)
    floors: dict = {}
    for key in _shared_endpoints(first, second):
        for metric in PRIMARY_METRICS:
            series = _paired_series(first, second, key, metric)
            if len(series) < 2:
                continue
            mean, low, high = bootstrap_ci(series, resamples, rng=rng)
            # Gürültü tabanı: gözlenen ortalama farkın ve güven aralığının
            # sıfırdan uzaklığının büyüğü.
            magnitude = max(abs(mean), abs(low) if low > 0 else 0.0,
                            abs(high) if high < 0 else 0.0)
            floors[metric] = max(floors.get(metric, 0.0), magnitude)
    return floors


def compare(control: Sequence[LatencyMeasurement],
            treatment: Sequence[LatencyMeasurement],
            min_effect_ms: float = DEFAULT_MIN_EFFECT_MS,
            regression_tolerance: dict | None = None,
            loss_tolerance: float = DEFAULT_LOSS_TOLERANCE,
            resamples: int = 2000, seed: int = 0,
            check_control: bool = True) -> ComparisonResult:
    """Eşleştirilmiş A/B bloklarını karşılaştır ve kararı gerekçesiyle döndür."""
    tolerance = dict(DEFAULT_REGRESSION_TOLERANCE)
    if regression_tolerance:
        tolerance.update(regression_tolerance)
    result = ComparisonResult()
    control = [item for item in control if item is not None]
    treatment = [item for item in treatment if item is not None]
    pairs = min(len(control), len(treatment))
    result.pairs = pairs
    if pairs < 1:
        result.outcome = OUTCOME_INCOMPARABLE
        result.reason = "eşleştirilmiş ölçüm bloğu yok"
        return result
    control, treatment = control[:pairs], treatment[:pairs]

    for before, after in zip(control, treatment):
        ok, why = before.comparable_with(after)
        if not ok:
            result.outcome = OUTCOME_INCOMPARABLE
            result.reason = why
            return result

    result.coverage_before = _mean_coverage(control)
    result.coverage_after = _mean_coverage(treatment)
    result.loss_delta = _mean_loss(treatment) - _mean_loss(control)

    endpoints = _shared_endpoints(control, treatment)
    if not endpoints:
        result.outcome = OUTCOME_INCOMPARABLE
        result.reason = "iki kolda ortak ve kimliği değişmemiş hedef yok"
        return result

    # Kapsam kaybı asla iyileşme sayılmaz: yavaş hedefin susması, kalan hızlı
    # hedefin özeti aşağı çekmesi demektir.
    if result.coverage_after < result.coverage_before - 1e-9:
        result.outcome = OUTCOME_REGRESSION
        result.reason = ("bir veya daha fazla hedef yanıt vermeyi bıraktı "
                         "(kapsam düştü)")
        return result

    # Gürültü tabanı iki yönü de kapılar: gürültü seviyesindeki bir fark
    # ne kazanç ne kötüleşmedir. A/A verisinde kazanan seçilmesini de,
    # gürültünün "kötüleşme" diye raporlanmasını da bu engeller.
    noise = control_noise(control, resamples, seed) if check_control else {}
    result.notes.extend(
        f"{metric} gürültü tabanı {value:.2f} ms"
        for metric, value in sorted(noise.items()) if value > 0.0)

    rng = random.Random(seed)
    labels = {item.spec.key: (item.spec.display, item.spec.role)
              for item in treatment[0].endpoints}
    for key in endpoints:
        label, role = labels.get(key, (key, ""))
        for metric in PRIMARY_METRICS:
            series = _paired_series(control, treatment, key, metric)
            if not series:
                continue
            mean, low, high = bootstrap_ci(series, resamples, rng=rng)
            floor = noise.get(metric, 0.0)
            gain_floor = max(min_effect_ms, floor)
            regress_floor = max(tolerance.get(metric, 0.5), floor)
            delta = MetricDelta(
                endpoint_key=key, endpoint_label=label, metric=metric,
                delta_ms=mean, ci_low=low, ci_high=high, pairs=len(series),
                role=role,
                improved=(high < 0.0 and abs(mean) >= gain_floor),
                regressed=(low > regress_floor),
            )
            result.deltas.append(delta)

    # --- veto sırası: kötüleşme her zaman kazançtan önce gelir ------------
    if result.loss_delta > loss_tolerance:
        result.outcome = OUTCOME_REGRESSION
        result.reason = (f"kayıp/başarısızlık oranı arttı "
                         f"(+{result.loss_delta:.2f} puan)")
        return result
    regressions = result.regressions()
    if regressions:
        worst = max(regressions, key=lambda item: item.delta_ms)
        result.outcome = OUTCOME_REGRESSION
        result.reason = (f"{worst.endpoint_label} hedefinde {worst.metric} "
                         f"kötüleşti ({worst.delta_ms:+.2f} ms)")
        return result

    # Kazanç kullanıcının hedefinde aranır; kullanıcı hedefi yoksa genel
    # gösterge hedefleri kullanılır ama sonuç öyle etiketlenir.
    primary_keys = {item.spec.key for item in treatment[0].endpoints
                    if item.spec.role == ROLE_USER}
    if not primary_keys:
        primary_keys = set(endpoints)
    gains = [item for item in result.improvements()
             if item.endpoint_key in primary_keys]
    if not gains:
        if pairs < 2:
            result.outcome = OUTCOME_INCONCLUSIVE
            result.reason = ("tek blok çiftinden güven aralığı çıkarılamaz; "
                             "daha çok tekrar gerekiyor")
            return result
        # Gürültü tabanı pratik etkinin belirgin üstündeyse "kazanç yok"
        # demek dürüst değil: bu koşuda o büyüklükte bir kazanç ölçülemezdi.
        worst_noise = max(noise.values()) if noise else 0.0
        if worst_noise > 2.0 * min_effect_ms:
            result.control_unstable = True
            result.outcome = OUTCOME_INCONCLUSIVE
            result.reason = (f"ağ bu koşuda kararsız; kontrol-kontrol gürültüsü "
                             f"{worst_noise:.2f} ms, bu büyüklükte bir fark "
                             f"gürültüden ayrılamaz")
            return result
        result.outcome = OUTCOME_NO_GAIN
        result.reason = "ölçülen fark gürültüden ayrılamadı"
        result.score = _score(result)
        return result

    result.outcome = OUTCOME_GAIN
    best = min(gains, key=lambda item: item.delta_ms)
    result.reason = (f"{best.endpoint_label}: {best.metric} "
                     f"{best.delta_ms:+.2f} ms "
                     f"(%95 GA {best.ci_low:+.2f}…{best.ci_high:+.2f}, "
                     f"{best.pairs} blok çifti)")
    result.score = _score(result)
    return result


def _score(result: ComparisonResult) -> float:
    """Adayları sıralamak için tek sayı; yalnız aynı koşuda anlamlıdır.

    Ağırlıklar gerçek zamanlı trafiğe göre: p95 ve jitter en az median kadar
    önemlidir. Yalnız **istatistiksel olarak ayırt edilebilen** farklar puana
    girer; gürültü puanı şişiremez.
    """
    weights = {"median_ms": 0.4, "p95_ms": 0.4, "jitter_ms": 0.2}
    total = 0.0
    for delta in result.deltas:
        if not (delta.improved or delta.regressed):
            continue
        # role ağırlığı: kullanıcının hedefi referans hedeften ağır basar
        role_weight = 1.0 if delta.role == ROLE_USER else 0.5
        total += weights.get(delta.metric, 0.0) * role_weight * (-delta.delta_ms)
    total -= 5.0 * max(0.0, result.loss_delta)
    return round(total, 3)


def summarize_endpoints(before: LatencyMeasurement,
                        after: LatencyMeasurement) -> list:
    """Ekran için endpoint bazında önce/sonra tablosu (karar vermez)."""
    rows = []
    old_map = before.endpoint_map()
    for item in after.endpoints:
        old = old_map.get(item.spec.key)
        rows.append({
            "endpoint": item.spec.display,
            "role": item.spec.role,
            "method": item.spec.method,
            "before": old.to_dict() if old else None,
            "after": item.to_dict(),
        })
    return rows


def gain_dict(before: LatencyMeasurement,
              after: LatencyMeasurement | None) -> dict:
    """Geriye dönük uyumlu kazanç özeti (sabit ağırlıklı toplu metrikler)."""
    if after is None:
        return {}
    old, new = before.remote, after.remote

    def delta(first, second):
        if first is None or second is None:
            return None
        return round(second - first, 2)

    return {
        "median_ms": delta(old.median_ms, new.median_ms),
        "p95_ms": delta(old.p95_ms, new.p95_ms),
        "jitter_ms": delta(old.jitter_ms, new.jitter_ms),
        "packet_loss": delta(old.packet_loss, new.packet_loss),
        "coverage": delta(old.coverage, new.coverage),
    }
