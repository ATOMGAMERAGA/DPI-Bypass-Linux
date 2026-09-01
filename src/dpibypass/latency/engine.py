"""Ölçüm → eşleştirilmiş aday karşılaştırması → bağımsız doğrulama → uygulama.

Akış
----
::

    hedefleri çöz ve yolu doğrula
      → ortamı keşfet (Wi-Fi / qdisc yuvaları / NIC / SQM yeteneği)
      → her aday için ABBA blokları: A ölç · B uygula-ölç-geri al · …
      → blok bootstrap ile karar (kazanç / kazanç yok / kararsız / kötüleşme)
      → kazananı BAĞIMSIZ holdout bloklarıyla yeniden doğrula
      → doğrulandıysa uygula, doğrulanmadıysa geri al

Tek bir eski baseline'a karşı ölçüm yapılmaz: kontrol kolu adayla iç içe ve
dengeli sırayla tekrar tekrar ölçülür. Ağın kendiliğinden iyileşmesi böylece
adaya yazılamaz.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import json
import logging
import os
import platform
import re
import time
from dataclasses import dataclass, field
from typing import Callable, Sequence

from ..constants import LATENCY_PROFILE_FILE, LATENCY_STATE_FILE
from ..netmon import NetworkFingerprint
from ..util import run, which
from . import analysis, load as loadmod, probe as probemod, qdisc as qdiscmod
from .actions import (ActionError, ActionExecutor, ActionSnapshot,
                      LatencySnapshot, SnapshotCorrupt, coalesce_candidates,
                      ifindex_of)
from .analysis import (OUTCOME_GAIN, OUTCOME_INCOMPARABLE, OUTCOME_INCONCLUSIVE,
                       OUTCOME_NO_GAIN, OUTCOME_REGRESSION)
from .metrics import (CONDITION_IDLE, CONDITION_LOAD_BOTH, LatencyMeasurement,
                      LatencyStats, ROLE_USER)
from .profiles import LatencyProfiles, ProfileContext
from .sqm import SqmCapacity, SqmError, SqmManager, SqmState, DEFAULT_RATIOS

log = logging.getLogger("dpibypass.latency")

_IFACE_RE = re.compile(r"^[A-Za-z0-9_.@-]{1,15}\Z")

_VIRTUAL_PREFIXES = (
    "lo", "docker", "veth", "virbr", "br-", "cni", "flannel", "podman",
    "tun", "tap", "wg", "tailscale", "zt", "dummy", "ifb", "bond",
)

#: Kararlı durum kodları. UI metni üzerinden iş mantığı kurulmaz.
STATE_DISABLED = "disabled"
STATE_MEASURING = "measuring"
STATE_APPLYING = "applying"
STATE_BENCHMARKING = "benchmarking"
STATE_VERIFYING = "verifying"
STATE_ACTIVE = "active"
STATE_NO_GAIN = "no-gain"
STATE_INCONCLUSIVE = "inconclusive"
STATE_UNSUPPORTED = "unsupported"
STATE_ALREADY = "already-configured"
STATE_PERMISSION = "permission-denied"
STATE_EXTERNAL = "external-change"
STATE_ROLLED_BACK = "rolled-back"
STATE_ROLLBACK_FAILED = "rollback-failed"
STATE_SNAPSHOT_CORRUPT = "snapshot-corrupt"
STATE_FAILED = "failed"
STATE_CANCELLED = "cancelled"
STATE_MEASURED = "measured"

BUSY_STATES = (STATE_MEASURING, STATE_APPLYING, STATE_BENCHMARKING,
               STATE_VERIFYING)

#: Aday sonuç kodları.
CANDIDATE_TRIED = "tried"
CANDIDATE_NOT_NEEDED = "not-needed"
CANDIDATE_UNSUPPORTED = "unsupported"
CANDIDATE_BUDGET = "budget-exhausted"
CANDIDATE_REJECTED = "rejected"
CANDIDATE_FAILED = "failed"
CANDIDATE_CANCELLED = "cancelled"


class LatencyError(RuntimeError):
    pass


# --------------------------------------------------------------------------- #
# ayarlar
# --------------------------------------------------------------------------- #
@dataclass
class LatencySettings:
    """Kullanıcının kalıcı tercihleri; motor bunları kendiliğinden değiştirmez."""

    targets: list = field(default_factory=list)        # list[TargetSpec]
    #: Yük altı ölçüm ve SQM ayrı ayrı opt-in'dir.
    load_test: bool = False
    load_target: "loadmod.LoadTarget | None" = None
    load_budget: "loadmod.LoadBudget" = field(default_factory=loadmod.LoadBudget)
    metered: bool = False
    sqm: bool = False
    uplink_kbit: int = 0
    downlink_kbit: int = 0
    max_throughput_loss: float = 15.0
    #: Tarama ve holdout blok sayıları.
    scan_blocks: int = 3
    holdout_blocks: int = 4
    #: Blok başına, hedef başına örnek sayısı. 20, ``EndpointStats``'in
    #: güvenilir p95 alt sınırıdır: daha azında p95 pratikte örneklerin
    #: maksimumuna eşit olur ve motor bunu ``p95_reliable = false`` diye
    #: işaretlemek zorunda kalır.
    samples: int = 20
    seed: int = 0
    min_effect_ms: float = analysis.DEFAULT_MIN_EFFECT_MS

    def capacity(self) -> SqmCapacity:
        if self.uplink_kbit > 0:
            return SqmCapacity(egress_kbit=int(self.uplink_kbit),
                               ingress_kbit=int(self.downlink_kbit or 0),
                               source="user",
                               note="kullanıcının girdiği hat kapasitesi")
        return SqmCapacity(source="unknown",
                           note="hat kapasitesi bilinmiyor; shaping yapılmaz")


# --------------------------------------------------------------------------- #
# adaylar ve ortam
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class Step:
    kind: str
    target: str = ""
    label: str = ""

    def to_dict(self) -> dict:
        return {"kind": self.kind, "target": self.target, "label": self.label}


@dataclass(frozen=True)
class Candidate:
    key: str
    label: str
    steps: tuple = ()

    def to_dict(self) -> dict:
        return {"key": self.key, "label": self.label,
                "steps": [step.to_dict() for step in self.steps]}


@dataclass
class CandidateResult:
    key: str
    label: str
    applied: list = field(default_factory=list)
    measurement: "LatencyMeasurement | None" = None
    score: "float | None" = None
    verified: bool = False
    verdict: str = ""
    status: str = CANDIDATE_TRIED
    comparison: "analysis.ComparisonResult | None" = None

    def to_dict(self) -> dict:
        return {
            "key": self.key, "label": self.label, "applied": list(self.applied),
            "measurement": self.measurement.to_dict() if self.measurement else None,
            "score": None if self.score is None else round(self.score, 2),
            "verified": self.verified, "verdict": self.verdict,
            "status": self.status,
            "comparison": self.comparison.to_dict() if self.comparison else None,
        }


@dataclass
class Environment:
    interface: str
    link_type: str
    ifindex: int = 0
    wifi_power_save: "str | None" = None
    qdisc_slots: list = field(default_factory=list)
    qdisc_targets: tuple = ()
    eee: "str | None" = None
    coalesce: dict = field(default_factory=dict)
    coalesce_options: list = field(default_factory=list)
    cake_available: bool = False
    sqm_capacity: SqmCapacity = field(default_factory=SqmCapacity)
    sqm_possible: bool = False
    notes: list = field(default_factory=list)


@dataclass
class LatencyStatus:
    enabled: bool = False
    active: bool = False
    interface: str = ""
    state: str = STATE_DISABLED
    message: str = "Kapalı"
    before: "LatencyMeasurement | None" = None
    after: "LatencyMeasurement | None" = None
    applied: list = field(default_factory=list)
    skipped: list = field(default_factory=list)
    candidates: list = field(default_factory=list)
    best: str = ""
    cached: bool = False
    gain: dict = field(default_factory=dict)
    #: Ekranda gösterilecek bağlam.
    condition: str = CONDITION_IDLE
    targets: list = field(default_factory=list)
    verification: dict = field(default_factory=dict)
    endpoints: list = field(default_factory=list)
    load: dict = field(default_factory=dict)
    sqm: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "enabled": self.enabled, "active": self.active,
            "interface": self.interface, "state": self.state,
            "message": self.message,
            "before": self.before.to_dict() if self.before else None,
            "after": self.after.to_dict() if self.after else None,
            "applied": list(self.applied), "skipped": list(self.skipped),
            "candidates": [item.to_dict() for item in self.candidates],
            "best": self.best, "cached": self.cached, "gain": dict(self.gain),
            "condition": self.condition, "targets": list(self.targets),
            "verification": dict(self.verification),
            "endpoints": list(self.endpoints),
            "load": dict(self.load), "sqm": dict(self.sqm),
        }


# --------------------------------------------------------------------------- #
# düzenleyici
# --------------------------------------------------------------------------- #
class LatencyOptimizer:
    """Taban ölçüm → eşleştirilmiş aday karşılaştırması → holdout doğrulama."""

    BUDGET_SECONDS = 240.0
    #: Aktif profil denetiminin en sık yapılabileceği aralık (saniye).
    REVALIDATE_COOLDOWN = 900.0
    #: Kaç ardışık başarısız denetimden sonra geri alınır (histerezis).
    REVALIDATE_STRIKES = 2

    def __init__(self, runner: Callable = run,
                 which_fn: Callable = which,
                 probe=None,
                 state_path: str = LATENCY_STATE_FILE,
                 profiles: "LatencyProfiles | None" = None,
                 profile_path: str = LATENCY_PROFILE_FILE,
                 budget_seconds: "float | None" = None,
                 settings: "LatencySettings | None" = None) -> None:
        self.runner = runner
        self.which = which_fn
        self.settings = settings or LatencySettings()
        self.probe = probe or probemod.LatencyProbe(
            runner, which_fn, samples=self.settings.samples, rounds=1,
            warmup=True)
        self.state_path = state_path
        self.profiles = profiles if profiles is not None else \
            LatencyProfiles(profile_path)
        self.budget_seconds = float(
            self.BUDGET_SECONDS if budget_seconds is None else budget_seconds)
        self.status = LatencyStatus()
        self.snapshot: "LatencySnapshot | None" = None
        self.executor = ActionExecutor(runner, which_fn)
        self.sqm = SqmManager(runner, which_fn)
        self.resolver = probemod.TargetResolver(
            path_resolver=probemod.PathResolver(runner, which_fn))
        self._lock: "asyncio.Lock | None" = None
        self._generation = 0
        #: Snapshot bozuksa yeni mutasyon yapılmaz.
        self._blocked = ""
        self._last_revalidate = 0.0
        self._strikes = 0
        self._plan: "probemod.ProbePlan | None" = None
        self._active_context: "ProfileContext | None" = None

    # ------------------------------------------------------------------ #
    # yardımcılar
    # ------------------------------------------------------------------ #
    def _get_lock(self) -> asyncio.Lock:
        if self._lock is None:
            self._lock = asyncio.Lock()
        return self._lock

    def request_cancel(self) -> None:
        self._generation += 1

    def status_dict(self) -> dict:
        return self.status.to_dict()

    def _cancelled(self, generation: int) -> bool:
        return generation != self._generation

    async def _blocking(self, func: Callable, *args, **kwargs):
        """Engelleyici işi ayrı bir iş parçacığında çalıştır.

        Mutasyonlar **iptal edilmez**: yarıda kesilmiş bir komutun gerçek
        sonucu bilinemez ve o durumda geri alma başlatmak sistemi tanımsız
        bırakır. Bu yüzden çağrı ``shield`` ile korunur; iptal isteği ancak
        mutasyon bittikten sonra işlenir.
        """
        loop = asyncio.get_running_loop()
        executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
        try:
            return await asyncio.shield(
                loop.run_in_executor(executor, lambda: func(*args, **kwargs)))
        finally:
            executor.shutdown(wait=False)

    @staticmethod
    def _safe_network(network: NetworkFingerprint) -> tuple:
        iface = network.interface
        if not iface or not _IFACE_RE.match(iface):
            return False, "Geçerli bir aktif ağ arayüzü bulunamadı"
        lowered = iface.lower()
        if network.link_type == "vpn" or lowered.startswith(_VIRTUAL_PREFIXES):
            return False, "VPN veya sanal ağ arayüzlerine dokunulmaz"
        if network.link_type not in ("wifi", "ethernet", "mobile"):
            return False, "Bu arayüz türü güvenli optimizasyon için desteklenmiyor"
        if not network.is_online():
            return False, "Ağ bağlantısı yok"
        return True, ""

    # ------------------------------------------------------------------ #
    # ölçüm planı
    # ------------------------------------------------------------------ #
    def _build_plan(self, network: NetworkFingerprint,
                    condition: str = CONDITION_IDLE) -> probemod.ProbePlan:
        targets = list(self.settings.targets)
        using_reference = not targets
        if using_reference:
            targets = probemod.reference_targets()
        plan = probemod.build_plan(
            targets, network.interface, network.gateway,
            resolver=self.resolver, condition=condition,
            samples=self.settings.samples, rounds=1, warmup=True)
        if using_reference:
            plan.notes.insert(0, (
                "Kullanıcı hedefi tanımlı değil; genel ağ göstergesi hedefleri "
                "kullanıldı. Bu bir oyun ping'i değildir — kendi sunucunuzu "
                "'dpi-bypass latency target add' ile ekleyin."))
        return plan

    async def _measure(self, plan: probemod.ProbePlan, block: int = 0,
                       arm: str = "") -> LatencyMeasurement:
        plan.block = block
        plan.arm = arm
        return await self._blocking(self.probe.measure, plan)

    # ------------------------------------------------------------------ #
    # yaşam döngüsü
    # ------------------------------------------------------------------ #
    async def recover(self) -> bool:
        """Önceki servis sürecinden kalan runtime ayarlarını geri al."""
        async with self._get_lock():
            try:
                stale = self._load_snapshot()
            except SnapshotCorrupt as exc:
                # Bozuk snapshot ile "snapshot yok" AYNI ŞEY DEĞİL: sistemde
                # geri alınmamış bir değişiklik olabilir. Dosya silinmez,
                # yeni mutasyon yapılmaz, durum açıkça bildirilir.
                self._blocked = str(exc)
                self.status = LatencyStatus(
                    enabled=False, active=True, state=STATE_SNAPSHOT_CORRUPT,
                    message=(f"Geri alma kaydı okunamadı ({exc}). Sistemde geri "
                             f"alınmamış bir ayar olabilir; güvenlik için yeni "
                             f"değişiklik yapılmayacak. Kayıt: "
                             f"{self.state_path}"))
                log.error("Gecikme geri alma kaydı bozuk: %s", exc)
                return False
            if stale is None:
                return True
            log.warning("Önceki gecikme ayarları bulundu; geri alınıyor (%s)",
                        stale.interface)
            ok = await self._restore(stale)
            if ok:
                self._drop_snapshot()
                self.snapshot = None
            else:
                self.snapshot = stale
                self.status = LatencyStatus(
                    enabled=False, active=True, interface=stale.interface,
                    state=STATE_ROLLBACK_FAILED,
                    message="Önceki gecikme ayarları geri alınamadı")
            return ok

    async def disable(self) -> bool:
        self.request_cancel()
        async with self._get_lock():
            snapshot = self.snapshot
            if snapshot is None:
                try:
                    snapshot = self._load_snapshot()
                except SnapshotCorrupt as exc:
                    self._blocked = str(exc)
                    self.status = LatencyStatus(
                        enabled=False, active=True,
                        state=STATE_SNAPSHOT_CORRUPT,
                        message=f"Geri alma kaydı okunamadı ({exc})")
                    return False
            ok = True
            if snapshot is not None:
                ok = await self._restore(snapshot)
                if ok:
                    self._drop_snapshot()
                    self.snapshot = None
            self.status = LatencyStatus(
                enabled=False, active=not ok,
                interface=snapshot.interface if snapshot else self.status.interface,
                state=STATE_DISABLED if ok else STATE_ROLLBACK_FAILED,
                message="Kapalı; tüm değişiklikler geri alındı" if ok else
                        "Bazı ayarlar geri alınamadı; servis günlüğünü kontrol edin")
            return ok

    async def cancel(self) -> dict:
        """Kullanıcı isteğiyle devam eden ölçümü güvenli sınırda durdur.

        Mutasyonlar yarıda kesilmez; iptal ancak uygulanmakta olan adım
        bittikten sonra işlenir ve uygulanmış her şey geri alınır.
        """
        self.request_cancel()
        async with self._get_lock():
            ok = await self._restore_current()
            self.status.active = not ok
            self.status.applied = [] if ok else self.status.applied
            self.status.state = STATE_CANCELLED if ok else STATE_ROLLBACK_FAILED
            self.status.message = (
                "Ölçüm kullanıcı isteğiyle durduruldu; ayarlar geri alındı"
                if ok else
                "Ölçüm durduruldu ama bazı ayarlar geri alınamadı; servis "
                "günlüğünü kontrol edin")
            return self.status_dict()

    async def measure_only(self, network: NetworkFingerprint,
                           condition: str = CONDITION_IDLE) -> LatencyMeasurement:
        async with self._get_lock():
            safe, reason = self._safe_network(network)
            if not safe:
                raise LatencyError(reason)
            plan = self._build_plan(network, condition)
            if not plan.endpoints:
                raise LatencyError("; ".join(plan.notes[:3])
                                   or "Ölçülebilir hedef bulunamadı")
            measurement = await self._measure(plan)
            if not measurement.connected:
                raise LatencyError("Hedeflere bağlantı ölçülemedi")
            if not self.status.enabled:
                self.status.interface = network.interface
                self.status.state = STATE_MEASURED
                self.status.condition = condition
                self.status.targets = list(measurement.targets)
                self.status.message = _measurement_message(measurement)
                self.status.endpoints = [item.to_dict()
                                         for item in measurement.endpoints]
            return measurement

    # ------------------------------------------------------------------ #
    # ana akış
    # ------------------------------------------------------------------ #
    async def optimize(self, network: NetworkFingerprint) -> dict:
        async with self._get_lock():
            generation = self._generation
            started = time.monotonic()
            self.executor.external_change = ""
            if self._blocked:
                self.status = LatencyStatus(
                    enabled=True, interface=network.interface,
                    state=STATE_SNAPSHOT_CORRUPT,
                    message=(f"Geri alma kaydı belirsiz ({self._blocked}); yeni "
                             f"ayar denenmiyor"))
                return self.status_dict()
            safe, reason = self._safe_network(network)
            self.status = LatencyStatus(
                enabled=True, interface=network.interface,
                state=STATE_MEASURING if safe else STATE_UNSUPPORTED,
                message="Ölçüm hedefleri hazırlanıyor…" if safe else reason)
            if not safe:
                return self.status_dict()
            try:
                return await self._optimize_inner(network, generation, started)
            except LatencyError as exc:
                log.warning("Ping düşürme uygulanamadı: %s", exc)
                return await self._failure(f"Optimizasyon uygulanamadı: {exc}")
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                log.exception("Ping düşürme akışı hata verdi")
                return await self._failure(f"Optimizasyon uygulanamadı: {exc}")

    async def _optimize_inner(self, network: NetworkFingerprint,
                              generation: int, started: float) -> dict:
        plan = self._build_plan(network)
        self._plan = plan
        self.status.skipped = list(plan.notes)
        self.status.targets = [spec.display for spec in plan.endpoints]
        if not plan.endpoints:
            self.status.state = STATE_UNSUPPORTED
            self.status.message = (
                "Doğrulanmış bir ölçüm hedefi kurulamadı; hiçbir ayar "
                "değiştirilmedi")
            return self.status_dict()

        baseline = await self._measure(plan, 0, "A")
        self.status.before = baseline
        self.status.endpoints = [item.to_dict() for item in baseline.endpoints]
        if self._cancelled(generation):
            return self._cancel_status(network.interface, baseline)
        if not baseline.connected:
            self.status.state = STATE_FAILED
            self.status.message = \
                "Bağlantı testi başarısız; hiçbir ayar değiştirilmedi"
            return self.status_dict()

        self.status.state = STATE_APPLYING
        self.status.message = "Donanıma uygun adaylar hazırlanıyor…"
        environment = await self._blocking(self._discover, network)
        self.status.skipped = list(plan.notes) + list(environment.notes)
        candidates = self._candidates(environment)
        if self._cancelled(generation):
            return self._cancel_status(network.interface, baseline)
        if not candidates:
            already = any("zaten" in note for note in environment.notes)
            self.status.state = STATE_ALREADY if already else STATE_UNSUPPORTED
            self.status.message = (
                "Desteklenen düşük gecikme ayarları zaten etkin; başka aday "
                "denenemedi" if already else
                "Bu ağda denenebilecek güvenli bir aday bulunamadı")
            return self.status_dict()

        context = self._context(environment, plan)
        self._active_context = context
        results: list = []

        # 1) Bu ağda daha önce doğrulanmış bir aday varsa önce onu sına.
        cached, why = self.profiles.usable(network.key, context)
        if why:
            self.status.skipped.append(f"Kayıtlı profil kullanılmadı: {why}")
            self.profiles.forget(network.key)
        if cached:
            candidate = self._resolve_cached(
                str(cached.get("candidate") or ""), candidates)
            if candidate is None:
                self.profiles.forget(network.key)
            else:
                result = await self._compare_candidate(
                    network, environment, candidate, plan, generation,
                    blocks=self.settings.holdout_blocks)
                results.append(result)
                self.status.candidates = list(results)
                if self._cancelled(generation):
                    await self._rollback("Ağ değişti; eski ayarlar geri alındı")
                    return self.status_dict()
                if result.verified:
                    keep = await self._apply_final(environment, candidate,
                                                   network, plan, generation)
                    if keep is not None:
                        return self._activate(candidate, baseline, keep,
                                              result, cached=True)
                self.profiles.forget(network.key)
                if self.executor.external_change:
                    return self._abort_external()

        # 2) Tam tarama.
        for candidate in candidates:
            if any(item.key == candidate.key for item in results):
                continue
            if time.monotonic() - started > self.budget_seconds:
                results.append(CandidateResult(
                    key=candidate.key, label=candidate.label,
                    status=CANDIDATE_BUDGET,
                    verdict="süre bütçesi doldu; denenmedi"))
                self.status.candidates = list(results)
                self.status.skipped.append(
                    "Süre bütçesi doldu; kalan adaylar denenmedi")
                break
            result = await self._compare_candidate(
                network, environment, candidate, plan, generation,
                blocks=self.settings.scan_blocks)
            results.append(result)
            self.status.candidates = list(results)
            if self._cancelled(generation):
                await self._rollback("Ağ değişti; eski ayarlar geri alındı")
                return self.status_dict()
            if self.executor.external_change:
                return self._abort_external()

        # 3) Çakışmayan adayların birleşimi.
        combined = self._combine(results, candidates)
        if combined is not None and \
                time.monotonic() - started <= self.budget_seconds:
            result = await self._compare_candidate(
                network, environment, combined, plan, generation,
                blocks=self.settings.scan_blocks)
            results.append(result)
            self.status.candidates = list(results)
            candidates = list(candidates) + [combined]
            if self._cancelled(generation):
                await self._rollback("Ağ değişti; eski ayarlar geri alındı")
                return self.status_dict()
            if self.executor.external_change:
                return self._abort_external()

        winner = self._best(results)
        if winner is None:
            return self._no_winner(results)

        # 4) Bağımsız holdout doğrulaması. Çok adaylı taramanın tesadüfi
        #    kazanan üretmesini önleyen adım budur: kazanan, taramada
        #    kullanılmamış YENİ bloklarla yeniden sınanır.
        candidate = next(item for item in candidates if item.key == winner.key)
        self.status.state = STATE_VERIFYING
        self.status.message = (f"{candidate.label} bağımsız bloklarla "
                               f"doğrulanıyor…")
        holdout = await self._compare_candidate(
            network, environment, candidate, plan, generation,
            blocks=self.settings.holdout_blocks)
        self.status.verification = {
            "scan": winner.comparison.to_dict() if winner.comparison else {},
            "holdout": holdout.comparison.to_dict() if holdout.comparison else {},
            "blocks": self.settings.holdout_blocks,
            "independent": True,
        }
        if self._cancelled(generation):
            await self._rollback("Ağ değişti; eski ayarlar geri alındı")
            return self.status_dict()
        if not holdout.verified:
            self.profiles.forget(network.key)
            self.status.candidates = list(results) + [holdout]
            outcome = (holdout.comparison.outcome if holdout.comparison
                       else OUTCOME_NO_GAIN)
            self.status.state = (STATE_INCONCLUSIVE
                                 if outcome == OUTCOME_INCONCLUSIVE
                                 else STATE_NO_GAIN)
            self.status.active = False
            self.status.applied = []
            self.status.message = (
                f"Kazanç bağımsız doğrulamada tekrarlanmadı "
                f"({holdout.verdict}); hiçbir ayar değiştirilmedi")
            return self.status_dict()

        final = await self._apply_final(environment, candidate, network, plan,
                                        generation)
        if final is None:
            return self.status_dict()
        self.profiles.remember(network.key, candidate.key, candidate.label,
                               network.interface,
                               analysis.gain_dict(baseline, final), context)
        return self._activate(candidate, baseline, final, holdout)

    def _no_winner(self, results: Sequence[CandidateResult]) -> dict:
        outcomes = [item.comparison.outcome for item in results
                    if item.comparison is not None]
        if not outcomes:
            # Hiçbir aday gerçekten ölçülemedi (desteklenmiyor / bütçe doldu).
            # Bu "kazanç yok" DEĞİLDİR: denenmemiş bir şey için kazanç
            # olmadığı söylenemez.
            reasons = "; ".join(
                f"{item.label}: {item.verdict or item.status}"
                for item in results) or "aday üretilemedi"
            self.status.state = STATE_UNSUPPORTED
            self.status.message = (
                f"Hiçbir aday ölçülemedi, bu yüzden kazanç olup olmadığı "
                f"denenmedi. Nedenler — {reasons}")
            self.status.active = False
            self.status.applied = []
            log.info("Ping düşürme: %s", self.status.message)
            return self.status_dict()
        inconclusive = [item for item in outcomes
                        if item in (OUTCOME_INCONCLUSIVE, OUTCOME_INCOMPARABLE)]
        if inconclusive and len(inconclusive) >= max(1, len(outcomes) // 2):
            self.status.state = STATE_INCONCLUSIVE
            self.status.message = (
                "Ağ ölçüm boyunca kararsızdı; kazanç olup olmadığı "
                "belirlenemedi. Hiçbir ayar değiştirilmedi — daha sakin bir "
                "zamanda tekrar deneyin.")
        else:
            tried = [item.label for item in results
                     if item.comparison is not None]
            self.status.state = STATE_NO_GAIN
            self.status.message = (
                f"Denenen adaylar ({', '.join(tried)}) ölçülebilir bir gecikme "
                f"kazancı sağlamadı; hiçbir ayar değiştirilmedi. Bu, bu ağda "
                f"daha düşük gecikmenin mümkün olmadığı anlamına gelmez — "
                f"denenmeyenler için 'Atlanan' listesine bakın")
        self.status.active = False
        self.status.applied = []
        log.info("Ping düşürme: %s", self.status.message)
        return self.status_dict()

    async def _apply_final(self, env: Environment, candidate: Candidate,
                           network: NetworkFingerprint,
                           plan: probemod.ProbePlan,
                           generation: int) -> "LatencyMeasurement | None":
        """Kazananı kalıcı olarak uygula ve uygulanmış durumu ölç."""
        snapshot = LatencySnapshot(interface=env.interface,
                                   link_type=env.link_type,
                                   candidate=candidate.key,
                                   ifindex=env.ifindex)
        self.snapshot = snapshot
        try:
            applied = await self._blocking(self._apply_steps, snapshot,
                                           candidate, env)
        except (ActionError, LatencyError) as exc:
            await self._rollback(f"{candidate.label} uygulanamadı: {exc}")
            return None
        self.status.applied = applied
        return await self._measure(plan, 999, "final")

    def _activate(self, candidate: Candidate, baseline: LatencyMeasurement,
                  after: "LatencyMeasurement | None",
                  result: CandidateResult, cached: bool = False) -> dict:
        self.status.state = STATE_ACTIVE
        self.status.active = True
        self.status.after = after
        self.status.best = candidate.key
        self.status.cached = cached
        self.status.gain = analysis.gain_dict(baseline, after)
        if after is not None:
            self.status.endpoints = analysis.summarize_endpoints(baseline, after)
        self.status.message = _gain_message(result, cached)
        log.info("Ping düşürme doğrulandı (%s): %s", candidate.key,
                 self.status.message)
        return self.status_dict()

    def _abort_external(self) -> dict:
        change = self.executor.external_change
        log.warning("Aday taraması durduruldu: %s", change)
        self.status.state = STATE_EXTERNAL
        self.status.active = False
        self.status.applied = []
        self.status.message = (
            f"{change}. Ölçüm durduruldu; hiçbir ayar değiştirilmedi.")
        if change not in self.status.skipped:
            self.status.skipped.append(change)
        return self.status_dict()

    async def _failure(self, message: str) -> dict:
        if self.snapshot is not None:
            await self._rollback(f"Optimizasyon hatası; ayarlar geri alındı: "
                                 f"{message}")
        else:
            self.status.state = STATE_FAILED
            self.status.message = message
        return self.status_dict()

    def _cancel_status(self, interface: str,
                       before: LatencyMeasurement) -> dict:
        self.status = LatencyStatus(
            enabled=self.status.enabled, interface=interface,
            state=STATE_CANCELLED,
            message="Ölçüm ağ değişikliği nedeniyle iptal edildi",
            before=before)
        return self.status_dict()

    # ------------------------------------------------------------------ #
    # eşleştirilmiş aday karşılaştırması
    # ------------------------------------------------------------------ #
    async def _compare_candidate(self, network: NetworkFingerprint,
                                 env: Environment, candidate: Candidate,
                                 plan: probemod.ProbePlan, generation: int,
                                 blocks: int) -> CandidateResult:
        """ABBA blokları: A ölç · B uygula-ölç-geri al (sıra dengelenir)."""
        result = CandidateResult(key=candidate.key, label=candidate.label)
        self.status.state = STATE_BENCHMARKING
        self.status.message = f"{candidate.label} deneniyor…"
        control: list = []
        treatment: list = []

        for index in range(max(2, blocks)):
            if self._cancelled(generation):
                result.status = CANDIDATE_CANCELLED
                result.verdict = "iptal edildi"
                return result
            # Sıra dengelenir: doğal iyileşme her zaman aynı kola yazılamaz.
            order = ("A", "B") if index % 2 == 0 else ("B", "A")
            for arm in order:
                if arm == "A":
                    control.append(await self._measure(plan, index, "A"))
                    continue
                snapshot = LatencySnapshot(
                    interface=env.interface, link_type=env.link_type,
                    candidate=candidate.key, ifindex=env.ifindex)
                self.snapshot = snapshot
                try:
                    applied = await self._blocking(self._apply_steps, snapshot,
                                                   candidate, env)
                except (ActionError, LatencyError) as exc:
                    if not await self._restore_current():
                        raise LatencyError(
                            f"{candidate.label} yarım kaldı ve geri alınamadı: "
                            f"{exc}")
                    result.status = CANDIDATE_UNSUPPORTED
                    result.verdict = f"uygulanamadı: {exc}"
                    log.info("Aday atlandı (%s): %s", candidate.key, exc)
                    return result
                result.applied = applied
                measurement = await self._measure(plan, index, "B")
                treatment.append(measurement)
                result.measurement = measurement
                if not await self._restore_current():
                    raise LatencyError(
                        f"{candidate.label} sonrası eski ayarlar geri alınamadı")
                if self.executor.external_change:
                    result.status = CANDIDATE_REJECTED
                    result.verdict = self.executor.external_change
                    return result

        comparison = analysis.compare(
            control, treatment, min_effect_ms=self.settings.min_effect_ms,
            seed=self.settings.seed)
        result.comparison = comparison
        result.verified = comparison.verified
        result.score = comparison.score
        result.verdict = f"{comparison.outcome}: {comparison.reason}"
        result.status = (CANDIDATE_TRIED if comparison.outcome != OUTCOME_REGRESSION
                         else CANDIDATE_REJECTED)
        log.info("Aday %s → %s (%s)", candidate.key, comparison.outcome,
                 comparison.reason)
        return result

    # ------------------------------------------------------------------ #
    # ortam keşfi
    # ------------------------------------------------------------------ #
    def _discover(self, network: NetworkFingerprint) -> Environment:
        env = Environment(interface=network.interface,
                          link_type=network.link_type,
                          ifindex=ifindex_of(network.interface))
        iface = env.interface

        if network.link_type == "wifi":
            if self.which("iw") is None:
                env.notes.append("iw bulunamadı; Wi-Fi güç tasarrufu atlandı")
            else:
                value = self.executor.read_wifi_power_save(iface)
                if value is None:
                    env.notes.append(
                        "Sürücü Wi-Fi güç tasarrufu sorgusunu desteklemiyor")
                else:
                    env.wifi_power_save = value
                    if value == "off":
                        env.notes.append("Wi-Fi güç tasarrufu zaten kapalı")
        else:
            env.notes.append("Arayüz Wi-Fi değil; güç tasarrufu adayı yok")

        self._discover_qdisc(env)
        if network.link_type == "ethernet":
            self._discover_ethtool(env)
        else:
            env.notes.append("Arayüz Ethernet değil; ethtool adayları atlandı")
        self._discover_sqm(env)
        return env

    def _discover_qdisc(self, env: Environment) -> None:
        topology = qdiscmod.read_topology(self.runner, self.which, env.interface)
        slots, notes = qdiscmod.plan_slots(topology, env.interface,
                                           runner=self.runner)
        env.notes.extend(notes)
        env.qdisc_slots = slots
        if not slots:
            return
        targets = ["fq_codel", "fq"]
        env.cake_available = self._cake_available()
        if env.cake_available:
            targets.append("cake")
        else:
            env.notes.append("sch_cake çekirdek modülü yok; cake adayı atlandı")
        # Yapraklar türdeş olmak zorunda (plan_slots böyle olmayanı reddeder),
        # yani hâlihazırda kurulu tek bir tür vardır; onu yeniden denemenin
        # anlamı yok.
        current = {slot.kind for slot in slots}
        env.qdisc_targets = tuple(item for item in targets
                                  if item not in current)
        if not env.qdisc_targets:
            env.notes.append(
                f"Kuyruk disiplini zaten {'/'.join(sorted(current))}; "
                f"denenecek farklı bir hedef yok")

    def _cake_available(self) -> bool:
        try:
            if os.path.isdir("/sys/module/sch_cake"):
                return True
            with open("/proc/modules", "r", encoding="ascii",
                      errors="replace") as handle:
                if any(line.startswith("sch_cake ") for line in handle):
                    return True
        except OSError:
            pass
        if self.which("modinfo") is None:
            return False
        result = self.runner(["modinfo", "-F", "filename", "sch_cake"],
                             timeout=8)
        return (int(getattr(result, "returncode", 1) or 0) == 0
                and bool(str(getattr(result, "stdout", "") or "").strip()))

    def _discover_ethtool(self, env: Environment) -> None:
        if self.which("ethtool") is None:
            env.notes.append("ethtool bulunamadı; NIC adayları atlandı")
            return
        eee = self.executor.read_eee(env.interface)
        if eee is None:
            env.notes.append("Sürücü EEE sorgusunu desteklemiyor")
        else:
            env.eee = eee
            if eee == "disabled":
                env.notes.append("EEE zaten kapalı")

        current = self.executor.read_coalesce(env.interface)
        if not current:
            env.notes.append(
                "Coalescing değerleri okunamadı; NIC coalescing adayı atlandı")
            return
        env.coalesce = current
        # Yazılabilirlik, mevcut değerleri geri yazarak (no-op) kanıtlanır.
        # Desteklenmeyen tek bir adaptif alan yüzünden bütün özellik
        # reddedilmez; yalnız okunup geri yazılabilen alanlarla çalışılır.
        if not self.executor.coalesce_writable(env.interface, current):
            env.notes.append(
                "Sürücü coalescing değerlerini geri yazmayı desteklemiyor; "
                "aday atlandı")
            return
        env.coalesce_options = coalesce_candidates(current)
        if not env.coalesce_options:
            env.notes.append("RX coalescing zaten en düşük gecikmede")

    def _discover_sqm(self, env: Environment) -> None:
        if not self.settings.sqm:
            env.notes.append(
                "Yük altında düşük gecikme (SQM) kipi kapalı; bant genişliğine "
                "limit konmadı")
            return
        capacity = self.settings.capacity()
        env.sqm_capacity = capacity
        if not capacity.usable:
            env.notes.append(
                "SQM açık ama hat kapasitesi bilinmiyor; PHY link hızı internet "
                "kapasitesi sayılmaz. 'dpi-bypass latency calibrate' ile "
                "kapasiteyi girin")
            return
        if not env.qdisc_slots:
            env.notes.append(
                "SQM için egress kökü değiştirilebilir değil; mevcut yapı korundu")
            return
        if any(slot.parent != "root" for slot in env.qdisc_slots):
            env.notes.append(
                "SQM yalnız tek köklü yapılarda uygulanır; mq yaprak yapısı "
                "korundu")
            return
        env.sqm_possible = True
        if not self.settings.load_test:
            # Shaping'in asıl kazancı YÜK ALTINDA görünür ve bedeli
            # throughput'tur. Yük testi kapalıyken ikisini de ölçemeyiz;
            # bunu gizlemek yerine söylüyoruz.
            env.notes.append(
                "SQM adayları yalnız boşta ölçülüyor: yük testi kapalı "
                "olduğu için yük altındaki kazanç ve throughput bedeli "
                "ölçülemedi. Kendi sunucunuzu tanımlayıp yük testini "
                "açmadan SQM kazancı doğrulanmış sayılmaz")

    def _context(self, env: Environment,
                 plan: probemod.ProbePlan) -> ProfileContext:
        return ProfileContext(
            interface=env.interface,
            condition=plan.condition,
            targets="|".join(sorted(spec.key for spec in plan.endpoints)),
            kernel=platform.release(),
            driver=f"{env.link_type}:{env.ifindex}",
        )

    # ------------------------------------------------------------------ #
    # aday üretimi
    # ------------------------------------------------------------------ #
    def _candidates(self, env: Environment) -> list:
        candidates: list = []
        if env.wifi_power_save == "on":
            candidates.append(Candidate(
                key="wifi-power-save", label="Wi-Fi güç tasarrufu kapalı",
                steps=(Step("wifi-power-save", "off",
                            "Wi-Fi güç tasarrufu kapatıldı"),)))
        if env.eee == "enabled":
            candidates.append(Candidate(
                key="eee-off", label="Energy Efficient Ethernet kapalı",
                steps=(Step("eee", "off", "EEE kapatıldı"),)))
        for index, params in enumerate(env.coalesce_options):
            usecs = params.get("rx-usecs", "?")
            candidates.append(Candidate(
                key=f"rx-coalesce-{usecs}",
                label=f"RX coalescing rx-usecs={usecs}",
                steps=(Step("coalesce", str(index),
                            f"RX coalescing rx-usecs={usecs}"),)))
        for target in env.qdisc_targets:
            candidates.append(Candidate(
                key=f"qdisc-{target}", label=f"{target} kuyruk disiplini",
                steps=(Step("qdisc", target, f"{target} uygulandı"),)))
        if env.sqm_possible:
            for ratio in DEFAULT_RATIOS:
                percent = int(round(ratio * 100))
                candidates.append(Candidate(
                    key=f"sqm-{percent}",
                    label=(f"Yük altında düşük gecikme (SQM %{percent} "
                           f"kapasite)"),
                    steps=(Step("sqm", f"{ratio}",
                                f"SQM %{percent} kapasitede uygulandı"),)))
        return candidates

    @staticmethod
    def _resolve_cached(key: str, candidates: Sequence[Candidate]):
        if not key:
            return None
        by_key = {item.key: item for item in candidates}
        if key in by_key:
            return by_key[key]
        parts = key.split("+")
        if len(parts) < 2 or not all(part in by_key for part in parts):
            return None
        steps = tuple(step for part in parts for step in by_key[part].steps)
        return Candidate(key=key,
                         label=" + ".join(by_key[part].label for part in parts),
                         steps=steps)

    @staticmethod
    def _combine(results: Sequence[CandidateResult],
                 candidates: Sequence[Candidate]):
        """Çakışmayan adayları birleştir.

        Yalnız tek başına eşiği geçenlerle sınırlı değil: mekanizması farklı,
        aynı kaynağa dokunmayan ve kötüleşme göstermemiş **nötr** adaylar da
        sınırlı bütçeyle birleşime katılabilir. Aynı kaynağı değiştiren
        çelişkili adaylar (iki qdisc, iki coalescing) birleştirilmez.
        """
        by_key = {item.key: item for item in candidates}
        usable = [item for item in results
                  if item.key in by_key and item.comparison is not None
                  and item.comparison.outcome in (OUTCOME_GAIN, OUTCOME_NO_GAIN)]
        if len(usable) < 2:
            return None
        # Önce kazançlılar, sonra nötrler; ikisi de puanına göre.
        usable.sort(key=lambda item: (item.verified, item.score or 0.0),
                    reverse=True)
        if not any(item.verified for item in usable):
            return None      # hepsi nötrse birleşimden kazanç beklenmez
        steps: list = []
        used_kinds: set = set()
        keys: list = []
        for item in usable:
            candidate = by_key[item.key]
            kinds = {step.kind for step in candidate.steps}
            if kinds & used_kinds:
                continue
            if len(steps) + len(candidate.steps) > 3:
                continue
            used_kinds |= kinds
            steps.extend(candidate.steps)
            keys.append(item.key)
        if len(keys) < 2:
            return None
        return Candidate(key="+".join(keys),
                         label=" + ".join(by_key[key].label for key in keys),
                         steps=tuple(steps))

    @staticmethod
    def _best(results: Sequence[CandidateResult]):
        winners = [item for item in results
                   if item.verified and item.score is not None]
        if not winners:
            return None
        return max(winners, key=lambda item: item.score or 0.0)

    # ------------------------------------------------------------------ #
    # uygulama (senkron; iş parçacığında çalışır)
    # ------------------------------------------------------------------ #
    def _apply_steps(self, snapshot: LatencySnapshot, candidate: Candidate,
                     env: Environment) -> list:
        """Adımları sırayla uygula; her adımın tarifi **uygulamadan önce** yazılır."""
        applied: list = []
        for step in candidate.steps:
            for action in self._prepare(step, env):
                snapshot.actions.append(action)
                self._save_snapshot(snapshot)
                self._run_step(step, env, action)
                action.signature = self.executor.signature(action.kind,
                                                           env.interface)
                self._save_snapshot(snapshot)
                if action.label not in applied:
                    applied.append(action.label)
        return applied

    def _prepare(self, step: Step, env: Environment) -> list:
        iface = env.interface
        index = env.ifindex
        if step.kind == "wifi-power-save":
            return [ActionSnapshot(
                kind="wifi-power-save", interface=iface, ifindex=index,
                restore={"value": env.wifi_power_save or "on"},
                expected=step.target,
                label="Wi-Fi güç tasarrufu kapatıldı")]
        if step.kind == "eee":
            return [ActionSnapshot(
                kind="eee", interface=iface, ifindex=index,
                restore={"value": "on" if env.eee == "enabled" else "off"},
                expected="disabled", label="EEE kapatıldı")]
        if step.kind == "coalesce":
            params = {key: value for key, value in env.coalesce.items()
                      if key in ("adaptive-rx", "rx-usecs", "rx-frames")}
            if not params:
                raise LatencyError("coalescing tabanı okunamadı")
            return [ActionSnapshot(
                kind="coalesce", interface=iface, ifindex=index,
                restore={"params": params}, label=step.label)]
        if step.kind == "qdisc":
            if not env.qdisc_slots:
                raise LatencyError("qdisc tabanı kayboldu")
            return [ActionSnapshot(
                kind="qdisc", interface=iface, ifindex=index,
                restore={"args": list(slot.restore_args),
                         "parent": slot.parent},
                label=f"{step.target} uygulandı ({slot.label})")
                for slot in env.qdisc_slots]
        if step.kind == "sqm":
            if not env.sqm_possible or not env.qdisc_slots:
                raise LatencyError("SQM için uygun egress kökü yok")
            slot = env.qdisc_slots[0]
            # Uygulamadan ÖNCE yazılan tarif iyimserdir: henüz oluşturulmamış
            # kaynakları da oluşturulmuş gibi işaretler. Süreç uygulamanın
            # ortasında öldürülürse kurtarma yine de her kaynağı temizlemeye
            # çalışır; ``SqmManager.rollback`` var olmayan kaynağı hata
            # saymadığı için bu güvenlidir.
            state = SqmState(interface=iface,
                             egress_restore=list(slot.restore_args),
                             egress_applied=True, ifb_created=True,
                             ingress_qdisc_created=True, filter_added=True)
            return [ActionSnapshot(
                kind="sqm", interface=iface, ifindex=index,
                restore=state.to_dict(), label=step.label)]
        raise LatencyError(f"bilinmeyen aday adımı: {step.kind}")

    def _run_step(self, step: Step, env: Environment,
                  action: ActionSnapshot) -> None:
        iface = env.interface
        if step.kind == "wifi-power-save":
            self.executor.apply_wifi_power_save(iface, step.target)
        elif step.kind == "eee":
            self.executor.apply_eee(iface, step.target)
        elif step.kind == "coalesce":
            params = env.coalesce_options[int(step.target)]
            self.executor.apply_coalesce(iface, params)
        elif step.kind == "qdisc":
            parent = action.restore.get("parent", "root")
            slot = next(item for item in env.qdisc_slots
                        if item.parent == parent)
            self.executor.apply_qdisc(iface, slot, step.target)
        elif step.kind == "sqm":
            slot = env.qdisc_slots[0]
            try:
                state = self.sqm.apply(
                    iface, env.sqm_capacity, float(step.target),
                    list(slot.restore_args),
                    engine="cake" if env.cake_available else "htb+fq_codel")
            except SqmError as exc:
                raise ActionError(str(exc))
            # Gerçekte uygulanmış durum tarife yazılır: geri alma yalnız
            # gerçekten oluşturulmuş kaynakları hedefler.
            action.restore = state.to_dict()
        else:
            raise LatencyError(f"bilinmeyen aday adımı: {step.kind}")

    # ------------------------------------------------------------------ #
    # geri alma
    # ------------------------------------------------------------------ #
    async def _restore_current(self) -> bool:
        snapshot = self.snapshot
        if snapshot is None:
            try:
                snapshot = self._load_snapshot()
            except SnapshotCorrupt as exc:
                self._blocked = str(exc)
                return False
        ok = True if snapshot is None else await self._restore(snapshot)
        if ok:
            self._drop_snapshot()
            self.snapshot = None
        return ok

    async def _restore(self, snapshot: LatencySnapshot) -> bool:
        live = ifindex_of(snapshot.interface)
        if not snapshot.identity_matches(live):
            log.error("%s artık farklı bir aygıt (ifindex %s ≠ %s); eski kayıt "
                      "uygulanmadı", snapshot.interface, live, snapshot.ifindex)
            return False
        return await self._blocking(self._restore_sync, snapshot)

    def _restore_sync(self, snapshot: LatencySnapshot) -> bool:
        ok = True
        # Uygulama sırasının tersi; her adım idempotenttir.
        for action in reversed(snapshot.actions):
            if not self.executor.restore(action, sqm_manager=self.sqm):
                ok = False
        return ok

    async def _rollback(self, message: str) -> bool:
        ok = await self._restore_current()
        if not ok and message:
            log.error("%s — geri alma başarısız", message)
        self.status.active = not ok
        self.status.applied = [] if ok else self.status.applied
        self.status.state = STATE_ROLLED_BACK if ok else STATE_ROLLBACK_FAILED
        self.status.message = message if ok else (
            "Ayarların tamamı geri alınamadı; servis günlüğünü kontrol edin")
        log.info("Ping düşürme sonucu: %s", self.status.message)
        return ok

    def restore_persisted_sync(self) -> bool:
        """``dpi-bypassd --cleanup`` için olay döngüsüz geri alma yolu."""
        try:
            snapshot = self._load_snapshot()
        except SnapshotCorrupt as exc:
            log.error("Gecikme geri alma kaydı bozuk; dosya korunuyor: %s", exc)
            return False
        if snapshot is None:
            return True
        ok = self._restore_sync(snapshot)
        if ok:
            self._drop_snapshot()
        return ok

    # ------------------------------------------------------------------ #
    # hafif yeniden doğrulama
    # ------------------------------------------------------------------ #
    async def revalidate(self, network: NetworkFingerprint) -> "dict | None":
        """Aktif profili seyrek ve hafif biçimde denetle.

        Sürekli doygunluk testi yapmaz. Doğal internet dalgalanmasında her
        seferinde apply/rollback yapan bir salınım döngüsü kurulmaması için
        cooldown ve histerezis (arka arkaya birkaç başarısız denetim)
        kullanılır.
        """
        if not self.status.active or self.status.state != STATE_ACTIVE:
            return None
        now = time.monotonic()
        if now - self._last_revalidate < self.REVALIDATE_COOLDOWN:
            return None
        self._last_revalidate = now
        async with self._get_lock():
            snapshot = self.snapshot
            if snapshot is None:
                return None
            # Yalnız uygulanmış durumun HÂLÂ yürürlükte olduğunu doğrula:
            # yeni bir benchmark başlatılmaz.
            drifted = []
            for action in snapshot.actions:
                if not action.signature:
                    continue
                live = await self._blocking(self.executor.signature,
                                            action.kind, action.interface)
                if live and live != action.signature:
                    drifted.append(action.kind)
            if not drifted:
                self._strikes = 0
                return None
            self._strikes += 1
            if self._strikes < self.REVALIDATE_STRIKES:
                log.info("Gecikme profili denetimi: %s değişmiş görünüyor "
                         "(%d/%d)", ", ".join(drifted), self._strikes,
                         self.REVALIDATE_STRIKES)
                return None
            self._strikes = 0
            self.status.active = False
            self.status.state = STATE_EXTERNAL
            self.status.applied = []
            self.status.message = (
                f"Uygulanan ayar ({', '.join(drifted)}) dışarıdan değiştirildi; "
                f"doğrulanmış kazanç artık gösterilmiyor")
            self.snapshot = None
            self._drop_snapshot()
            return self.status_dict()

    # ------------------------------------------------------------------ #
    # snapshot dosyası
    # ------------------------------------------------------------------ #
    def _save_snapshot(self, snapshot: LatencySnapshot) -> None:
        directory = os.path.dirname(self.state_path)
        if directory:
            os.makedirs(directory, mode=0o755, exist_ok=True)
        tmp = self.state_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as handle:
            json.dump(snapshot.to_dict(), handle, ensure_ascii=False)
            handle.write("\n")
        os.replace(tmp, self.state_path)

    def _load_snapshot(self) -> "LatencySnapshot | None":
        """Döner: snapshot ya da None (dosya yok). Bozuksa ``SnapshotCorrupt``."""
        try:
            with open(self.state_path, "r", encoding="utf-8") as handle:
                raw = handle.read(1024 * 1024)
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise SnapshotCorrupt(f"dosya okunamadı: {exc}")
        try:
            data = json.loads(raw)
            if not isinstance(data, dict):
                raise ValueError("snapshot nesne değil")
            return LatencySnapshot.from_dict(data)
        except (ValueError, TypeError) as exc:
            raise SnapshotCorrupt(str(exc))

    def _drop_snapshot(self) -> None:
        try:
            os.unlink(self.state_path)
        except OSError:
            pass


# --------------------------------------------------------------------------- #
# metinler
# --------------------------------------------------------------------------- #
def _gain_message(result: CandidateResult, cached: bool = False) -> str:
    prefix = "Doğrulandı (bu ağda kayıtlı ayar)" if cached else "Doğrulandı"
    comparison = result.comparison
    if comparison is None:
        return prefix
    return f"{prefix}: {comparison.reason}"


def _measurement_message(measurement: LatencyMeasurement) -> str:
    remote = measurement.remote
    parts = []
    for label, value in (("median", remote.median_ms), ("p95", remote.p95_ms),
                         ("jitter", remote.jitter_ms)):
        parts.append(f"{value:g} ms {label}" if value is not None
                     else f"{label} ölçülemedi")
    parts.append(f"%{remote.packet_loss:g} yanıtsız")
    if not remote.p95_reliable:
        parts.append("p95 için örnek sayısı düşük")
    return " · ".join(parts)
