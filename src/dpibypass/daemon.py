"""Arka plan servisi: her şeyi bir araya getiren düzenleyici.

Akış
----
1. Yerel DNS köprüsü ve şeffaf vekil başlatılır, çekirdek kuralları kurulur.
2. Operatör saptanır (ASN + bağlantı türü + SSID).
3. O operatöre uygun strateji sırası, discord.com üzerinde *gerçekten*
   denenir; ilk çalışan seçilir ve ağ parmak izine kaydedilir.
4. Ağ değiştiğinde (SSID değişimi dahil) aynı arama arka planda, saniyeler
   içinde yeniden yapılır; daha önce o ağda çalışan yöntem ilk sırada
   denendiği için çoğunlukla tek denemede biter.
"""

from __future__ import annotations

import asyncio
import collections
import logging
import signal
import time
from typing import Optional

from . import isps, logging_setup, strategies
from .config import Config, State
from .connectivity import networkmanager_check_domains
from .constants import DNS_PORT, PROXY_PORT, VODAFONE_TTL_VALUE
from .desync import capabilities
from .dnsserver import DnsServer
from .firewall import Firewall, FirewallError
from .ipc import IpcServer
from .latency import (LatencyError, LatencyOptimizer, LatencySettings,
                      LoadBudget, LoadTarget, TargetSpec)
from .netmon import NetworkFingerprint, NetworkMonitor, fingerprint
from .proxy import TransparentProxy
from .resolver import shared as dns_resolver
from .strategies import Strategy
from .tester import Tester
from .util import domain_matches, is_root
from .version import APP_NAME, __version__
from .vodafone import VodafoneError, VodafoneMode

log = logging.getLogger("dpibypass.daemon")

STATE_STARTING = "starting"
STATE_SEARCHING = "searching"
STATE_ACTIVE = "active"
STATE_DNS_ONLY = "dns-only"
STATE_FAILED = "failed"
STATE_DISABLED = "disabled"


class Daemon:
    def __init__(self, verbose: bool = False) -> None:
        self.config = Config()
        self.state = State()
        self.direct_domains = networkmanager_check_domains()
        removed = self.state.forget_domains(self.direct_domains)
        if removed:
            log.info("Bağlantı denetimi yanlış engelli-site kaydından "
                     "temizlendi: %s", ", ".join(sorted(removed)))
        log.debug("Doğrudan bırakılan bağlantı denetimleri: %s",
                  ", ".join(sorted(self.direct_domains)))
        self.verbose = verbose or bool(self.config["verbose"])

        self.resolver = dns_resolver
        self.tester = Tester(self.resolver)
        self.firewall = Firewall(PROXY_PORT, DNS_PORT)
        self.vodafone = self._make_vodafone()
        self.latency = LatencyOptimizer(settings=self._latency_settings())
        self.proxy = TransparentProxy(
            PROXY_PORT, self._current_strategy, self._should_bypass, self._on_result
        )
        self.dns_server = DnsServer(self.resolver, DNS_PORT, self._on_dns_answer)
        self.netmon = NetworkMonitor(self._on_network_change)
        self.ipc = IpcServer(self._on_command)

        self.status = STATE_STARTING
        self.status_detail = "başlatılıyor"
        self.active_strategy: Optional[Strategy] = None
        self.profile: isps.IspProfile = isps.UNKNOWN
        self.profile_confidence = 0.0
        self.link = isps.LinkInfo()
        self.network: NetworkFingerprint = fingerprint()
        self.blocked = True
        self.last_results: list[dict] = []
        self.last_search_at = 0.0
        self.started_at = time.time()

        # Eşzamanlılık nesneleri, olay döngüsü başladıktan sonra kurulur
        # (eski Python sürümlerinde döngüye erken bağlanmamaları için).
        self._search_lock: asyncio.Lock = None  # type: ignore[assignment]
        self._latency_control_lock: asyncio.Lock = None  # type: ignore[assignment]
        self._probe_semaphore: asyncio.Semaphore = None  # type: ignore[assignment]
        self._search_task: Optional[asyncio.Task] = None
        self._latency_task: Optional[asyncio.Task] = None
        self._tasks: list[asyncio.Task] = []
        self._fail_counter: collections.Counter = collections.Counter()
        self._strategy_failures = 0
        self._stopping = False
        self._probed: dict[str, float] = {}

    # ------------------------------------------------------------------ #
    # yaşam döngüsü
    # ------------------------------------------------------------------ #
    async def run(self) -> int:
        if not is_root():
            log.error("Bu servis root olarak çalışmalıdır.")
            return 1

        log.info("%s %s başlıyor (yazan: Atom Gamer Arda A.G.A)",
                 APP_NAME, __version__)
        caps = capabilities()
        log.info("Yetenekler: sıra numarası okuma=%s, ham soket=%s "
                 "(sahte paket kipi %s)",
                 "var" if caps.get("seq_read") else "yok",
                 "var" if caps.get("raw_socket") else "yok",
                 "kullanılabilir" if caps.get("rawfake") else "kullanılamaz")

        self._search_lock = asyncio.Lock()
        self._latency_control_lock = asyncio.Lock()
        self._probe_semaphore = asyncio.Semaphore(2)
        self.resolver.set_preferred(self.config["dns_provider"])
        await self.ipc.start()
        if self.ipc.degraded:
            # Soket beklenen grup/kip ile kurulamadı: GUI ve komut satırı
            # bağlanamayacak. Sessizce herkese açmaktansa bunu yüksek sesle
            # söyle; kullanıcı 'dpi-bypass doctor' ile aynı tanıyı görür.
            log.error("Denetim soketi güvenli kipte: %s", self.ipc.degraded_reason)
        await self.latency.recover()

        loop = asyncio.get_running_loop()
        stop_event = asyncio.Event()
        for sig in (signal.SIGTERM, signal.SIGINT):
            try:
                loop.add_signal_handler(sig, stop_event.set)
            except NotImplementedError:  # pragma: no cover
                pass

        try:
            await self._start_network_services()
            await self.netmon.start()
            self.network = self.netmon.current
            self._apply_vodafone()
            if self.config["latency_mode"]:
                await self._restart_latency(self.network)
            self._tasks.append(asyncio.ensure_future(self._periodic_recheck()))
            self.trigger_search("servis başlangıcı")
            await stop_event.wait()
        finally:
            await self.shutdown()
        return 0

    async def _start_network_services(self) -> None:
        if not self.config["enabled"]:
            self.status = STATE_DISABLED
            self.status_detail = "kullanıcı tarafından kapatıldı"
            log.info("Servis yapılandırmada kapalı; kurallar uygulanmıyor.")
            return
        await self.dns_server.start()
        await self.proxy.start()
        self._apply_firewall()

    def _apply_firewall(self) -> None:
        try:
            self.firewall.apply(
                mode=self.config["mode"],
                dns_intercept=bool(self.config["dns_intercept"]),
                block_quic=bool(self.config["block_quic"]),
            )
        except FirewallError as exc:
            log.error("Güvenlik duvarı kuralları kurulamadı: %s", exc)
            self.status = STATE_FAILED
            self.status_detail = f"güvenlik duvarı hatası: {exc}"

    # ------------------------------------------------------------------ #
    # Vodafone sınırsız kipi
    # ------------------------------------------------------------------ #
    def _make_vodafone(self) -> VodafoneMode:
        """Yapılandırmadaki TTL geçersizse varsayılana dönerek örnekle."""
        try:
            return VodafoneMode(ttl=int(self.config["vodafone_ttl"]))
        except (VodafoneError, TypeError, ValueError) as exc:
            log.error("vodafone_ttl ayarı geçersiz (%s); %d kullanılacak",
                      exc, VODAFONE_TTL_VALUE)
            self.config.update({"vodafone_ttl": VODAFONE_TTL_VALUE})
            return VodafoneMode()

    def _apply_vodafone(self) -> None:
        """Vodafone modunu mevcut ağa göre uygula ya da kaldır."""
        if not self.config["enabled"] or not self.config["vodafone_mode"]:
            self.vodafone.clear()
            return

        net = self.network            # NetworkFingerprint
        if not net.is_online():
            self.vodafone.clear()
            return
        if not self.config.vodafone_has_network(net.key):
            log.info("Vodafone modu bu ağda kayıtlı değil (%s), uygulanmadı",
                     net.name)
            self.vodafone.clear()
            return
        try:
            self.vodafone.apply(
                net.interface,
                disable_ipv6=bool(self.config["vodafone_disable_ipv6"]))
            log.info("Vodafone modu etkin: %s (%s), TTL=%d",
                     net.name, net.interface, self.vodafone.ttl)
        except VodafoneError as exc:
            log.error("Vodafone modu uygulanamadı: %s", exc)

    async def shutdown(self) -> None:
        if self._stopping:
            return
        self._stopping = True
        log.info("Kapanıyor, kurallar geri alınıyor…")
        for task in self._tasks:
            task.cancel()
        if self._search_task and not self._search_task.done():
            self._search_task.cancel()
        await self._stop_latency()
        await self.netmon.stop()
        await self.proxy.stop()
        await self.dns_server.stop()
        self.firewall.clear()
        self.vodafone.clear()
        await self.ipc.stop()

    # ------------------------------------------------------------------ #
    # vekil / DNS geri çağırımları
    # ------------------------------------------------------------------ #
    def _current_strategy(self) -> Optional[Strategy]:
        return self.active_strategy

    def bypass_domains(self) -> list[str]:
        return [domain for domain in
                self.config.domains() + self.state.learned_domains()
                if not domain_matches(domain, self.direct_domains)]

    def _should_bypass(self, host: str, dst_ip: str) -> bool:
        if not host:
            return False
        if domain_matches(host, self.direct_domains):
            return False
        return domain_matches(host, self.bypass_domains())

    def _on_dns_answer(self, qname: str, addresses: list[str]) -> None:
        """Çözülen alan adlarını izle: bilinen engellileri yönlendirmeye ekle,
        bilinmeyenleri gerekirse sınayarak öğren."""
        if not addresses or not qname:
            return
        if domain_matches(qname, self.direct_domains):
            return
        known = domain_matches(qname, self.bypass_domains())
        if known:
            if self.config["mode"] == "smart":
                added = self.firewall.add_ips(addresses)
                if added:
                    log.debug("%s için %d IP yönlendirmeye eklendi", qname, added)
            return

        if not self.config["auto_discover"]:
            return
        if self.status != STATE_ACTIVE or self.active_strategy is None:
            return
        now = time.time()
        if self._probed.get(qname, 0) > now - 3600:
            return
        self._probed[qname] = now
        if len(self._probed) > 500:
            for old in sorted(self._probed, key=self._probed.get)[:200]:
                self._probed.pop(old, None)
        asyncio.ensure_future(self._probe_new_domain(qname, addresses))

    async def _probe_new_domain(self, host: str, addresses: list[str]) -> None:
        """Yeni görülen bir alan adı DPI ile engelli mi diye sessizce sına.

        Önce atlatmasız denenir; başarısız olup atlatmayla açılıyorsa site
        engellidir ve kalıcı olarak listeye alınır. Böylece "akıllı" kipte
        de her site kapsanır, üstelik diğer trafik vekilden geçmez.
        """
        if domain_matches(host, self.direct_domains):
            return
        async with self._probe_semaphore:
            if self.status != STATE_ACTIVE or self.active_strategy is None:
                return
            await asyncio.sleep(1.5)     # kullanıcının kendi isteğini geciktirme
            plain = await self.tester.probe(strategies.BY_NAME["none"],
                                            host=host, timeout=5)
            if plain.ok or plain.error == "alan adı çözümlenemedi":
                return
            with_bypass = await self.tester.probe(self.active_strategy,
                                                  host=host, timeout=6)
            if not with_bypass.ok:
                return
            if self.state.learn_domain(host):
                log.info("Yeni engelli site bulundu: %s — atlatma ile açıldı "
                         "(%d ms), listeye eklendi", host, with_bypass.latency_ms)
                self.firewall.add_ips(addresses)

    async def _on_result(self, host: str, ok: bool, bypassed: bool,
                         error: str) -> None:
        if domain_matches(host, self.direct_domains):
            return
        if ok:
            if bypassed:
                self._strategy_failures = 0
            self._fail_counter.pop(host, None)
            return

        if bypassed:
            self._strategy_failures += 1
            if self._strategy_failures >= 6 and self.status == STATE_ACTIVE:
                self._strategy_failures = 0
                log.warning("Seçili yöntem (%s) çalışmayı bıraktı; yeniden aranıyor",
                            self.active_strategy.name if self.active_strategy else "-")
                self.trigger_search("yöntem başarısız oldu")
            return

        # Atlatma uygulanmadan başarısız olan bağlantı: yeni engelli site olabilir
        if "." not in host:
            return
        self._fail_counter[host] += 1
        if self._fail_counter[host] >= 2 and \
                not domain_matches(host, self.bypass_domains()):
            if self.state.learn_domain(host):
                log.info("Yeni engelli alan adı öğrenildi: %s "
                         "(bundan sonra atlatma uygulanacak)", host)
                self._fail_counter.pop(host, None)

    # ------------------------------------------------------------------ #
    # saptama + arama
    # ------------------------------------------------------------------ #
    def trigger_search(self, reason: str) -> None:
        if self._search_task and not self._search_task.done():
            self._search_task.cancel()
        self._search_task = asyncio.ensure_future(self._search(reason))

    async def _search(self, reason: str) -> None:
        async with self._search_lock:
            try:
                await self._search_inner(reason)
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception("yöntem araması hata verdi")
                self.status = STATE_FAILED
                self.status_detail = "arama sırasında hata"

    async def _search_inner(self, reason: str) -> None:
        if not self.config["enabled"]:
            self.status = STATE_DISABLED
            self.status_detail = "kapalı"
            return

        self.status = STATE_SEARCHING
        self.status_detail = f"yöntem aranıyor ({reason})"
        self.network = fingerprint()
        log.info("── Yöntem araması başlıyor: %s | ağ: %s", reason, self.network.name)

        # 1) Operatör
        if self.config["isp"] == "auto":
            try:
                self.profile, self.profile_confidence, self.link = \
                    await asyncio.wait_for(isps.detect(), 25)
            except (asyncio.TimeoutError, Exception) as exc:  # noqa: B014
                log.warning("Operatör saptanamadı (%s); genel sıra kullanılacak", exc)
                self.profile, self.profile_confidence = isps.UNKNOWN, 0.0
        else:
            self.profile = isps.get(self.config["isp"])
            self.profile_confidence = 1.0
            log.info("Operatör elle seçildi: %s", self.profile.label)

        # 2) Aday sırası
        remembered = self.state.recall(self.network.key)
        preferred: list[str] = []
        if self.config["strategy"] != "auto":
            chosen = strategies.get(self.config["strategy"])
            if chosen:
                log.info("Yöntem elle seçildi: %s", chosen.label)
                await self._activate_strategy(chosen, verified=False)
                return
        if remembered and remembered.get("strategy"):
            preferred.append(remembered["strategy"])
            log.info("Bu ağ daha önce görüldü; önce %s denenecek",
                     remembered["strategy"])
        preferred.extend(self.profile.strategies)
        candidates = strategies.order_for(preferred)

        # 3) Engel var mı? (DoH zaten devrede olduğu için bu, DPI katmanını ölçer)
        try:
            self.blocked = await asyncio.wait_for(self.tester.is_blocked(), 20)
        except asyncio.TimeoutError:
            self.blocked = True
        if not self.blocked:
            log.info("DPI engeli görülmedi — DNS düzeyindeki engel DoH ile aşıldı.")
            self.active_strategy = None
            self.status = STATE_DNS_ONLY
            self.status_detail = "DNS engeli aşıldı, DPI atlatması gerekmiyor"
            self.last_search_at = time.time()
            await self._prefetch_domains()
            return

        # 4) Sırayla dene
        log.info("DPI engeli saptandı; %d yöntem denenecek", len(candidates))
        found, results = await self.tester.find_working(candidates)
        self.last_results = [r.to_dict() for r in results]
        self.last_search_at = time.time()

        if found is None:
            self.status = STATE_FAILED
            self.status_detail = "çalışan bir yöntem bulunamadı"
            log.error("Hiçbir yöntem işe yaramadı. Ağ tamamen kapalı olabilir.")
            return

        await self._activate_strategy(found, verified=True)

    async def _activate_strategy(self, strategy: Strategy, verified: bool) -> None:
        self.active_strategy = strategy
        self.resolver.set_strategy(strategy)
        self.status = STATE_ACTIVE
        self.status_detail = strategy.label
        self._strategy_failures = 0
        self.state.remember(self.network.key, self.network.name,
                            self.profile.id, strategy.name)
        log.info("✔ Çalışan yöntem: %s (%s)%s", strategy.label, strategy.name,
                 "" if verified else " — doğrulanmadı, elle seçildi")
        await self._prefetch_domains()

    async def _prefetch_domains(self) -> None:
        """Engelli alan adlarını DoH ile çözüp yönlendirme kümesine ekle."""
        if self.config["mode"] != "smart":
            return
        domains = self.bypass_domains()
        semaphore = asyncio.Semaphore(8)

        async def resolve_one(domain: str) -> None:
            async with semaphore:
                try:
                    addrs = await self.resolver.resolve(domain, timeout=6)
                except Exception:
                    return
                if addrs:
                    self.firewall.add_ips(addrs)

        await asyncio.gather(*(resolve_one(d) for d in domains),
                             return_exceptions=True)
        log.info("Yönlendirme kümesinde %d IP var",
                 self.firewall.status()["ips"])

    # ------------------------------------------------------------------ #
    # ağ değişikliği ve düzenli denetim
    # ------------------------------------------------------------------ #
    async def _restart_latency(self, fp: NetworkFingerprint) -> None:
        """Eski arayüzü geri alıp yeni ağ için tek bir ölçüm işi başlat."""
        async with self._latency_control_lock:
            current = self._latency_task
            if current is not None and not current.done():
                self.latency.request_cancel()
                try:
                    await current
                except asyncio.CancelledError:
                    pass
            if self.latency.snapshot is not None:
                if not await self.latency.disable():
                    log.error("Eski ağın gecikme ayarları geri alınamadı; "
                              "yeni ağa optimizasyon uygulanmayacak")
                    return
            if not self.config["latency_mode"]:
                return
            self._latency_task = asyncio.ensure_future(self.latency.optimize(fp))

    async def _stop_latency_task(self) -> None:
        """Devam eden ölçüm işini bitir; ayarları geri almayı çağırana bırak."""
        lock = self._latency_control_lock
        if lock is None:
            return
        async with lock:
            current = self._latency_task
            if current is not None and not current.done():
                self.latency.request_cancel()
                try:
                    await current
                except asyncio.CancelledError:
                    pass
            self._latency_task = None

    async def _stop_latency(self) -> bool:
        """Devam eden ölçümü durdur ve uygulanmış bütün ayarları geri al."""
        lock = self._latency_control_lock
        if lock is None:  # yalnız kısmi test örnekleri için
            return await self.latency.disable()
        async with lock:
            current = self._latency_task
            if current is not None and not current.done():
                self.latency.request_cancel()
                try:
                    await current
                except asyncio.CancelledError:
                    pass
            self._latency_task = None
            return await self.latency.disable()

    async def _on_network_change(self, fp: NetworkFingerprint) -> None:
        self.network = fp
        self.resolver.clear_cache()
        self.tester._ip_cache.clear()
        # Gecikme ayarları arayüze bağlıdır. Eski arayüzdeki runtime değişiklik
        # tamamen geri alınmadan yenisi için ölçüm/apply işi başlamaz.
        await self._restart_latency(fp)
        # TTL düzeltmesi ağa bağlıdır: yeni ağ kayıtlı değilse kendiliğinden
        # kalkar, kayıtlıysa yeni arayüz için yeniden kurulur.
        self._apply_vodafone()
        if not fp.is_online():
            self.status_detail = "ağ bağlantısı yok"
            log.info("Ağ bağlantısı kesildi; arama beklemede")
            return
        if not self.config["auto_switch"]:
            log.info("Ağ değişti ama otomatik arama kapalı; mevcut yöntem korunuyor")
            return
        # Yeni ağın hazır olması için kısa bir bekleme (DHCP/portal)
        await asyncio.sleep(1.0)
        self.trigger_search(f"ağ değişti → {fp.name}")

    @staticmethod
    def _redact(value, mapping: dict):
        """Hedef kimliklerini rapordan çıkar, ölçüm verisini koru.

        İki katman:

        * Kimlik taşıyan anahtarlar (``host``, ``address``, ``source``,
          ``display``, ``label``) tamamen düşürülür.
        * Serbest metinlerde (mesajlar, gerekçeler, atlama notları) geçen
          aynı değerler kararlı bir yer tutucuyla değiştirilir. Bu ikinci
          katman olmadan hedef adı ``skipped`` notlarında ve karar
          gerekçelerinde sızardı.
        """
        if isinstance(value, dict):
            return {key: Daemon._redact(item, mapping)
                    for key, item in value.items()
                    if key not in ("host", "address", "source", "display",
                                   "label")}
        if isinstance(value, list):
            return [Daemon._redact(item, mapping) for item in value]
        if isinstance(value, str):
            for secret, placeholder in mapping.items():
                if secret and secret in value:
                    value = value.replace(secret, placeholder)
            return value
        return value

    def _redaction_map(self, status: dict) -> dict:
        """Rapordan çıkarılacak kimlikler → kararlı yer tutucular."""
        secrets: list = []

        def note(text) -> None:
            text = str(text or "")
            if len(text) >= 3 and text not in secrets:
                secrets.append(text)

        for target in self.latency.settings.targets:
            note(target.host)
            note(target.label)
        for key in ("before", "after"):
            measurement = status.get(key) or {}
            for endpoint in measurement.get("endpoints") or []:
                for field in ("host", "address", "source", "display", "label"):
                    note((endpoint.get("endpoint") or {}).get(field))
        for text in status.get("targets") or []:
            note(text)
        note(self.network.ssid)
        note(self.network.gateway)
        note(self.network.gateway_mac)
        # Uzun değerler önce değiştirilsin ki kısa bir parça uzununu bozmasın.
        secrets.sort(key=len, reverse=True)
        return {secret: f"<hedef-{index + 1}>"
                for index, secret in enumerate(secrets)}

    def _latency_report(self) -> dict:
        """Paylaşılabilir tanı raporu.

        Rapor yereldir, sınırlı boyuttadır ve varsayılan olarak gizlilik
        korumalıdır: SSID, ağ geçidi ve MAC'i, dış IP ve kullanıcının hedef
        adları/adresleri rapora KONMAZ — serbest metinlerde geçenler dahil.
        Geriye ölçüm ve karar verileri kalır; teşhis için gereken budur.
        """
        raw = self._latency_status()
        status = self._redact(raw, self._redaction_map(raw))
        status.pop("targets", None)
        settings = status.get("settings")
        if isinstance(settings, dict):
            settings["targets"] = len(self.latency.settings.targets)
        return {
            "version": __version__,
            "generated_at": time.time(),
            "redacted": True,
            "network": {"key": self.network.key[:8],
                        "link_type": self.network.link_type,
                        "interface": self.network.interface},
            "latency": status,
        }

    async def _periodic_recheck(self) -> None:
        while True:
            interval = int(self.config["recheck_interval"] or 0)
            await asyncio.sleep(interval if interval > 0 else 600)
            # Gecikme profilinin hafif denetimi, bypass denetiminden bağımsız
            # çalışır: uygulanmış ayar hâlâ yürürlükte mi? Yeni benchmark
            # başlatmaz, cooldown ve histerezis kullanır.
            if self.config["latency_mode"]:
                try:
                    await self.latency.revalidate(self.network)
                except Exception:
                    log.exception("gecikme profili denetimi hata verdi")
            if interval <= 0 or not self.config["enabled"]:
                continue
            if self.status not in (STATE_ACTIVE, STATE_DNS_ONLY):
                self.trigger_search("düzenli denetim")
                continue
            strategy = self.active_strategy or strategies.BY_NAME["none"]
            result = await self.tester.probe(strategy)
            if result.ok:
                log.debug("düzenli denetim: %s hâlâ çalışıyor (%d ms)",
                          strategy.name, result.latency_ms)
            else:
                log.warning("düzenli denetim başarısız (%s); yeniden aranıyor",
                            result.error)
                self.trigger_search("düzenli denetim başarısız")

    # ------------------------------------------------------------------ #
    # IPC komutları
    # ------------------------------------------------------------------ #
    def status_dict(self) -> dict:
        return {
            "version": __version__,
            "status": self.status,
            "detail": self.status_detail,
            "enabled": bool(self.config["enabled"]),
            "blocked": self.blocked,
            "strategy": self.active_strategy.to_dict() if self.active_strategy else None,
            "isp": {
                "id": self.profile.id,
                "label": self.profile.label,
                "confidence": round(self.profile_confidence, 2),
                "note": self.profile.note,
                "manual": self.config["isp"] != "auto",
            },
            "link": self.link.to_dict(),
            "network": self.network.to_dict(),
            "firewall": self.firewall.status(),
            "socket": self.ipc.status(),
            "latency": self._latency_status(),
            "vodafone": self._vodafone_status(),
            "proxy": dict(self.proxy.stats),
            "dns": {
                **self.dns_server.stats,
                **self.resolver.stats,
                "provider": self.resolver.last_provider,
            },
            "capabilities": capabilities(),
            "last_search_at": self.last_search_at,
            "last_results": self.last_results,
            "uptime": int(time.time() - self.started_at),
            "domains": len(self.bypass_domains()),
            "learned_domains": self.state.learned_domains(),
        }

    def _vodafone_status(self) -> dict:
        """Kural durumuna kullanıcının seçimini ve ağ kaydını da ekler."""
        return {
            **self.vodafone.status(),
            "mode": bool(self.config["vodafone_mode"]),
            "registered": self.config.vodafone_has_network(self.network.key),
            "network": self.network.name,
            "networks": self.config.vodafone_networks(),
        }

    def _latency_settings(self) -> LatencySettings:
        """Kullanıcının kalıcı tercihlerini motorun ayarlarına çevir.

        Geçersiz kayıtlar sessizce yok sayılmaz: nedeni günlüğe yazılır ve
        hedef listeye alınmaz. Yük testi ve SQM ayrı ayrı opt-in'dir ve
        eksik/geçersiz yapılandırmada kendiliğinden etkinleşmez.
        """
        targets = []
        for raw in self.config["latency_targets"] or []:
            try:
                targets.append(TargetSpec.from_dict(raw))
            except (ValueError, TypeError) as exc:
                log.warning("Gecikme ölçüm hedefi yok sayıldı (%s): %s",
                            raw, exc)

        load_target = None
        raw_load = self.config["latency_load_target"] or {}
        if raw_load:
            try:
                load_target = LoadTarget.from_dict(raw_load)
            except (ValueError, TypeError) as exc:
                log.warning("Yük testi hedefi yok sayıldı: %s", exc)

        load_enabled = bool(self.config["latency_load_test"]) and \
            load_target is not None and load_target.owned
        if bool(self.config["latency_load_test"]) and not load_enabled:
            log.warning("Yük testi açık ama onaylanmış bir hedef yok; "
                        "yük uygulanmayacak")

        settings = LatencySettings(
            targets=targets,
            load_test=load_enabled,
            load_target=load_target,
            load_budget=LoadBudget(
                max_seconds=int(self.config["latency_load_max_seconds"] or 0),
                max_bytes=int(self.config["latency_load_max_bytes"] or 0)),
            metered=bool(self.config["latency_metered"]),
            sqm=bool(self.config["latency_sqm"]),
            uplink_kbit=int(self.config["latency_uplink_kbit"] or 0),
            downlink_kbit=int(self.config["latency_downlink_kbit"] or 0),
            max_throughput_loss=float(
                self.config["latency_max_throughput_loss"] or 15.0),
        )
        if settings.sqm and settings.uplink_kbit <= 0:
            log.warning("SQM kipi açık ama hat kapasitesi girilmemiş; "
                        "shaping uygulanmayacak")
        return settings

    def _latency_status(self) -> dict:
        """Runtime durumuna kalıcı kullanıcı seçimini ekle.

        ``enabled`` kullanıcının tercihidir; ``active`` şu anda yürürlükte
        ve doğrulanmış ayarı gösterir. İkisi karıştırılmaz.
        """
        data = self.latency.status_dict()
        data["enabled"] = bool(self.config["latency_mode"])
        data["settings"] = {
            "targets": [item.to_dict() for item in self.latency.settings.targets],
            "load_test": self.latency.settings.load_test,
            "sqm": self.latency.settings.sqm,
            "uplink_kbit": self.latency.settings.uplink_kbit,
            "downlink_kbit": self.latency.settings.downlink_kbit,
        }
        return data

    @staticmethod
    def _validate_latency_values(values: dict) -> str:
        """Gecikme ayarlarını kabul etmeden önce doğrula."""
        for key in ("latency_mode", "latency_load_test", "latency_sqm",
                    "latency_metered"):
            if key in values and not isinstance(values[key], bool):
                return f"{key} true/false olmalı"
        for key, low, high in (("latency_uplink_kbit", 0, 10_000_000),
                               ("latency_downlink_kbit", 0, 10_000_000),
                               ("latency_load_max_seconds", 1, 60),
                               ("latency_load_max_bytes", 1024, 512 * 1024 * 1024)):
            if key not in values:
                continue
            value = values[key]
            if isinstance(value, bool) or not isinstance(value, int) \
                    or not low <= value <= high:
                return f"{key} {low}-{high} aralığında bir tam sayı olmalı"
        if "latency_max_throughput_loss" in values:
            value = values["latency_max_throughput_loss"]
            if isinstance(value, bool) or not isinstance(value, (int, float)) \
                    or not 0 <= float(value) <= 50:
                return "latency_max_throughput_loss 0-50 aralığında olmalı"
        if "latency_targets" in values:
            raw = values["latency_targets"]
            if not isinstance(raw, list) or len(raw) > 8:
                return "latency_targets en çok 8 öğeli bir liste olmalı"
            for item in raw:
                try:
                    TargetSpec.from_dict(item)
                except (ValueError, TypeError) as exc:
                    return f"geçersiz ölçüm hedefi: {exc}"
        if "latency_load_target" in values:
            raw = values["latency_load_target"]
            if not isinstance(raw, dict):
                return "latency_load_target bir nesne olmalı"
            if raw:
                try:
                    LoadTarget.from_dict(raw)
                except (ValueError, TypeError) as exc:
                    return f"geçersiz yük testi hedefi: {exc}"
        return ""

    async def _on_command(self, request: dict) -> dict:
        cmd = str(request.get("cmd", ""))
        try:
            if cmd == "ping":
                return {"ok": True, "data": "pong"}

            if cmd == "status":
                return {"ok": True, "data": self.status_dict()}

            if cmd == "config.get":
                return {"ok": True, "data": self.config.data}

            if cmd == "config.set":
                values = request.get("values") or {}
                if not isinstance(values, dict):
                    return {"ok": False, "error": "values bir nesne olmalı"}
                problem = self._validate_latency_values(values)
                if problem:
                    return {"ok": False, "error": problem}
                changed = self.config.update(values)
                await self._apply_config_change(changed)
                return {"ok": True, "data": {"changed": changed,
                                             "config": self.config.data}}

            if cmd == "strategies":
                return {"ok": True, "data": [s.to_dict() for s in strategies.CATALOG]}

            if cmd == "isps":
                return {"ok": True, "data": [p.to_dict() for p in isps.PROFILES]}

            if cmd == "search":
                self.trigger_search(request.get("reason") or "kullanıcı isteği")
                return {"ok": True, "data": "arama başlatıldı"}

            if cmd == "detect":
                profile, confidence, link = await isps.detect()
                self.profile, self.profile_confidence, self.link = \
                    profile, confidence, link
                return {"ok": True, "data": {"isp": profile.to_dict(),
                                             "confidence": confidence,
                                             "link": link.to_dict()}}

            if cmd == "test":
                name = request.get("strategy")
                strategy = (strategies.get(name) if name
                            else (self.active_strategy or strategies.BY_NAME["none"]))
                if strategy is None:
                    return {"ok": False, "error": f"bilinmeyen yöntem: {name}"}
                result = await self.tester.probe(strategy)
                return {"ok": True, "data": result.to_dict()}

            if cmd == "latency.status":
                return {"ok": True, "data": self._latency_status()}

            if cmd == "latency.enable":
                changed = self.config.update({"latency_mode": True})
                await self._apply_config_change(changed)
                if not changed:
                    self.network = fingerprint()
                    await self._restart_latency(self.network)
                return {"ok": True, "data": self._latency_status()}

            if cmd == "latency.disable":
                self.config.update({"latency_mode": False})
                if not await self._stop_latency():
                    return {"ok": False,
                            "error": "Gecikme ayarlarının tamamı geri alınamadı"}
                return {"ok": True, "data": self._latency_status()}

            if cmd == "latency.test":
                self.network = fingerprint()
                condition = str(request.get("condition") or "idle")
                try:
                    measured = await self.latency.measure_only(
                        self.network, condition=condition)
                except LatencyError as exc:
                    return {"ok": False, "error": str(exc)}
                return {"ok": True, "data": measured.to_dict()}

            if cmd == "latency.cancel":
                await self._stop_latency_task()
                return {"ok": True, "data": await self.latency.cancel()}

            if cmd == "latency.report":
                # Tanı raporu: yerel, sınırlı boyutta ve varsayılan olarak
                # gizlilik korumalı. SSID, MAC ve dış IP rapora girmez.
                return {"ok": True, "data": self._latency_report()}

            if cmd == "logs":
                since = float(request.get("since") or 0)
                return {"ok": True, "data": logging_setup.ring_entries(since)}

            if cmd == "networks":
                return {"ok": True, "data": self.state.networks()}

            if cmd == "forget":
                key = request.get("key") or self.network.key
                self.state.forget(key)
                return {"ok": True, "data": "unutuldu"}

            if cmd == "enable":
                self.config.update({"enabled": True})
                await self._apply_config_change(["enabled"])
                return {"ok": True, "data": "açıldı"}

            if cmd == "disable":
                self.config.update({"enabled": False})
                await self._apply_config_change(["enabled"])
                return {"ok": True, "data": "kapatıldı"}

            if cmd == "vodafone.enable":
                # O anki ağı kaydeder ve modu açar.
                self.network = fingerprint()
                net = self.network
                if not net.is_online():
                    return {"ok": False,
                            "error": "Şu anda bir ağa bağlı değilsiniz."}
                self.config.vodafone_add_network(net.key, net.name,
                                                 net.interface)
                self.config.update({"vodafone_mode": True})
                self._apply_vodafone()
                return {"ok": True, "data": {"network": net.to_dict(),
                                             "vodafone": self._vodafone_status()}}

            if cmd == "vodafone.disable":
                self.config.update({"vodafone_mode": False})
                if not self.vodafone.clear():
                    return {"ok": False,
                            "error": "TTL kuralları kaldırılamadı; kural "
                                     "çekirdekte hâlâ etkin olabilir."}
                return {"ok": True, "data": {"vodafone": self._vodafone_status()}}

            if cmd == "vodafone.forget":
                key = request.get("key") or self.network.key
                self.config.vodafone_remove_network(key)
                self._apply_vodafone()
                return {"ok": True, "data": {"vodafone": self._vodafone_status()}}

            if cmd == "vodafone.verify":
                # Kuralın gerçekten paket saydığını döndürür.
                return {"ok": True, "data": self._vodafone_status()}

            return {"ok": False, "error": f"bilinmeyen komut: {cmd}"}
        except Exception as exc:
            log.exception("komut hatası: %s", cmd)
            return {"ok": False, "error": str(exc)}

    async def _apply_config_change(self, changed: list[str]) -> None:
        if not changed:
            return
        log.info("Ayar değişti: %s", ", ".join(changed))

        # TTL eşitlemesi "enabled" dalından önce yapılır: o dal return ile
        # çıkar ve iki ayar birlikte değiştiğinde eşitleme atlanırdı.
        if "vodafone_ttl" in changed:
            try:
                self.vodafone.ttl = int(self.config["vodafone_ttl"])
            except (VodafoneError, TypeError, ValueError) as exc:
                log.error("vodafone_ttl ayarı geçersiz (%s); önceki değer "
                          "(%d) geri yazıldı", exc, self.vodafone.ttl)
                # Yapılandırma dosyası da gerçeği göstersin.
                self.config.update({"vodafone_ttl": self.vodafone.ttl})

        if any(key.startswith("latency_") and key != "latency_mode"
               for key in changed):
            # Hedef/yük/SQM ayarları değişti: motorun ayarlarını tazele. Aktif
            # bir profil varsa artık başka koşullarda ölçülmüş sayılır ve
            # yeniden doğrulanmadan "aktif kazanç" gösterilmez.
            self.latency.settings = self._latency_settings()
            if self.config["latency_mode"]:
                self.network = fingerprint()
                await self._restart_latency(self.network)

        if "latency_mode" in changed:
            if self.config["latency_mode"]:
                self.network = fingerprint()
                await self._restart_latency(self.network)
            else:
                await self._stop_latency()

        if "enabled" in changed:
            if self.config["enabled"]:
                await self._start_network_services()
                self._apply_vodafone()
                self.trigger_search("servis açıldı")
            else:
                self.firewall.clear()
                self.vodafone.clear()
                await self.proxy.stop()
                await self.dns_server.stop()
                self.active_strategy = None
                self.status = STATE_DISABLED
                self.status_detail = "kapatıldı"
            return

        if "dns_provider" in changed:
            self.resolver.set_preferred(self.config["dns_provider"])
            self.resolver.clear_cache()

        if any(k in changed for k in ("mode", "dns_intercept", "block_quic")):
            if self.config["enabled"]:
                self._apply_firewall()

        if any(k in changed for k in ("isp", "strategy", "extra_domains",
                                      "disabled_domains")):
            if self.config["enabled"]:
                self.trigger_search("ayar değişikliği")

        if any(k in changed for k in ("vodafone_mode", "vodafone_networks",
                                      "vodafone_ttl", "vodafone_disable_ipv6")):
            self._apply_vodafone()

        if "verbose" in changed:
            logging.getLogger().setLevel(
                logging.DEBUG if self.config["verbose"] else logging.INFO
            )


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(
        prog="dpi-bypassd", description=f"{APP_NAME} arka plan servisi")
    parser.add_argument("-v", "--verbose", action="store_true", help="ayrıntılı günlük")
    parser.add_argument("--cleanup", action="store_true",
                        help="yalnızca çekirdek kurallarını temizle ve çık")
    args = parser.parse_args(argv)

    logging_setup.setup(args.verbose)

    if args.cleanup:
        Firewall().clear()
        VodafoneMode().clear()
        if not LatencyOptimizer().restore_persisted_sync():
            log.error("Gecikme ayarlarının tamamı geri alınamadı.")
            return 1
        log.info("Kurallar temizlendi.")
        return 0

    daemon = Daemon(verbose=args.verbose)
    try:
        return asyncio.run(daemon.run())
    except KeyboardInterrupt:
        return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
