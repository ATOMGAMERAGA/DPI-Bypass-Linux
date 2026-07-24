"""Strateji doğrulama: gerçekten çalışıyor mu?

Bir yöntem bulunduğunda ya da ağ değiştiğinde, discord.com üzerinde gerçek
bir TLS el sıkışması + HTTP isteği yapılır. Yalnızca "bağlantı kuruldu"
demek yetmez; DPI çoğu zaman TCP el sıkışmasına izin verip ClientHello'dan
sonra RST gönderir. Bu yüzden sunucudan gerçek yanıt beklenir.
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass

from . import desync, strategies, tlsclient
from .constants import TEST_TARGETS
from .resolver import Resolver
from .strategies import Strategy

log = logging.getLogger("dpibypass.test")


@dataclass
class TestResult:
    strategy: str
    label: str
    ok: bool
    latency_ms: int = 0
    error: str = ""
    target: str = ""

    def to_dict(self) -> dict:
        return {
            "strategy": self.strategy,
            "label": self.label,
            "ok": self.ok,
            "latency_ms": self.latency_ms,
            "error": self.error,
            "target": self.target,
        }


class Tester:
    def __init__(self, resolver: Resolver) -> None:
        self.resolver = resolver
        self._ip_cache: dict[str, list[str]] = {}

    async def target_ips(self, host: str, refresh: bool = False) -> list[str]:
        if refresh or host not in self._ip_cache:
            addrs = await self.resolver.resolve(host)
            if addrs:
                self._ip_cache[host] = addrs
        return self._ip_cache.get(host, [])

    async def probe(self, strategy: Strategy, host: str = "", port: int = 443,
                    path: str = "/", timeout: float = 7.0) -> TestResult:
        """Tek bir stratejiyi tek bir hedefe karşı dene."""
        host = host or TEST_TARGETS[0][0]
        result = TestResult(strategy=strategy.name, label=strategy.label,
                            ok=False, target=host)
        if not desync.strategy_available(strategy):
            result.error = "bu sistemde kullanılamıyor (TCP_REPAIR yok)"
            return result

        ips = await self.target_ips(host)
        if not ips:
            result.error = "alan adı çözümlenemedi"
            return result

        started = time.monotonic()
        last_error = ""
        for ip in ips[:3]:
            try:
                status, _body = await asyncio.wait_for(
                    tlsclient.https_request(
                        ip, host, "HEAD", path,
                        strategy=strategy, port=port, timeout=timeout,
                    ),
                    timeout + 2,
                )
                if status > 0:
                    result.ok = True
                    result.latency_ms = int((time.monotonic() - started) * 1000)
                    return result
                last_error = "boş HTTP yanıtı"
            except asyncio.TimeoutError:
                last_error = "zaman aşımı"
            except ConnectionResetError:
                last_error = "bağlantı sıfırlandı (RST)"
            except Exception as exc:
                last_error = str(exc) or exc.__class__.__name__
        result.error = last_error or "bilinmeyen hata"
        result.latency_ms = int((time.monotonic() - started) * 1000)
        return result

    async def verify(self, strategy: Strategy, timeout: float = 7.0) -> TestResult:
        """Seçili stratejiyi birden çok Discord uç noktasında doğrula."""
        last = TestResult(strategy.name, strategy.label, False)
        for host, port, path in TEST_TARGETS[:2]:
            last = await self.probe(strategy, host, port, path, timeout)
            if not last.ok:
                return last
        return last

    async def is_blocked(self, timeout: float = 6.0) -> bool:
        """Atlatma olmadan erişilebiliyor mu? (engel var mı?)"""
        plain = strategies.BY_NAME["none"]
        result = await self.probe(plain, timeout=timeout)
        return not result.ok

    async def find_working(self, candidates: list[Strategy],
                           timeout: float = 7.0,
                           stop_on_first: bool = True,
                           progress=None) -> tuple[Strategy | None, list[TestResult]]:
        """Adayları sırayla dene; ilk çalışanı döndür."""
        results: list[TestResult] = []
        for strategy in candidates:
            if not desync.strategy_available(strategy):
                continue
            result = await self.probe(strategy, timeout=timeout)
            results.append(result)
            log.info("  %-22s %s%s", strategy.name,
                     "ÇALIŞIYOR" if result.ok else "başarısız",
                     f" ({result.latency_ms} ms)" if result.ok
                     else f" — {result.error}")
            if progress:
                try:
                    progress(result)
                except Exception:
                    pass
            if result.ok and stop_on_first:
                # ikinci bir hedefle doğrula: tek seferlik şans olmasın
                confirm = await self.verify(strategy, timeout)
                if confirm.ok:
                    return strategy, results
                log.info("  %-22s doğrulama başarısız (%s), aramaya devam",
                         strategy.name, confirm.error)
                result.ok = False
                result.error = "doğrulanamadı: " + confirm.error
        return None, results
