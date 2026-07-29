"""Vodafone sınırsız modu — giden paketlerin TTL/hop limit değerini düzeltir.

Operatör, hotspot kullanımını paketin TTL değerinden anlar: telefonun kendi
trafiği 64 ile ulaşırken, paylaşılan bağlantıdan gelen paket telefonda bir
kez yönlendirildiği için 63 olarak varır. Bu modül giden paketleri 65 ile
yollar; telefon bir düşürünce operatöre tam 64 gider.

Kurallar ``inet dpibypass_ttl`` tablosunda, Firewall sınıfının tablolarından
ayrı tutulur. Böylece çalışma kipi değiştiğinde silinmezler.

ÖNEMLİ: Kural yalnızca TTL'i VODAFONE_TTL_GUARD üstünde olan paketlere
uygulanır. desync/rawfake modülleri kasıtlı olarak düşük TTL kullanır;
onlara dokunulursa DPI atlatma çalışmaz.
"""

from __future__ import annotations

import json
import logging
import os
import re

from .constants import (VODAFONE_CHAIN, VODAFONE_HELPER, VODAFONE_STATE_FILE,
                        VODAFONE_TABLE, VODAFONE_TTL_GUARD, VODAFONE_TTL_VALUE)
from .util import run, which

log = logging.getLogger("dpibypass.vodafone")

#: Çekirdeğin kabul ettiği arayüz adı (IFNAMSIZ-1 = 15 karakter).
#: Sonda ``\Z`` kullanılır: ``$`` sondaki satır sonunu da eşleştirir ve
#: "wlan0\n" gibi bir ad kural metnine satır enjekte edebilirdi.
_IFACE_RE = re.compile(r"^[A-Za-z0-9_.@-]{1,15}\Z")

#: IPv6'nın arayüz bazında kapatıldığı sysctl dosyası.
_IPV6_SYSCTL = "/proc/sys/net/ipv6/conf/{iface}/disable_ipv6"

#: Kaynak ağacından çalıştırıldığında yardımcı betiğin aranacağı yerler.
_HELPER_FALLBACKS = (
    VODAFONE_HELPER,
    "/usr/local/libexec/dpi-bypass/vodafone-helper",
)


class VodafoneError(RuntimeError):
    pass


def validate_interface(iface: str) -> str:
    """Arayüz adını doğrula; kural metnine yalnızca doğrulanmış ad girer."""
    if not isinstance(iface, str) or not _IFACE_RE.match(iface):
        raise VodafoneError(f"geçersiz arayüz adı: {iface!r}")
    return iface


def helper_path() -> str | None:
    """pkexec ile çalıştırılacak yardımcı betiğin yolu."""
    for path in _HELPER_FALLBACKS:
        if os.access(path, os.X_OK):
            return path
    # kaynak ağacı: <repo>/bin/vodafone-helper
    local = os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(
            os.path.abspath(__file__)))),
        "bin", "vodafone-helper")
    return local if os.access(local, os.X_OK) else None


class VodafoneMode:
    """Giden paketlerin TTL/hop limit değerini tek bir arayüzde düzeltir."""

    def __init__(self, ttl: int = VODAFONE_TTL_VALUE,
                 guard: int = VODAFONE_TTL_GUARD) -> None:
        self.guard = int(guard)
        self._ttl = VODAFONE_TTL_VALUE
        self.ttl = ttl                      # doğrulama setter'da yapılır
        self.interface = ""
        self.active = False
        self._backend: str | None = None
        self._backend_probed = False
        self._ipv6_previous: str | None = None
        self._ipv6_iface = ""

    # -- ayarlar ---------------------------------------------------------
    @property
    def ttl(self) -> int:
        return self._ttl

    @ttl.setter
    def ttl(self, value: int) -> None:
        try:
            number = int(value)
        except (TypeError, ValueError):
            raise VodafoneError(f"TTL bir sayı olmalı: {value!r}") from None
        if not self.guard < number <= 255:
            raise VodafoneError(
                f"TTL {self.guard + 1}-255 aralığında olmalı (verilen: {number}). "
                f"Koruma eşiğinin altındaki bir değer normal trafiği keser.")
        self._ttl = number

    # -- arka uç seçimi (firewall.py ile aynı mantık) --------------------
    @property
    def backend(self) -> str | None:
        if not self._backend_probed:
            self._backend = self._detect_backend()
            self._backend_probed = True
        return self._backend

    @staticmethod
    def _detect_backend() -> str | None:
        if which("nft"):
            probe = run(["nft", "list", "ruleset"], timeout=10)
            if probe.returncode == 0:
                return "nft"
        if which("iptables"):
            return "iptables"
        return None

    def describe(self) -> str:
        return {"nft": "nftables",
                "iptables": "iptables"}.get(self.backend or "", "yok")

    # -- yaşam döngüsü ---------------------------------------------------
    def apply(self, iface: str, disable_ipv6: bool = True) -> None:
        """Kuralları verilen arayüz için kur. Önce mevcutları temizler."""
        validate_interface(iface)
        self.clear()
        if self.backend is None:
            raise VodafoneError(
                "Ne nftables ne iptables bulundu; TTL kuralı kurulamıyor.")
        if self.backend == "nft":
            self._apply_nft(iface)
        else:
            self._apply_iptables(iface)
        self.interface = iface
        self.active = True
        if disable_ipv6:
            self._disable_ipv6(iface)

    def clear(self) -> bool:
        """Kuralları kaldır ve IPv6 ayarını eski haline getir.

        Kaldırma başarısız olursa False döner ve ``active`` olduğu gibi
        bırakılır: kural çekirdekte hâlâ çalışıyor olabilir, kullanıcıya
        "kapalı" göstermek yanıltıcı olurdu.
        """
        ok = True
        if self.backend == "nft":
            ok = self._clear_nft()
        elif self.backend == "iptables":
            ok = self._clear_iptables()
        self._restore_ipv6()
        if ok:
            self.active = False
            self.interface = ""
        return ok

    # -- bilgi -----------------------------------------------------------
    def status(self) -> dict:
        packets4, packets6 = self.counters() if self.active else (0, 0)
        return {
            "active": self.active,
            "interface": self.interface,
            "ttl": self.ttl,
            "backend": self.describe(),
            "packets": packets4 + packets6,
            "ipv6_disabled": self._ipv6_previous is not None,
        }

    def counters(self) -> tuple[int, int]:
        """(ipv4_paket, ipv6_paket) — kuralın gerçekten çalıştığını gösterir."""
        if self.backend == "nft":
            return self._counters_nft()
        if self.backend == "iptables":
            return (self._counters_iptables("iptables"),
                    self._counters_iptables("ip6tables"))
        return (0, 0)

    # -- nftables --------------------------------------------------------
    def _build_nft_script(self, iface: str) -> str:
        """Uygulanacak kural metnini üret (yan etkisiz; testlerde çağrılır).

        ``table`` + ``delete table`` ikilisi, tablo ister var ister yok
        olsun çalışan idempotent kalıptır. ``priority 300`` srcnat'tan (100)
        sonra gelir; böylece paketin tel üzerindeki son hali düzeltilir.
        """
        validate_interface(iface)
        return (
            f"table inet {VODAFONE_TABLE}\n"
            f"delete table inet {VODAFONE_TABLE}\n"
            f"table inet {VODAFONE_TABLE} {{\n"
            f"    chain postrouting {{\n"
            f"        type filter hook postrouting priority 300; policy accept;\n"
            f'        oifname "{iface}" meta nfproto ipv4 '
            f"ip ttl >= {self.guard} counter ip ttl set {self.ttl}\n"
            f'        oifname "{iface}" meta nfproto ipv6 '
            f"ip6 hoplimit >= {self.guard} counter ip6 hoplimit set {self.ttl}\n"
            f"    }}\n"
            f"}}\n"
        )

    def _apply_nft(self, iface: str) -> None:
        text = self._build_nft_script(iface)
        res = run(["nft", "-f", "-"], input_text=text, timeout=20)
        if res.returncode != 0:
            log.debug("Kural metni:\n%s", text)
            raise VodafoneError(res.stderr.strip() or "nft hatası")

    def _clear_nft(self) -> bool:
        # Tablo yoksa da hata vermeyen idempotent silme.
        script = (f"table inet {VODAFONE_TABLE}\n"
                  f"delete table inet {VODAFONE_TABLE}\n")
        res = run(["nft", "-f", "-"], input_text=script, timeout=10)
        if res.returncode != 0:
            log.error("TTL kuralları kaldırılamadı (nft %d): %s",
                      res.returncode, res.stderr.strip() or "bilinmeyen hata")
            return False
        return True

    def _counters_nft(self) -> tuple[int, int]:
        res = run(["nft", "-j", "list", "table", "inet", VODAFONE_TABLE],
                  timeout=10)
        if res.returncode != 0:
            return (0, 0)
        try:
            document = json.loads(res.stdout or "{}")
        except (TypeError, ValueError):
            return (0, 0)
        packets4 = packets6 = 0
        for item in document.get("nftables", []):
            rule = item.get("rule") if isinstance(item, dict) else None
            if not isinstance(rule, dict):
                continue
            packets = 0
            family = ""
            for expr in rule.get("expr", []):
                if not isinstance(expr, dict):
                    continue
                counter = expr.get("counter")
                if isinstance(counter, dict):
                    try:
                        packets = int(counter.get("packets", 0) or 0)
                    except (TypeError, ValueError):
                        packets = 0
                mangle = expr.get("mangle")
                if isinstance(mangle, dict):
                    payload = (mangle.get("key") or {}).get("payload") or {}
                    family = payload.get("protocol", "") or family
            if family == "ip":
                packets4 += packets
            elif family == "ip6":
                packets6 += packets
        return packets4, packets6

    # -- iptables yedeği -------------------------------------------------
    def _apply_iptables(self, iface: str) -> None:
        if which("iptables") is None:
            raise VodafoneError("iptables bulunamadı.")
        self._apply_iptables_family("iptables", iface,
                                    ["-m", "ttl", "--ttl-gt", str(self.guard),
                                     "-j", "TTL", "--ttl-set", str(self.ttl)])
        if which("ip6tables") is None:
            log.warning("ip6tables yok; IPv6 hop limit kuralı kurulamadı. "
                        "IPv6 kapatma seçeneğini açık bırakın.")
            return
        try:
            self._apply_iptables_family(
                "ip6tables", iface,
                ["-m", "hl", "--hl-gt", str(self.guard),
                 "-j", "HL", "--hl-set", str(self.ttl)])
        except VodafoneError as exc:
            # IPv4 kuralı duruyor; IPv6 sızıntısı IPv6'yı kapatma seçeneğiyle
            # zaten engelleniyor. Tüm işlemi düşürmek yerine uyarmak yeterli.
            log.warning("IPv6 hop limit kuralı kurulamadı (%s). IPv6 kapatma "
                        "seçeneğini açık bırakın, yoksa paylaşım fark edilir.",
                        exc)

    def _apply_iptables_family(self, cmd: str, iface: str,
                               match: list[str]) -> None:
        base = [cmd, "-w", "5", "-t", "mangle"]
        run([*base, "-N", VODAFONE_CHAIN], timeout=10)
        run([*base, "-F", VODAFONE_CHAIN], timeout=10)
        res = run([*base, "-A", VODAFONE_CHAIN, "-o", iface, *match], timeout=10)
        if res.returncode != 0:
            # Yalnızca başarısız olan aileyi geri al: IPv4 ile IPv6 ayrı
            # çekirdek tablolarıdır ve yalnızca zincir adını paylaşırlar.
            # Hepsini temizlemek, az önce kurulan IPv4 kuralını da silerdi.
            self._clear_iptables(only=cmd)
            raise VodafoneError(
                "Bu sistemde iptables TTL modülü yok; nftables kurulu bir "
                "çekirdek gerekiyor. Ayrıntı: "
                + (res.stderr.strip() or "bilinmeyen hata"))
        if run([*base, "-C", "POSTROUTING", "-j", VODAFONE_CHAIN],
               timeout=10).returncode != 0:
            run([*base, "-A", "POSTROUTING", "-j", VODAFONE_CHAIN], timeout=10)

    def _clear_iptables(self, only: str | None = None) -> bool:
        """Zinciri kaldır. ``only`` verilirse yalnızca o aile temizlenir."""
        ok = True
        for cmd in ((only,) if only else ("iptables", "ip6tables")):
            if which(cmd) is None:
                continue
            base = [cmd, "-w", "5", "-t", "mangle"]
            # Bağlantı kuralı birden çok kez eklenmiş olabilir; sonsuz döngüye
            # düşmemek için deneme sayısı sınırlıdır.
            for _ in range(10):
                if run([*base, "-C", "POSTROUTING", "-j", VODAFONE_CHAIN],
                       timeout=10).returncode != 0:
                    break
                if run([*base, "-D", "POSTROUTING", "-j", VODAFONE_CHAIN],
                       timeout=10).returncode != 0:
                    break
            run([*base, "-F", VODAFONE_CHAIN], timeout=10)
            run([*base, "-X", VODAFONE_CHAIN], timeout=10)
            # Bağlantı hâlâ duruyorsa kural çekirdekte çalışmaya devam eder.
            if run([*base, "-C", "POSTROUTING", "-j", VODAFONE_CHAIN],
                   timeout=10).returncode == 0:
                log.error("%s: TTL zinciri POSTROUTING'den kaldırılamadı", cmd)
                ok = False
        return ok

    def _counters_iptables(self, cmd: str) -> int:
        if which(cmd) is None:
            return 0
        res = run([cmd, "-w", "5", "-t", "mangle", "-L", VODAFONE_CHAIN,
                   "-n", "-v", "-x"], timeout=10)
        if res.returncode != 0:
            return 0
        total = 0
        for line in (res.stdout or "").splitlines():
            fields = line.split()
            # kural satırları "<paket> <bayt> <hedef> …" ile başlar
            if len(fields) >= 3 and fields[0].isdigit() and fields[1].isdigit():
                total += int(fields[0])
        return total

    # -- IPv6 ------------------------------------------------------------
    # Telefon tethering yaparken laptopa kendi global IPv6 adresini verir.
    # O zaman operatör aynı aboneden iki farklı IPv6 kaynağı görür; hop limit
    # ne olursa olsun paylaşım tek başına bundan anlaşılır.
    def _disable_ipv6(self, iface: str) -> None:
        path = _IPV6_SYSCTL.format(iface=iface)
        try:
            with open(path, "r", encoding="ascii") as handle:
                previous = handle.read().strip()
        except FileNotFoundError:
            log.debug("IPv6 çekirdekte kapalı (%s yok); adım atlandı", path)
            return
        except OSError as exc:
            log.warning("IPv6 ayarı okunamadı (%s): %s", path, exc)
            return
        try:
            with open(path, "w", encoding="ascii") as handle:
                handle.write("1\n")
        except OSError as exc:
            # TTL kısmı yine değerli; tüm işlemi düşürme.
            log.warning("%s arayüzünde IPv6 kapatılamadı: %s", iface, exc)
            return
        self._ipv6_previous = previous
        self._ipv6_iface = iface
        self._save_ipv6_state()
        log.info("%s arayüzünde IPv6 kapatıldı (eski değer: %s)",
                 iface, previous)

    def _restore_ipv6(self) -> None:
        self._load_ipv6_state()
        if self._ipv6_previous is None or not self._ipv6_iface:
            return
        path = _IPV6_SYSCTL.format(iface=self._ipv6_iface)
        try:
            with open(path, "w", encoding="ascii") as handle:
                handle.write(f"{self._ipv6_previous}\n")
            log.info("IPv6 ayarı geri alındı (%s = %s)",
                     self._ipv6_iface, self._ipv6_previous)
        except OSError as exc:
            log.warning("IPv6 ayarı geri alınamadı (%s): %s", path, exc)
        finally:
            self._ipv6_previous = None
            self._ipv6_iface = ""
            self._drop_ipv6_state()

    def _save_ipv6_state(self) -> None:
        try:
            os.makedirs(os.path.dirname(VODAFONE_STATE_FILE), exist_ok=True)
            with open(VODAFONE_STATE_FILE, "w", encoding="utf-8") as handle:
                json.dump({"interface": self._ipv6_iface,
                           "ipv6_previous": self._ipv6_previous}, handle)
        except OSError as exc:
            log.debug("IPv6 durumu yazılamadı: %s", exc)

    def _load_ipv6_state(self) -> None:
        """Servis çökmüşse eski IPv6 değerini dosyadan geri oku."""
        if self._ipv6_previous is not None:
            return
        try:
            with open(VODAFONE_STATE_FILE, "r", encoding="utf-8") as handle:
                data = json.load(handle)
        except (OSError, ValueError):
            return
        if not isinstance(data, dict):
            return
        previous = data.get("ipv6_previous")
        iface = data.get("interface")
        if previous in ("0", "1") and isinstance(iface, str) and iface:
            try:
                validate_interface(iface)
            except VodafoneError:
                self._drop_ipv6_state()
                return
            self._ipv6_previous = previous
            self._ipv6_iface = iface

    @staticmethod
    def _drop_ipv6_state() -> None:
        try:
            os.unlink(VODAFONE_STATE_FILE)
        except OSError:
            pass
