"""Operatör (ISP) profilleri ve otomatik saptama.

Saptama üç kaynağı birleştirir:

1. **ASN**  Team Cymru'nun DNS tabanlı IP→ASN servisi, DoH üzerinden
   sorgulanır. Böylece dış bir HTTP API'ye ya da anahtara gerek kalmaz.
2. **Bağlantı türü**  Varsayılan rotanın çıktığı arayüz (wifi / ethernet /
   mobil) çekirdekten okunur.
3. **SSID**  Kablosuz ağın adı, hotspot ve FWA (Superbox / Redbox) ayrımı
   için kullanılır.
"""

from __future__ import annotations

import ipaddress
import logging
import os
import re
from dataclasses import dataclass

from . import tlsclient
from .resolver import shared as dns
from .util import run

log = logging.getLogger("dpibypass.isp")


@dataclass(frozen=True)
class IspProfile:
    id: str
    label: str                                   # arayüzde görünen ad
    keywords: tuple[str, ...] = ()               # AS adı içinde aranan sözcükler
    asns: tuple[int, ...] = ()                   # bilinen ASN ipuçları
    link: tuple[str, ...] = ()                   # wifi | ethernet | mobile
    ssid_hints: tuple[str, ...] = ()
    strategies: tuple[str, ...] = ()             # denenecek strateji sırası
    note: str = ""

    def to_dict(self) -> dict:
        return {"id": self.id, "label": self.label, "strategies": list(self.strategies),
                "note": self.note}


# Ekran görüntüsündeki liste, birebir aynı sırada.
PROFILES: tuple[IspProfile, ...] = (
    IspProfile(
        id="tt-mobile",
        label="Türk Telekom (Mobil)",
        keywords=("turk telekom", "turktelekom", "ttnet", "avea", "tt mobil"),
        asns=(9121, 47331, 16126, 34984),
        link=("mobile",),
        strategies=("disorder-snimid", "tlsrec-sni", "split-snimid",
                    "disoob-snimid", "multisplit", "fake-snimid"),
        note="Mobil şebekede SNI ve TLS kayıt denetimi birlikte uygulanır.",
    ),
    IspProfile(
        id="tt-home",
        label="Türk Telekom Evde İnternet",
        keywords=("turk telekom", "turktelekom", "ttnet"),
        asns=(9121, 47331),
        link=("ethernet", "wifi"),
        strategies=("tlsrec-sni", "split-snimid", "disorder-snimid",
                    "tlsrec-split-sni", "multisplit", "oob-snimid", "fake-snimid"),
        note="TTNet DSL/fiber: çoğunlukla SNI tabanlı RST enjeksiyonu.",
    ),
    IspProfile(
        id="tt-hotspot",
        label="Türk Telekom Hotspot",
        keywords=("turk telekom", "ttnet", "wifi"),
        asns=(9121, 47331),
        link=("wifi",),
        ssid_hints=("ttnet", "turktelekom", "türk telekom", "tt wifi", "ttwifi"),
        strategies=("disorder-snimid", "disoob-snimid", "tlsrec-sni",
                    "split-snimid", "multisplit", "fake-snimid"),
        note="Hotspot portalları ek olarak HTTP yönlendirmesi yapabilir.",
    ),
    IspProfile(
        id="redbox",
        label="Redbox (Türk Telekom)",
        keywords=("turk telekom", "ttnet", "redbox"),
        asns=(9121, 47331),
        link=("wifi", "ethernet"),
        ssid_hints=("redbox", "red box"),
        strategies=("disorder-snimid", "disorder-ttl6", "tlsrec-sni",
                    "split-snimid", "disoob-snimid", "fake-ttl8"),
        note="Sabit kablosuz (FWA) kutusu: yol uzunluğu farklı, TTL ayarı önemli.",
    ),
    IspProfile(
        id="turkcell-mobile",
        label="Turkcell (Mobil)",
        keywords=("turkcell", "turk cell"),
        asns=(16135, 20978),
        link=("mobile",),
        strategies=("disorder-snimid", "disorder-ttl2", "oob-snimid",
                    "tlsrec-sni", "split-snimid", "fake-snimid"),
        note="Turkcell mobil şebekesinde kısa yol; düşük TTL gerekir.",
    ),
    IspProfile(
        id="superonline",
        label="Turkcell Superonline",
        keywords=("superonline", "tellcom", "turkcell"),
        asns=(34984, 16135),
        link=("ethernet", "wifi"),
        strategies=("tlsrec-sni", "disorder-snimid", "split-snimid",
                    "tlsrec-split-sni", "oob-snimid", "fake-snimid"),
        note="Superonline fiber: TLS kayıt parçalama genelde yeterli.",
    ),
    IspProfile(
        id="superbox",
        label="Superbox (Turkcell FWA)",
        keywords=("turkcell", "superonline", "tellcom"),
        asns=(16135, 34984),
        link=("wifi", "ethernet"),
        ssid_hints=("superbox", "super box"),
        strategies=("disorder-snimid", "disorder-ttl6", "disoob-snimid",
                    "tlsrec-sni", "split-snimid", "fake-ttl8"),
        note="Superbox mobil çekirdek üzerinden geçer; mobil profile yakındır.",
    ),
    IspProfile(
        id="turkcell-hotspot",
        label="Turkcell Hotspot",
        keywords=("turkcell", "superonline", "tellcom"),
        asns=(16135, 34984),
        link=("wifi",),
        ssid_hints=("turkcell", "superonline wifi", "tcell"),
        strategies=("disorder-snimid", "disoob-snimid", "oob-snimid",
                    "tlsrec-sni", "split-snimid", "fake-snimid"),
    ),
    IspProfile(
        id="vodafone-mobile",
        label="Vodafone (Mobil)",
        keywords=("vodafone",),
        asns=(15897, 197328),
        link=("mobile",),
        strategies=("oob-snimid", "disoob-snimid", "disorder-snimid",
                    "tlsrec-sni", "split-snimid", "fake-snimid"),
        note="Vodafone mobilde bant dışı bayt yöntemi çoğunlukla en hızlısı.",
    ),
    IspProfile(
        id="vodafone-home",
        label="Vodafone Evde İnternet",
        keywords=("vodafone",),
        asns=(15897,),
        link=("ethernet", "wifi"),
        strategies=("tlsrec-sni", "oob-snimid", "split-snimid",
                    "disorder-snimid", "multisplit", "fake-snimid"),
    ),
    IspProfile(
        id="vodafone-hotspot",
        label="Vodafone Hotspot",
        keywords=("vodafone",),
        asns=(15897,),
        link=("wifi",),
        ssid_hints=("vodafone", "vodafonewifi", "vodafone wifi"),
        strategies=("oob-snimid", "disoob-snimid", "disorder-snimid",
                    "tlsrec-sni", "split-snimid"),
    ),
    IspProfile(
        id="turknet",
        label="TurkNet",
        keywords=("turknet", "turk net"),
        asns=(12735,),
        link=("ethernet", "wifi"),
        strategies=("tlsrec-sni", "split-snimid", "split-2",
                    "disorder-snimid", "multisplit", "oob-snimid"),
        note="TurkNet'te genelde yalnız DNS engeli vardır; DoH çoğu zaman yeter.",
    ),
    IspProfile(
        id="unknown",
        label="Diğer / Bilinmiyor",
        strategies=(),
        note="Tüm stratejiler sırayla denenir.",
    ),
)

BY_ID: dict[str, IspProfile] = {p.id: p for p in PROFILES}
UNKNOWN = BY_ID["unknown"]


def get(profile_id: str | None) -> IspProfile:
    return BY_ID.get(profile_id or "", UNKNOWN)


# --- bağlantı bilgisi -------------------------------------------------------

@dataclass
class LinkInfo:
    interface: str = ""
    link_type: str = ""      # wifi | ethernet | mobile | ""
    ssid: str = ""
    gateway: str = ""
    public_ip: str = ""
    asn: int = 0
    as_name: str = ""
    country: str = ""

    def to_dict(self) -> dict:
        return {
            "interface": self.interface,
            "link_type": self.link_type,
            "ssid": self.ssid,
            "gateway": self.gateway,
            "public_ip": self.public_ip,
            "asn": self.asn,
            "as_name": self.as_name,
            "country": self.country,
        }


def default_route() -> tuple[str, str]:
    """(arayüz, ağ geçidi) — varsayılan IPv4 rotasından."""
    try:
        with open("/proc/net/route", "r", encoding="ascii") as fh:
            for line in fh.readlines()[1:]:
                fields = line.split()
                if len(fields) > 2 and fields[1] == "00000000":
                    gw_hex = fields[2]
                    gw = ".".join(str(int(gw_hex[i:i + 2], 16))
                                  for i in (6, 4, 2, 0))
                    return fields[0], gw
    except OSError:
        pass
    return "", ""


def link_type_of(iface: str) -> str:
    if not iface:
        return ""
    if os.path.isdir(f"/sys/class/net/{iface}/wireless") or iface.startswith("wl"):
        return "wifi"
    uevent = f"/sys/class/net/{iface}/uevent"
    try:
        with open(uevent, "r", encoding="ascii", errors="replace") as fh:
            text = fh.read().lower()
        if "devtype=wwan" in text or "devtype=wlan" in text:
            return "mobile" if "wwan" in text else "wifi"
    except OSError:
        pass
    if re.match(r"^(wwan|ppp|wwp|usb|rmnet)", iface):
        return "mobile"
    if re.match(r"^(en|eth)", iface):
        return "ethernet"
    if iface.startswith(("tun", "tap", "wg")):
        return "vpn"
    return ""


def current_ssid(iface: str = "") -> str:
    """Bağlı olunan kablosuz ağın adı."""
    res = run(["nmcli", "-t", "-f", "active,ssid", "dev", "wifi"], timeout=5)
    if res.returncode == 0:
        for line in res.stdout.splitlines():
            if line.startswith("yes:"):
                return line.split(":", 1)[1].strip()
    if iface:
        res = run(["iw", "dev", iface, "link"], timeout=5)
        if res.returncode == 0:
            match = re.search(r"SSID:\s*(.+)", res.stdout)
            if match:
                return match.group(1).strip()
    res = run(["iwgetid", "-r"], timeout=5)
    if res.returncode == 0 and res.stdout.strip():
        return res.stdout.strip()
    return ""


async def public_ip() -> str:
    """Genel IP adresi (Cloudflare trace uç noktası, doğrudan IP ile)."""
    for ip, host in (("1.1.1.1", "one.one.one.one"),
                     ("1.0.0.1", "one.one.one.one"),
                     ("8.8.8.8", "dns.google")):
        try:
            status, body = await tlsclient.https_request(
                ip, host, "GET", "/cdn-cgi/trace", timeout=6
            )
            if status == 200:
                match = re.search(r"^ip=(.+)$", body.decode("utf-8", "replace"),
                                  re.MULTILINE)
                if match:
                    return match.group(1).strip()
        except Exception as exc:
            log.debug("genel IP alınamadı (%s): %s", ip, exc)
    return ""


async def asn_lookup(ip: str) -> tuple[int, str, str]:
    """Team Cymru üzerinden (ASN, AS adı, ülke)."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return 0, "", ""
    if addr.version == 4:
        query = ".".join(reversed(ip.split("."))) + ".origin.asn.cymru.com"
    else:
        nibbles = "".join(reversed(addr.exploded.replace(":", "")))
        query = ".".join(nibbles) + ".origin6.asn.cymru.com"
    try:
        texts = await dns.txt(query, timeout=6)
    except Exception as exc:
        log.debug("Cymru origin sorgusu başarısız: %s", exc)
        return 0, "", ""
    if not texts:
        return 0, "", ""
    parts = [p.strip() for p in texts[0].split("|")]
    try:
        asn = int(parts[0].split()[0])
    except (ValueError, IndexError):
        return 0, "", ""
    country = parts[2] if len(parts) > 2 else ""
    as_name = ""
    try:
        info = await dns.txt(f"AS{asn}.asn.cymru.com", timeout=6)
        if info:
            fields = [p.strip() for p in info[0].split("|")]
            as_name = fields[-1] if fields else ""
    except Exception:
        pass
    return asn, as_name, country


async def gather_link_info() -> LinkInfo:
    info = LinkInfo()
    info.interface, info.gateway = default_route()
    info.link_type = link_type_of(info.interface)
    if info.link_type == "wifi":
        info.ssid = current_ssid(info.interface)
    info.public_ip = await public_ip()
    if info.public_ip:
        info.asn, info.as_name, info.country = await asn_lookup(info.public_ip)
    return info


def match_profile(info: LinkInfo) -> tuple[IspProfile, float]:
    """Bağlantı bilgisine en uygun profili ve güven puanını döndür."""
    as_name = (info.as_name or "").lower()
    ssid = (info.ssid or "").lower()
    best = UNKNOWN
    best_score = 0.0

    for profile in PROFILES:
        if profile.id == "unknown":
            continue
        score = 0.0
        operator_hit = False

        if profile.keywords and any(k in as_name for k in profile.keywords):
            score += 3.0
            operator_hit = True
        if profile.asns and info.asn in profile.asns:
            score += 2.5
            operator_hit = True
        if not operator_hit:
            continue

        if profile.ssid_hints:
            if ssid and any(h in ssid for h in profile.ssid_hints):
                score += 3.0
            else:
                # SSID ipucu bekleyen profil (hotspot/FWA) eşleşmediyse geri çekil
                score -= 2.0
        if profile.link:
            if info.link_type in profile.link:
                score += 1.5
            else:
                score -= 1.5

        if score > best_score:
            best, best_score = profile, score

    if best_score <= 0:
        return UNKNOWN, 0.0
    confidence = min(1.0, best_score / 7.5)
    return best, confidence


async def detect() -> tuple[IspProfile, float, LinkInfo]:
    info = await gather_link_info()
    profile, confidence = match_profile(info)
    log.info(
        "Operatör saptaması: %s (güven %.0f%%) — AS%s %s, arayüz %s/%s%s",
        profile.label, confidence * 100, info.asn or "?", info.as_name or "?",
        info.interface or "?", info.link_type or "?",
        f", SSID {info.ssid}" if info.ssid else "",
    )
    return profile, confidence, info
