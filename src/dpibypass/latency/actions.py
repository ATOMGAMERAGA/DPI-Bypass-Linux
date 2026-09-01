"""Çalışma zamanı değişiklikleri: hazırlık, uygulama, kanıt ve geri alma.

Her mutasyon için değişmez sıra
-------------------------------
1. **Tarif önce yazılır.** Değişiklikten önce geri alma tarifi diske
   kaydedilir. Komut yarıda kalsa ya da servis çökse bile geri dönüş yolu
   hazırdır.
2. **Uygula.**
3. **Geri oku ve karşılaştır.** Dönüş kodunun 0 olması "uygulandı" demek
   değildir; sürücü isteği sessizce yok saymış olabilir. Hedef değere
   ulaşılmadıysa adım başarısız sayılır.
4. **İmzayı sakla.** Uygulamadan sonraki gerçek durum imzadır. Geri alırken
   sistem hâlâ o imzadaysa değişiklik bizimdir; farklıysa araya biri
   girmiştir ve ayarı ezmeyiz.

Arayüz kimliği
--------------
Snapshot yalnız arayüz *adını* değil ``ifindex``'i de taşır. ``eth0`` adı
yeniden kullanılabilir (USB adaptör çıkarılıp başkası takıldığında); eski
kaydı yeni bir aygıta uygulamak yanlış donanımı bozardı.
"""

from __future__ import annotations

import json
import logging
import re
import socket
from dataclasses import dataclass, field
from typing import Callable

from .qdisc import QdiscSlot, normalize
from .sqm import SqmState

log = logging.getLogger("dpibypass.latency.actions")

SNAPSHOT_VERSION = 2

_IFACE_RE = re.compile(r"^[A-Za-z0-9_.@-]{1,15}\Z")
_QDISC_ARG_RE = re.compile(r"^[A-Za-z0-9_.:+-]{1,32}\Z")

#: ``ethtool -C`` ile hem okunup hem yazılabilen, gecikmeyle doğrudan ilgili
#: parametreler. Listeyi dar tutmak geri almayı da kesinleştirir.
COALESCE_KEYS = ("adaptive-rx", "rx-usecs", "rx-frames")
_COALESCE_VALUE_RE = re.compile(r"^(?:on|off|[0-9]{1,9})\Z")

ACTION_KINDS = ("wifi-power-save", "eee", "coalesce", "qdisc", "sqm")


class ActionError(RuntimeError):
    pass


def _rc(result) -> int:
    return int(getattr(result, "returncode", 1) or 0)


def _out(result) -> str:
    return str(getattr(result, "stdout", "") or "")


def ifindex_of(interface: str) -> int:
    try:
        return socket.if_nametoindex(interface)
    except (OSError, ValueError):
        return 0


# --------------------------------------------------------------------------- #
# snapshot
# --------------------------------------------------------------------------- #
@dataclass
class ActionSnapshot:
    """Tek bir değişikliğin eksiksiz geri alma tarifi."""

    kind: str
    interface: str
    restore: dict = field(default_factory=dict)
    signature: str = ""
    label: str = ""
    #: Uygulamadan sonra beklenen durum; readback bununla karşılaştırılır.
    expected: str = ""
    ifindex: int = 0
    #: Geri alma tamamlandı mı? Idempotent rollback için.
    restored: bool = False

    def to_dict(self) -> dict:
        return {"kind": self.kind, "interface": self.interface,
                "restore": dict(self.restore), "signature": self.signature,
                "label": self.label, "expected": self.expected,
                "ifindex": int(self.ifindex), "restored": bool(self.restored)}

    @classmethod
    def from_dict(cls, data: dict) -> "ActionSnapshot":
        if not isinstance(data, dict):
            raise ValueError("geçersiz eylem snapshot'ı")
        kind = data.get("kind")
        iface = data.get("interface")
        restore = data.get("restore")
        signature = data.get("signature", "")
        label = data.get("label", "")
        expected = data.get("expected", "")
        if not isinstance(iface, str) or not _IFACE_RE.match(iface):
            raise ValueError("geçersiz snapshot arayüzü")
        if not isinstance(restore, dict):
            raise ValueError("geçersiz geri alma tarifi")
        for text, name in ((signature, "imza"), (expected, "beklenen durum")):
            if not isinstance(text, str) or len(text) > 8192:
                raise ValueError(f"geçersiz {name}")
        if not isinstance(label, str) or len(label) > 200:
            raise ValueError("geçersiz eylem etiketi")
        try:
            ifindex = int(data.get("ifindex", 0) or 0)
        except (TypeError, ValueError):
            raise ValueError("geçersiz ifindex")

        if kind in ("wifi-power-save", "eee"):
            if restore.get("value") not in ("on", "off"):
                raise ValueError(f"geçersiz {kind} snapshot'ı")
        elif kind == "coalesce":
            params = restore.get("params")
            if not isinstance(params, dict) or not params:
                raise ValueError("geçersiz coalesce snapshot'ı")
            for key, value in params.items():
                if key not in COALESCE_KEYS or not isinstance(value, str) \
                        or not _COALESCE_VALUE_RE.match(value):
                    raise ValueError("güvenli olmayan coalesce parametresi")
        elif kind == "qdisc":
            args = restore.get("args")
            parent = restore.get("parent", "root")
            if not isinstance(args, list) or not args:
                raise ValueError("güvenli olmayan qdisc snapshot'ı")
            if not all(isinstance(item, str) and _QDISC_ARG_RE.match(item)
                       for item in args):
                raise ValueError("geçersiz qdisc geri alma argümanı")
            if not isinstance(parent, str) or not re.match(
                    r"^(?:root|[0-9a-fA-F]{0,4}:[0-9a-fA-F]{0,4})\Z", parent):
                raise ValueError("geçersiz qdisc parent'ı")
        elif kind == "sqm":
            SqmState.from_dict(restore)      # doğrulama için
        else:
            raise ValueError(f"bilinmeyen eylem türü: {kind!r}")
        return cls(kind=kind, interface=iface, restore=dict(restore),
                   signature=signature, label=label, expected=expected,
                   ifindex=ifindex, restored=bool(data.get("restored")))


class SnapshotCorrupt(Exception):
    """Snapshot var ama okunamıyor/bozuk. "Snapshot yok" ile AYNI ŞEY DEĞİL.

    Bu ayrım kritiktir: snapshot yoksa sistem temizdir ve yeni değişiklik
    güvenlidir. Snapshot bozuksa sistemde geri alınmamış bir değişiklik
    olabilir ve durum bilinmiyordur — yeni mutasyon yapılmaz, dosya sessizce
    silinmez.
    """


@dataclass
class LatencySnapshot:
    """Bir arayüzde uygulanmış bütün eylemlerin sıralı geri alma tarifi."""

    interface: str
    link_type: str
    actions: list = field(default_factory=list)
    candidate: str = ""
    ifindex: int = 0
    version: int = SNAPSHOT_VERSION

    def to_dict(self) -> dict:
        return {
            "version": self.version,
            "interface": self.interface,
            "link_type": self.link_type,
            "candidate": self.candidate,
            "ifindex": int(self.ifindex),
            "actions": [action.to_dict() for action in self.actions],
        }

    @classmethod
    def from_dict(cls, data: dict) -> "LatencySnapshot":
        iface = data.get("interface")
        link_type = data.get("link_type")
        if not isinstance(iface, str) or not _IFACE_RE.match(iface):
            raise ValueError("geçersiz latency snapshot arayüzü")
        if link_type not in ("wifi", "ethernet", "mobile"):
            raise ValueError("geçersiz latency snapshot bağlantı türü")
        candidate = data.get("candidate", "")
        if not isinstance(candidate, str) or len(candidate) > 200:
            raise ValueError("geçersiz aday adı")
        try:
            ifindex = int(data.get("ifindex", 0) or 0)
        except (TypeError, ValueError):
            raise ValueError("geçersiz snapshot ifindex'i")
        raw_actions = data.get("actions")
        if raw_actions is None:
            return cls(interface=iface, link_type=link_type,
                       actions=_legacy_actions(data, iface),
                       candidate=candidate, ifindex=ifindex, version=1)
        if not isinstance(raw_actions, list):
            raise ValueError("geçersiz eylem listesi")
        actions = [ActionSnapshot.from_dict(item) for item in raw_actions]
        if any(action.interface != iface for action in actions):
            raise ValueError("snapshot arayüzleri tutarsız")
        try:
            version = int(data.get("version", SNAPSHOT_VERSION))
        except (TypeError, ValueError):
            version = SNAPSHOT_VERSION
        return cls(interface=iface, link_type=link_type, actions=actions,
                   candidate=candidate, ifindex=ifindex, version=version)

    def identity_matches(self, live_ifindex: int) -> bool:
        """Kayıttaki arayüz hâlâ aynı fiziksel aygıt mı?

        ``ifindex`` 0 ise (eski kayıt ya da okunamadı) ad üzerinden devam
        edilir; bu, yükseltme sonrası kalan kayıtların geri alınabilmesi için
        gereklidir.
        """
        if not self.ifindex or not live_ifindex:
            return True
        return self.ifindex == live_ifindex


def _legacy_actions(data: dict, iface: str) -> list:
    """1.2.0 biçimi: tek Wi-Fi + tek qdisc alanı."""
    actions = []
    qdisc = data.get("qdisc")
    if qdisc is not None:
        if not isinstance(qdisc, dict):
            raise ValueError("geçersiz qdisc snapshot'ı")
        actions.append(ActionSnapshot.from_dict({
            "kind": "qdisc", "interface": iface,
            "restore": {"args": qdisc.get("restore_args"), "parent": "root"},
            "signature": qdisc.get("applied_output", ""),
            "label": "fq_codel",
        }))
    power = data.get("wifi_power_save")
    if power is not None:
        if power not in ("on", "off"):
            raise ValueError("geçersiz Wi-Fi güç tasarrufu snapshot'ı")
        actions.append(ActionSnapshot.from_dict({
            "kind": "wifi-power-save", "interface": iface,
            "restore": {"value": power}, "signature": "",
            "label": "Wi-Fi güç tasarrufu",
        }))
    return actions


# --------------------------------------------------------------------------- #
# okuma yardımcıları
# --------------------------------------------------------------------------- #
def parse_coalesce(output: str) -> dict:
    """``ethtool -c`` çıktısından yalnız geri yazılabilir alanları al."""
    values: dict = {}
    for line in output.splitlines():
        line = line.strip()
        # TX alanı sürücüye göre "off", "on" ya da "n/a" olabilir; RX değeri
        # ondan bağımsız okunur. Gerçek çıktı: "Adaptive RX: off  TX: n/a"
        match = re.match(r"^Adaptive RX:\s*(on|off)\b", line, re.I)
        if match:
            values["adaptive-rx"] = match.group(1).lower()
            continue
        match = re.match(r"^(rx-usecs|rx-frames):\s*([0-9]{1,9})\Z", line)
        if match:
            values[match.group(1)] = match.group(2)
    if "adaptive-rx" not in values or "rx-usecs" not in values:
        return {}
    return values


def coalesce_candidates(current: dict) -> list:
    """Sürücünün gerçekten destekleyebileceği, anlamlı coalescing adayları.

    Tek bir agresif ``0`` seçeneği dayatılmaz: sıfır coalescing her durumda
    en iyi değildir. Küçük paket gecikmesi kazancı ile interrupt/CPU maliyeti
    birlikte değerlendirilmeli; bu yüzden birkaç nokta denenir ve kazananı
    ölçüm seçer.
    """
    try:
        rx_usecs = int(current.get("rx-usecs", "0"))
    except (TypeError, ValueError):
        return []
    wanted = []
    for value in (0, 8, max(1, rx_usecs // 4), max(1, rx_usecs // 2)):
        if 0 <= value < rx_usecs and value not in wanted:
            wanted.append(value)
    if current.get("adaptive-rx") == "on" and rx_usecs == 0:
        # Adaptif kip açıkken rx-usecs 0 görünse bile sabitlemek anlamlı.
        wanted.append(0)
    result = []
    for value in wanted[:3]:
        params = {"adaptive-rx": "off", "rx-usecs": str(value)}
        result.append(params)
    return result


# --------------------------------------------------------------------------- #
# uygulayıcı
# --------------------------------------------------------------------------- #
class ActionExecutor:
    """Eylemleri uygular, geri okur ve geri alır. Tamamen senkrondur.

    Motor bu çağrıları bir iş parçacığına devreder ve **iptal etmez**:
    yarıda kesilmiş bir mutasyonun gerçek durumu bilinemez, o yüzden
    mutasyon bitmeden geri alma başlatılmaz.
    """

    def __init__(self, runner: Callable, which_fn: Callable,
                 timeout: int = 8) -> None:
        self.runner = runner
        self.which = which_fn
        self.timeout = timeout
        #: Geri alma sırasında dışarıdan değişiklik görülürse buraya yazılır.
        self.external_change = ""

    def _run(self, cmd: list, timeout: "int | None" = None):
        return self.runner(cmd, timeout=timeout or self.timeout)

    # -- okuma -------------------------------------------------------------- #
    def read_wifi_power_save(self, iface: str) -> "str | None":
        if self.which("iw") is None:
            return None
        result = self._run(["iw", "dev", iface, "get", "power_save"])
        if _rc(result) != 0:
            return None
        match = re.search(r"Power save:\s*(on|off)", _out(result), re.I)
        return match.group(1).lower() if match else None

    def read_eee(self, iface: str) -> "str | None":
        if self.which("ethtool") is None:
            return None
        result = self._run(["ethtool", "--show-eee", iface])
        if _rc(result) != 0:
            return None
        match = re.search(r"EEE status:\s*(\S+)", _out(result), re.I)
        if match is None:
            return None
        state = match.group(1).lower()
        if state.startswith("enabled"):
            return "enabled"
        if state.startswith("disabled"):
            return "disabled"
        return None

    def read_coalesce(self, iface: str) -> dict:
        if self.which("ethtool") is None:
            return {}
        result = self._run(["ethtool", "-c", iface])
        if _rc(result) != 0:
            return {}
        return parse_coalesce(_out(result))

    def coalesce_writable(self, iface: str, current: dict) -> bool:
        """Mevcut değerleri geri yazarak (no-op) yazılabilirliği kanıtla."""
        if not current:
            return False
        cmd = ["ethtool", "-C", iface]
        for key in COALESCE_KEYS:
            if key in current:
                cmd.extend([key, str(current[key])])
        if len(cmd) <= 3:
            return False
        result = self._run(cmd)
        if _rc(result) != 0:
            return False
        return self.read_coalesce(iface) == current

    def read_qdisc(self, iface: str) -> str:
        if self.which("tc") is None:
            return ""
        result = self._run(["tc", "qdisc", "show", "dev", iface])
        return normalize(_out(result)) if _rc(result) == 0 else ""

    # -- imza --------------------------------------------------------------- #
    def signature(self, kind: str, iface: str) -> str:
        if kind in ("qdisc", "sqm"):
            return self.read_qdisc(iface)
        if kind == "coalesce":
            return json.dumps(self.read_coalesce(iface), sort_keys=True)
        if kind == "wifi-power-save":
            return self.read_wifi_power_save(iface) or ""
        if kind == "eee":
            return self.read_eee(iface) or ""
        return ""

    # -- uygulama ----------------------------------------------------------- #
    def apply_wifi_power_save(self, iface: str, value: str) -> None:
        if self.which("iw") is None:
            raise ActionError("iw bulunamadı")
        result = self._run(["iw", "dev", iface, "set", "power_save", value])
        if _rc(result) != 0:
            raise ActionError("Wi-Fi güç tasarrufu ayarı uygulanamadı")
        # Dönüş kodu 0 yetmez: NetworkManager ya da güç yönetimi servisi
        # ayarı hemen geri değiştirmiş olabilir.
        live = self.read_wifi_power_save(iface)
        if live != value:
            raise ActionError(
                f"Wi-Fi güç tasarrufu {value} yapılamadı (okunan: {live or '?'}); "
                f"sürücü ya da güç yönetimi servisi ayarı geri değiştiriyor")

    def apply_eee(self, iface: str, value: str) -> None:
        if self.which("ethtool") is None:
            raise ActionError("ethtool bulunamadı")
        result = self._run(["ethtool", "--set-eee", iface, "eee", value])
        if _rc(result) != 0:
            raise ActionError("Sürücü EEE ayarını değiştirmeyi desteklemiyor")
        expected = "enabled" if value == "on" else "disabled"
        live = self.read_eee(iface)
        if live != expected:
            raise ActionError(
                f"EEE {value} yapılamadı (okunan: {live or '?'})")

    def apply_coalesce(self, iface: str, params: dict) -> None:
        if self.which("ethtool") is None:
            raise ActionError("ethtool bulunamadı")
        cmd = ["ethtool", "-C", iface]
        for key in COALESCE_KEYS:
            if key in params:
                cmd.extend([key, str(params[key])])
        if len(cmd) <= 3:
            raise ActionError("uygulanacak coalescing parametresi yok")
        result = self._run(cmd)
        if _rc(result) != 0:
            raise ActionError("Sürücü interrupt coalescing ayarını desteklemiyor")
        live = self.read_coalesce(iface)
        for key, value in params.items():
            if live.get(key) != str(value):
                raise ActionError(
                    f"coalescing {key}={value} yazılamadı (okunan: "
                    f"{live.get(key, '?')})")

    def apply_qdisc(self, iface: str, slot: QdiscSlot, target: str) -> None:
        if self.which("tc") is None:
            raise ActionError("tc bulunamadı")
        location = slot.location()
        result = self._run(["tc", "qdisc", "replace", "dev", iface]
                           + location + [target])
        if _rc(result) != 0:
            raise ActionError(f"{target} uygulanamadı")
        live = self.read_qdisc(iface)
        if not self._qdisc_present(live, target, slot):
            raise ActionError(f"uygulanan {target} doğrulanamadı")

    @staticmethod
    def _qdisc_present(output: str, kind: str, slot: QdiscSlot) -> bool:
        for line in output.splitlines():
            if not line.startswith(f"qdisc {kind} "):
                continue
            if slot.parent == "root":
                if " root" in line:
                    return True
            elif f"parent {slot.parent}" in line:
                return True
        return False

    # -- geri alma ---------------------------------------------------------- #
    def restore(self, action: ActionSnapshot,
                sqm_manager: "object | None" = None) -> bool:
        """Tek bir eylemi geri al. Idempotenttir."""
        if action.restored:
            return True
        iface = action.interface
        if action.ifindex and ifindex_of(iface) not in (0, action.ifindex):
            log.error("%s artık farklı bir aygıt (ifindex %s ≠ %s); eski kayıt "
                      "uygulanmadı", iface, ifindex_of(iface), action.ifindex)
            return False

        if action.signature:
            live = self.signature(action.kind, iface)
            if live and live != action.signature:
                log.warning("%s %s ayarı dışarıdan değiştirildi; kullanıcı "
                            "ayarı korunuyor", iface, action.kind)
                self.external_change = (
                    f"{iface} {_kind_label(action.kind)} ayarı dışarıdan "
                    f"değiştirildi; kullanıcı ayarı korundu")
                action.restored = True
                return True

        try:
            if action.kind == "wifi-power-save":
                self.apply_wifi_power_save(iface, action.restore["value"])
            elif action.kind == "eee":
                self.apply_eee(iface, action.restore["value"])
            elif action.kind == "coalesce":
                self.apply_coalesce(iface, action.restore["params"])
            elif action.kind == "qdisc":
                if self.which("tc") is None:
                    raise ActionError("tc bulunamadı")
                parent = action.restore.get("parent", "root")
                location = (["root"] if parent == "root"
                            else ["parent", parent])
                result = self._run(["tc", "qdisc", "replace", "dev", iface]
                                   + location + list(action.restore["args"]))
                if _rc(result) != 0:
                    raise ActionError("qdisc geri alınamadı")
            elif action.kind == "sqm":
                if sqm_manager is None:
                    raise ActionError("SQM yöneticisi yok")
                state = SqmState.from_dict(action.restore)
                if not sqm_manager.rollback(state):   # type: ignore[attr-defined]
                    raise ActionError("SQM geri alınamadı")
            else:
                raise ActionError(f"bilinmeyen eylem: {action.kind}")
        except (ActionError, KeyError, ValueError) as exc:
            log.error("%s %s geri alınamadı: %s", iface, action.kind, exc)
            return False
        action.restored = True
        return True


def _kind_label(kind: str) -> str:
    return {"wifi-power-save": "Wi-Fi güç tasarrufu", "eee": "EEE",
            "coalesce": "coalescing", "qdisc": "kuyruk disiplini",
            "sqm": "SQM"}.get(kind, kind)
