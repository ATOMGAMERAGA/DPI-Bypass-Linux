"""Ağ başına öğrenilmiş en iyi aday ve geçerlilik denetimi.

Kayıt yalnız "hangi adayı önce dene" bilgisidir; sistemde kalıcı ayar
bırakmaz. Ama eski bir kaydı bugünün ölçümü gibi göstermek de dürüst
değildir: kayıt, koşulları değiştiğinde geçersiz sayılır ve yeniden
doğrulanmadan "aktif kazanç" olarak gösterilmez.
"""

from __future__ import annotations

import json
import logging
import os
import time
from dataclasses import dataclass

log = logging.getLogger("dpibypass.latency.profiles")

SCHEMA_VERSION = 2

#: Kaydın yeniden doğrulanmadan güvenilebileceği azami yaş (saniye).
DEFAULT_MAX_AGE = 14 * 24 * 3600


@dataclass
class ProfileContext:
    """Kaydın hangi koşullarda alındığı. Biri değişirse kayıt geçersizdir."""

    interface: str = ""
    condition: str = ""
    targets: str = ""          # hedef kimliklerinin sıralı özeti
    kernel: str = ""
    driver: str = ""

    def to_dict(self) -> dict:
        return {"interface": self.interface, "condition": self.condition,
                "targets": self.targets, "kernel": self.kernel,
                "driver": self.driver}

    def matches(self, other: dict) -> tuple[bool, str]:
        if not isinstance(other, dict):
            return False, "kayıt bağlamı okunamadı"
        for key, label in (("interface", "arayüz"), ("condition", "ölçüm koşulu"),
                           ("targets", "hedef kümesi"), ("kernel", "çekirdek"),
                           ("driver", "sürücü")):
            recorded = str(other.get(key, ""))
            current = getattr(self, key)
            if recorded and current and recorded != current:
                return False, f"{label} değişti"
        return True, ""


class LatencyProfiles:
    """``NetworkFingerprint.key`` → doğrulanmış en iyi aday belleği."""

    MAX_ENTRIES = 40

    def __init__(self, path: str, max_age: float = DEFAULT_MAX_AGE) -> None:
        self.path = path
        self.max_age = float(max_age)
        self.data: dict = {"version": SCHEMA_VERSION, "networks": {}}
        self.load()

    def load(self) -> None:
        try:
            with open(self.path, "r", encoding="utf-8") as handle:
                loaded = json.load(handle)
            if not isinstance(loaded, dict) or not isinstance(
                    loaded.get("networks"), dict):
                return
            version = loaded.get("version")
            if version != SCHEMA_VERSION:
                # Şema değişti: eski kayıtlar bugünün ölçüm yöntemiyle
                # karşılaştırılamaz. Sessizce kullanmak yerine düşürülür.
                log.info("gecikme profili şeması değişti (%s → %s); kayıtlar "
                         "yeniden öğrenilecek", version, SCHEMA_VERSION)
                return
            self.data = {"version": SCHEMA_VERSION,
                         "networks": loaded["networks"]}
        except FileNotFoundError:
            pass
        except (OSError, ValueError) as exc:
            log.warning("gecikme profilleri okunamadı: %s", exc)

    def save(self) -> None:
        try:
            directory = os.path.dirname(self.path)
            if directory:
                os.makedirs(directory, mode=0o755, exist_ok=True)
            tmp = self.path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as handle:
                json.dump(self.data, handle, ensure_ascii=False)
                handle.write("\n")
            os.replace(tmp, self.path)
        except OSError as exc:
            log.debug("gecikme profilleri yazılamadı: %s", exc)

    def get(self, key: str) -> "dict | None":
        if not key:
            return None
        entry = self.data.get("networks", {}).get(key)
        return dict(entry) if isinstance(entry, dict) else None

    def usable(self, key: str, context: ProfileContext) -> tuple:
        """Kayıt bugün için hâlâ geçerli mi?

        Döner: ``(entry | None, neden)``. Geçersizse neden kullanıcıya
        gösterilebilecek bir cümledir.
        """
        entry = self.get(key)
        if entry is None:
            return None, ""
        age = time.time() - float(entry.get("updated", 0) or 0)
        if age > self.max_age:
            return None, f"kayıt eskidi ({int(age // 86400)} gün)"
        ok, why = context.matches(entry.get("context") or {})
        if not ok:
            return None, why
        return entry, ""

    def remember(self, key: str, candidate_key: str, label: str,
                 interface: str, gain: dict,
                 context: "ProfileContext | None" = None) -> None:
        if not key or not candidate_key:
            return
        networks = self.data.setdefault("networks", {})
        networks[key] = {
            "candidate": candidate_key,
            "label": label,
            "interface": interface,
            "gain": dict(gain),
            "context": (context or ProfileContext(interface=interface)).to_dict(),
            "updated": time.time(),
        }
        if len(networks) > self.MAX_ENTRIES:
            oldest = sorted(networks.items(),
                            key=lambda item: item[1].get("updated", 0))
            for old_key, _value in oldest[:len(networks) - self.MAX_ENTRIES]:
                networks.pop(old_key, None)
        self.save()

    def forget(self, key: str) -> None:
        if self.data.get("networks", {}).pop(key, None) is not None:
            self.save()
