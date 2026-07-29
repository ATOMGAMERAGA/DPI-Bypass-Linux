"""Yapılandırma ve öğrenilen ağ durumu."""

from __future__ import annotations

import json
import logging
import os
import time
from typing import Any

from .constants import (CONFIG_DIR, CONFIG_FILE, DEFAULT_BLOCKED_DOMAINS,
                        STATE_DIR, STATE_FILE, VODAFONE_MAX_NETWORKS,
                        VODAFONE_TTL_VALUE)

log = logging.getLogger("dpibypass.config")

DEFAULTS: dict[str, Any] = {
    "enabled": True,
    "mode": "smart",              # smart | all
    "isp": "auto",                # auto | profil kimliği
    "strategy": "auto",           # auto | strateji adı
    "dns_provider": "cloudflare", # cloudflare | google | quad9
    "dns_intercept": True,
    "block_quic": True,
    "auto_switch": True,          # ağ değişince yeniden ara
    "auto_discover": True,        # yeni engelli siteleri kendiliğinden bul
    "recheck_interval": 1800,     # saniye; 0 = kapalı
    "extra_domains": [],
    "disabled_domains": [],
    "gui_autostart": True,
    "verbose": False,
    # --- Vodafone sınırsız kipi ---------------------------------------------
    "vodafone_mode": False,             # ana anahtar
    "vodafone_networks": [],            # [{"key","name","interface"}, ...]
    "vodafone_ttl": VODAFONE_TTL_VALUE, # ileri düzey; normalde değiştirilmez
    "vodafone_disable_ipv6": True,      # tethering arayüzünde IPv6'yı kapat
}


class Config:
    def __init__(self, path: str = CONFIG_FILE) -> None:
        self.path = path
        self.data: dict[str, Any] = dict(DEFAULTS)
        self.load()

    def load(self) -> None:
        try:
            with open(self.path, "r", encoding="utf-8") as fh:
                loaded = json.load(fh)
            if isinstance(loaded, dict):
                for key, value in loaded.items():
                    if key in DEFAULTS:
                        self.data[key] = value
        except FileNotFoundError:
            pass
        except (OSError, json.JSONDecodeError) as exc:
            log.warning("yapılandırma okunamadı (%s), varsayılanlar kullanılıyor", exc)

    def save(self) -> bool:
        try:
            os.makedirs(os.path.dirname(self.path) or CONFIG_DIR, exist_ok=True)
            tmp = self.path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(self.data, fh, indent=2, ensure_ascii=False)
                fh.write("\n")
            os.replace(tmp, self.path)
            return True
        except OSError as exc:
            log.error("yapılandırma yazılamadı: %s", exc)
            return False

    def update(self, values: dict[str, Any]) -> list[str]:
        """Bilinen anahtarları güncelle; değişenlerin listesini döndür."""
        changed = []
        for key, value in values.items():
            if key in DEFAULTS and self.data.get(key) != value:
                self.data[key] = value
                changed.append(key)
        if changed:
            self.save()
        return changed

    def __getitem__(self, key: str) -> Any:
        return self.data.get(key, DEFAULTS.get(key))

    def get(self, key: str, default: Any = None) -> Any:
        return self.data.get(key, DEFAULTS.get(key, default))

    def domains(self) -> list[str]:
        """Yönlendirilecek alan adlarının nihai listesi."""
        disabled = {d.lower().strip(".") for d in self.get("disabled_domains", [])}
        extra = [d.strip() for d in self.get("extra_domains", []) if d.strip()]
        merged = list(DEFAULT_BLOCKED_DOMAINS) + extra
        seen: set[str] = set()
        out = []
        for dom in merged:
            key = dom.lower().strip(".")
            if key in disabled or key in seen:
                continue
            seen.add(key)
            out.append(key)
        return out

    # -- Vodafone kipinin etkin olduğu ağlar --------------------------------
    # Mod yalnızca kullanıcının açtığı ağlarda çalışır: ev Wi-Fi'ına geçilince
    # kendiliğinden devre dışı kalır, telefona dönülünce geri gelir.
    def vodafone_networks(self) -> list[dict]:
        """Kayıtlı ağların kopyası (bozuk girdiler elenir)."""
        out: list[dict] = []
        for item in self.get("vodafone_networks", []) or []:
            if isinstance(item, dict) and item.get("key"):
                out.append(dict(item))
        return out

    def vodafone_has_network(self, key: str) -> bool:
        if not key:
            return False
        return any(net.get("key") == key for net in self.vodafone_networks())

    def vodafone_add_network(self, key: str, name: str, iface: str) -> None:
        """Ağı kaydet. Zaten varsa bilgileri tazelenir, sona alınır."""
        if not key:
            return
        nets = [net for net in self.vodafone_networks() if net.get("key") != key]
        nets.append({"key": key, "name": name, "interface": iface,
                     "added": time.time()})
        del nets[:-VODAFONE_MAX_NETWORKS]     # en eskiyi düş
        self.update({"vodafone_networks": nets})

    def vodafone_remove_network(self, key: str) -> None:
        current = self.vodafone_networks()
        nets = [net for net in current if net.get("key") != key]
        if len(nets) != len(current):
            self.update({"vodafone_networks": nets})


class State:
    """Ağ başına öğrenilen strateji belleği."""

    def __init__(self, path: str = STATE_FILE) -> None:
        self.path = path
        self.data: dict[str, Any] = {"networks": {}, "learned_domains": []}
        self.load()

    def load(self) -> None:
        try:
            with open(self.path, "r", encoding="utf-8") as fh:
                loaded = json.load(fh)
            if isinstance(loaded, dict):
                self.data.setdefault("networks", {})
                self.data.update(loaded)
        except FileNotFoundError:
            pass
        except (OSError, json.JSONDecodeError):
            pass

    def save(self) -> None:
        try:
            os.makedirs(STATE_DIR, exist_ok=True)
            tmp = self.path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(self.data, fh, indent=2, ensure_ascii=False)
            os.replace(tmp, self.path)
        except OSError as exc:
            log.debug("durum yazılamadı: %s", exc)

    # -- ağ belleği --------------------------------------------------------
    def remember(self, key: str, name: str, isp: str, strategy: str) -> None:
        nets = self.data.setdefault("networks", {})
        entry = nets.setdefault(key, {"successes": 0})
        entry.update({
            "name": name,
            "isp": isp,
            "strategy": strategy,
            "updated": time.time(),
        })
        entry["successes"] = entry.get("successes", 0) + 1
        # en fazla 40 ağ sakla
        if len(nets) > 40:
            oldest = sorted(nets.items(), key=lambda kv: kv[1].get("updated", 0))
            for old_key, _ in oldest[:len(nets) - 40]:
                nets.pop(old_key, None)
        self.save()

    def recall(self, key: str) -> dict | None:
        return self.data.get("networks", {}).get(key)

    def forget(self, key: str) -> None:
        if self.data.get("networks", {}).pop(key, None) is not None:
            self.save()

    def networks(self) -> dict:
        return dict(self.data.get("networks", {}))

    # -- öğrenilen engelli alan adları -------------------------------------
    def learn_domain(self, domain: str) -> bool:
        domain = domain.lower().strip(".")
        if not domain or "." not in domain:
            return False
        learned = self.data.setdefault("learned_domains", [])
        if domain in learned:
            return False
        learned.append(domain)
        del learned[:-200]
        self.save()
        return True

    def learned_domains(self) -> list[str]:
        return list(self.data.get("learned_domains", []))
