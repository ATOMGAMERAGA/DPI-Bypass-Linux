"""İsteğe bağlı gerçek SQM: bant genişliği şekillendirme + AQM.

Neden ayrı bir kip
------------------
Eski motor ``cake``'i **bandwidth vermeden** kuruyordu. CAKE'in varsayılanı
``unlimited``'dır: shaper devre dışıdır, yalnız AQM çalışır. Bu, darboğaz
modemde/ISS'te olduğunda kuyruğu kontrol etmez — yani "bufferbloat çözüldü"
denemez. Gerçek kazanç için kuyruğun **bizim tarafımıza** çekilmesi, yani
hattın gerçek kapasitesinin biraz altında şekillendirme yapılması gerekir.

Bunun bir bedeli vardır: throughput'tan feragat. Bu yüzden burada iki
davranış kesin olarak ayrılır:

* **Güvenli otomatik kip** (varsayılan): kullanıcının bant genişliğine gizli
  limit koymaz. SQM burada devreye girmez.
* **Yük altında düşük gecikme kipi** (opt-in, Beta): kullanıcının onayı ve
  doğrulanmış bir kapasite değeriyle gerçek shaping uygular. Hız-gecikme
  takası görünürdür.

Sahiplik
--------
Bu modül **yalnız kendi oluşturduğu** kaynakları yönetir: kendi IFB aygıtı
(``ifb-dpib``), kendi kök handle'ı (``4470:``) ve kendi filter önceliği
(``prio 4470``). Var olan ingress/clsact yapılandırması korunur; böyle bir
yapı varsa ingress şekillendirme yapılmaz ve durum açıkça "yalnız upload"
olarak raporlanır. Toplu ``tc qdisc del``, ``nft flush`` benzeri işlemler
yoktur.

Konum uyarısı
-------------
Dizüstü bilgisayardaki shaping yalnız **bu makinenin** trafiğini kontrol
eder. Modem/ISS kuyrukları ve evdeki diğer cihazların trafiği yönetilmez;
gerçek çözüm çoğu zaman router tarafındaki SQM'dir. Bu araç router'a
bağlanmaz, ayarını değiştirmez.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Callable

log = logging.getLogger("dpibypass.latency.sqm")

#: Bu uygulamaya ait, sınırlı ve tanınabilir kimlikler.
IFB_DEVICE = "ifb-dpib"
EGRESS_HANDLE = "4470:"
INGRESS_HANDLE = "ffff:"
FILTER_PRIO = "4470"

#: Denenen shaping oranları. Tek bir sabit yüzde dayatılmaz: izin verilen
#: throughput fedakârlığı içinde birkaç nokta karşılaştırılır ve
#: latency/throughput dengesindeki en iyisi seçilir.
DEFAULT_RATIOS = (0.95, 0.90, 0.85)

#: Alt/üst sınırlar. Çok düşük bir oran bağlantıyı kullanılmaz yapar.
MIN_RATIO = 0.70
MAX_RATIO = 0.98
MIN_KBIT = 256          # 256 kbit/s altında shaping anlamsız ve riskli
MAX_KBIT = 10_000_000   # 10 Gbit/s

#: Varsayılan olarak throughput'tan feragat sınırı (yüzde). Bunun ötesinde
#: gecikme kazancı olsa bile aday reddedilir.
DEFAULT_MAX_THROUGHPUT_LOSS = 15.0


class SqmError(RuntimeError):
    pass


def _rc(result) -> int:
    return int(getattr(result, "returncode", 1) or 0)


def _out(result) -> str:
    return str(getattr(result, "stdout", "") or "")


def clamp_rate(kbit: object) -> int:
    """Kullanıcı girdisini güvenli aralığa oturt; geçersizse hata ver."""
    try:
        value = int(float(kbit))  # type: ignore[arg-type]
    except (TypeError, ValueError):
        raise SqmError("bant genişliği sayısal olmalı (kbit/s)")
    if value < MIN_KBIT or value > MAX_KBIT:
        raise SqmError(f"bant genişliği {MIN_KBIT}-{MAX_KBIT} kbit/s "
                       f"aralığında olmalı (verilen: {value})")
    return value


def shaped_rate(capacity_kbit: int, ratio: float) -> int:
    ratio = max(MIN_RATIO, min(MAX_RATIO, float(ratio)))
    return max(MIN_KBIT, int(capacity_kbit * ratio))


@dataclass
class SqmCapacity:
    """Hattın kapasitesi ve bu bilginin **nereden geldiği**.

    ``source`` kararın güvenilirliğini belirler:

    * ``user`` — kullanıcı açıkça girdi (en güvenilir).
    * ``measured`` — izinli yük testiyle ölçüldü.
    * ``unknown`` — bilinmiyor. Bu durumda shaping YAPILMAZ; PHY link hızı
      (Ethernet 1000 Mbit, Wi-Fi anlık oranı) internet kapasitesi sayılmaz
      ve keyfî bir 10/100 Mbit değeri uydurulmaz.
    """

    egress_kbit: int = 0
    ingress_kbit: int = 0
    source: str = "unknown"
    measured_at: float = 0.0
    note: str = ""

    @property
    def usable(self) -> bool:
        return self.source in ("user", "measured") and self.egress_kbit > 0

    def to_dict(self) -> dict:
        return {"egress_kbit": self.egress_kbit,
                "ingress_kbit": self.ingress_kbit, "source": self.source,
                "measured_at": self.measured_at, "note": self.note}


@dataclass
class SqmState:
    """Uygulanmış SQM'in tam geri alma tarifi."""

    interface: str = ""
    engine: str = ""              # "cake" | "htb+fq_codel"
    egress_kbit: int = 0
    ingress_kbit: int = 0
    ratio: float = 0.0
    egress_applied: bool = False
    ingress_applied: bool = False
    ifb_created: bool = False
    ingress_qdisc_created: bool = False
    filter_added: bool = False
    #: Egress kökünün değişiklikten önceki geri alma tarifi.
    egress_restore: list = field(default_factory=list)
    notes: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "interface": self.interface, "engine": self.engine,
            "egress_kbit": self.egress_kbit, "ingress_kbit": self.ingress_kbit,
            "ratio": round(self.ratio, 3),
            "egress_applied": self.egress_applied,
            "ingress_applied": self.ingress_applied,
            "ifb_created": self.ifb_created,
            "ingress_qdisc_created": self.ingress_qdisc_created,
            "filter_added": self.filter_added,
            "egress_restore": list(self.egress_restore),
            "notes": list(self.notes),
        }

    @classmethod
    def from_dict(cls, data: dict) -> "SqmState":
        if not isinstance(data, dict):
            raise ValueError("geçersiz SQM durumu")
        restore = data.get("egress_restore") or []
        if not isinstance(restore, list) or not all(
                isinstance(item, str) and re.match(r"^[A-Za-z0-9_.:+-]{1,32}\Z", item)
                for item in restore):
            raise ValueError("güvenli olmayan SQM geri alma tarifi")
        engine = data.get("engine", "")
        if engine not in ("", "cake", "htb+fq_codel"):
            raise ValueError("bilinmeyen SQM motoru")
        state = cls(interface=str(data.get("interface", ""))[:16], engine=engine,
                    egress_restore=list(restore))
        for key in ("egress_kbit", "ingress_kbit"):
            try:
                setattr(state, key, int(data.get(key, 0) or 0))
            except (TypeError, ValueError):
                raise ValueError("geçersiz SQM bant genişliği")
        for key in ("egress_applied", "ingress_applied", "ifb_created",
                    "ingress_qdisc_created", "filter_added"):
            setattr(state, key, bool(data.get(key)))
        try:
            state.ratio = float(data.get("ratio", 0.0) or 0.0)
        except (TypeError, ValueError):
            state.ratio = 0.0
        notes = data.get("notes")
        state.notes = [str(item)[:200] for item in notes] \
            if isinstance(notes, list) else []
        return state


class SqmManager:
    """CAKE (ya da HTB+fq_codel) ile egress ve — mümkünse — ingress shaping."""

    def __init__(self, runner: Callable, which_fn: Callable,
                 timeout: int = 10) -> None:
        self.runner = runner
        self.which = which_fn
        self.timeout = timeout

    def _run(self, cmd: list):
        return self.runner(cmd, timeout=self.timeout)

    # -- yetenek keşfi ----------------------------------------------------- #
    def cake_available(self, cake_module_present: bool) -> bool:
        return bool(cake_module_present) and self.which("tc") is not None

    def ifb_available(self) -> bool:
        """IFB gerçekten kurulabiliyor mu? Modül adı görmek yetmez."""
        if self.which("ip") is None:
            return False
        result = self._run(["ip", "link", "show", "type", "ifb"])
        # rc 0 ise tür destekleniyor (liste boş olabilir).
        return _rc(result) == 0

    def ingress_occupied(self, interface: str) -> bool:
        """Arayüzde zaten bir ingress/clsact yapılandırması var mı?

        Varsa ona **dokunmayız**: kullanıcının ya da başka bir aracın
        (SQM scripti, container runtime, VPN) kurduğu filtreleri
        koruyoruz ve yalnız upload şekillendiriyoruz.
        """
        result = self._run(["tc", "qdisc", "show", "dev", interface,
                            "ingress"])
        if _rc(result) != 0:
            return False
        text = " ".join(_out(result).split())
        return bool(text) and ("ingress" in text or "clsact" in text)

    # -- uygulama ---------------------------------------------------------- #
    def apply(self, interface: str, capacity: SqmCapacity, ratio: float,
              egress_restore: list, engine: str = "cake",
              want_ingress: bool = True) -> SqmState:
        """Shaping'i uygula. Hata durumunda uygulanmış her adım geri alınır."""
        if not capacity.usable:
            raise SqmError("bant genişliği bilinmiyor; shaping uygulanmaz")
        if self.which("tc") is None:
            raise SqmError("tc bulunamadı")
        egress_kbit = shaped_rate(clamp_rate(capacity.egress_kbit), ratio)
        state = SqmState(interface=interface, engine=engine,
                         egress_kbit=egress_kbit, ratio=ratio,
                         egress_restore=list(egress_restore))
        try:
            self._apply_egress(interface, state)
            if want_ingress and capacity.ingress_kbit > 0:
                self._apply_ingress(interface, state,
                                    shaped_rate(clamp_rate(capacity.ingress_kbit),
                                                ratio))
            elif want_ingress:
                state.notes.append(
                    "İndirme kapasitesi bilinmiyor; yalnız upload şekillendirildi")
        except Exception:
            self.rollback(state)
            raise
        return state

    def _cake_args(self, kbit: int, ingress: bool = False) -> list:
        # ``besteffort``: bütün akışlara adil davran. DSCP'ye göre sınıf
        # ayrımı yapmıyoruz; ICMP'ye ya da "tüm UDP"ye özel öncelik vermek
        # benchmark'ı güzelleştirir, gerçek oyun trafiğini iyileştirmez.
        # ``rtt`` bilinçli olarak ayarlanmaz: CAKE'in rtt parametresi AQM
        # hedefidir, internet ping'ini o değere sabitlemez.
        args = ["cake", "bandwidth", f"{kbit}kbit", "besteffort"]
        if ingress:
            args.append("ingress")
        return args

    def _apply_egress(self, interface: str, state: SqmState) -> None:
        if state.engine == "cake":
            args = self._cake_args(state.egress_kbit)
            result = self._run(["tc", "qdisc", "replace", "dev", interface,
                                "root", "handle", EGRESS_HANDLE] + args)
            if _rc(result) != 0:
                raise SqmError("CAKE egress shaping uygulanamadı")
        else:
            # CAKE yoksa: shaper + fq_codel. Shaper'sız fq_codel bununla
            # aynı özellik DEĞİLDİR ve öyle sunulmaz.
            result = self._run(["tc", "qdisc", "replace", "dev", interface,
                                "root", "handle", EGRESS_HANDLE, "htb",
                                "default", "10"])
            if _rc(result) != 0:
                raise SqmError("HTB shaper kurulamadı")
            state.egress_applied = True
            result = self._run([
                "tc", "class", "replace", "dev", interface, "parent",
                EGRESS_HANDLE, "classid", EGRESS_HANDLE + "10", "htb",
                "rate", f"{state.egress_kbit}kbit",
                "ceil", f"{state.egress_kbit}kbit"])
            if _rc(result) != 0:
                raise SqmError("HTB sınıfı kurulamadı")
            result = self._run([
                "tc", "qdisc", "replace", "dev", interface, "parent",
                EGRESS_HANDLE + "10", "fq_codel"])
            if _rc(result) != 0:
                raise SqmError("fq_codel yaprağı kurulamadı")
        state.egress_applied = True
        if not self.verify_egress(interface, state):
            raise SqmError("uygulanan egress shaping doğrulanamadı")

    def verify_egress(self, interface: str, state: SqmState) -> bool:
        """Komutun 0 dönmesi yetmez: değer gerçekten yazıldı mı?"""
        result = self._run(["tc", "qdisc", "show", "dev", interface])
        if _rc(result) != 0:
            return False
        text = " ".join(_out(result).split())
        expected = "cake" if state.engine == "cake" else "htb"
        if f"qdisc {expected} {EGRESS_HANDLE}" not in text:
            return False
        if state.engine == "cake":
            # CAKE'in bandwidth'i gerçekten kuruldu mu? "unlimited" ise
            # shaper devre dışıdır ve bu bir başarı değildir.
            return "unlimited" not in text and "bandwidth" in text
        return True

    def _apply_ingress(self, interface: str, state: SqmState,
                       kbit: int) -> None:
        if not self.ifb_available():
            state.notes.append(
                "IFB desteği yok; yalnız upload şekillendirildi")
            return
        if self.ingress_occupied(interface):
            state.notes.append(
                "Arayüzde zaten ingress/clsact yapılandırması var; korundu, "
                "yalnız upload şekillendirildi")
            return

        if not self._ifb_exists():
            result = self._run(["ip", "link", "add", "name", IFB_DEVICE,
                                "type", "ifb"])
            if _rc(result) != 0:
                state.notes.append(
                    "IFB aygıtı oluşturulamadı; yalnız upload şekillendirildi")
                return
            state.ifb_created = True
        result = self._run(["ip", "link", "set", "dev", IFB_DEVICE, "up"])
        if _rc(result) != 0:
            state.notes.append(
                "IFB aygıtı açılamadı; yalnız upload şekillendirildi")
            return

        result = self._run(["tc", "qdisc", "add", "dev", interface, "handle",
                            INGRESS_HANDLE, "ingress"])
        if _rc(result) != 0:
            state.notes.append(
                "ingress qdisc kurulamadı; yalnız upload şekillendirildi")
            return
        state.ingress_qdisc_created = True

        result = self._run([
            "tc", "filter", "add", "dev", interface, "parent", INGRESS_HANDLE,
            "protocol", "all", "prio", FILTER_PRIO, "u32",
            "match", "u32", "0", "0", "flowid", "1:",
            "action", "mirred", "egress", "redirect", "dev", IFB_DEVICE])
        if _rc(result) != 0:
            state.notes.append(
                "ingress yönlendirme filtresi kurulamadı; yalnız upload "
                "şekillendirildi")
            return
        state.filter_added = True

        args = (self._cake_args(kbit, ingress=True) if state.engine == "cake"
                else ["fq_codel"])
        if state.engine != "cake":
            # HTB yolunda IFB üzerinde de shaper gerekir.
            result = self._run(["tc", "qdisc", "replace", "dev", IFB_DEVICE,
                                "root", "handle", EGRESS_HANDLE, "htb",
                                "default", "10"])
            if _rc(result) == 0:
                self._run(["tc", "class", "replace", "dev", IFB_DEVICE,
                           "parent", EGRESS_HANDLE, "classid",
                           EGRESS_HANDLE + "10", "htb", "rate", f"{kbit}kbit",
                           "ceil", f"{kbit}kbit"])
                result = self._run(["tc", "qdisc", "replace", "dev", IFB_DEVICE,
                                    "parent", EGRESS_HANDLE + "10", "fq_codel"])
        else:
            result = self._run(["tc", "qdisc", "replace", "dev", IFB_DEVICE,
                                "root", "handle", EGRESS_HANDLE] + args)
        if _rc(result) != 0:
            state.notes.append(
                "IFB kuyruğu kurulamadı; yalnız upload şekillendirildi")
            return
        state.ingress_applied = True
        state.ingress_kbit = kbit

    # -- geri alma --------------------------------------------------------- #
    def _ifb_exists(self) -> bool:
        result = self._run(["ip", "link", "show", "dev", IFB_DEVICE])
        return _rc(result) == 0

    def rollback(self, state: SqmState) -> bool:
        """Yalnız **bizim oluşturduğumuz** kaynakları, ters sırada kaldır.

        Idempotenttir ve **var olmayan kaynağı hata saymaz**. Bu ikinci
        özellik kurtarma için gereklidir: servis uygulama ortasında
        öldürülürse diskteki tarif, henüz oluşturulmamış kaynakları da
        oluşturulmuş gibi listeler. Silmeden önce varlık kontrol edilir,
        böylece "zaten yok" durumu istenen sonuç olarak kabul edilir ve
        yanlışlıkla "geri alınamadı" denmez.

        Her adım ayrı değerlendirilir; biri başarısız olsa da kalanlar
        denenir ve sonuç dürüstçe raporlanır.
        """
        ok = True
        interface = state.interface
        ingress_present = self.ingress_occupied(interface)

        if state.filter_added:
            if not ingress_present:
                state.filter_added = False      # ingress yok → filtre de yok
            else:
                result = self._run(["tc", "filter", "del", "dev", interface,
                                    "parent", INGRESS_HANDLE, "prio",
                                    FILTER_PRIO])
                if _rc(result) != 0:
                    log.error("%s ingress filtresi kaldırılamadı", interface)
                    ok = False
                else:
                    state.filter_added = False
        if state.ingress_qdisc_created:
            if not ingress_present:
                state.ingress_qdisc_created = False
            else:
                result = self._run(["tc", "qdisc", "del", "dev", interface,
                                    "handle", INGRESS_HANDLE, "ingress"])
                if _rc(result) != 0:
                    log.error("%s ingress qdisc'i kaldırılamadı", interface)
                    ok = False
                else:
                    state.ingress_qdisc_created = False
        if state.ifb_created:
            # Kuyruk aygıtla birlikte gider; aygıtı biz oluşturduğumuz için
            # kaldırabiliriz. Bizim oluşturmadığımız bir IFB'ye dokunulmaz.
            if not self._ifb_exists():
                state.ifb_created = False
                state.ingress_applied = False
            else:
                result = self._run(["ip", "link", "del", "dev", IFB_DEVICE])
                if _rc(result) != 0:
                    log.error("%s aygıtı kaldırılamadı", IFB_DEVICE)
                    ok = False
                else:
                    state.ifb_created = False
                    state.ingress_applied = False
        if state.egress_applied:
            if not state.egress_restore:
                log.error("%s egress geri alma tarifi yok", interface)
                return False
            # Tarif, değişiklikten önceki kanıtlanmış durumdur; hiç
            # değiştirmemiş olsak bile uygulanması no-op'tur.
            result = self._run(["tc", "qdisc", "replace", "dev", interface,
                                "root"] + list(state.egress_restore))
            if _rc(result) != 0:
                log.error("%s egress qdisc'i geri alınamadı", interface)
                ok = False
            else:
                state.egress_applied = False
        return ok

    def signature(self, interface: str) -> str:
        """Uygulama sonrası durum imzası — dış değişikliği saptamak için."""
        result = self._run(["tc", "qdisc", "show", "dev", interface])
        if _rc(result) != 0:
            return ""
        return "\n".join(line.strip() for line in _out(result).splitlines()
                         if line.strip())
