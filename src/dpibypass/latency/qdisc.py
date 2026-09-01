"""Kuyruk disiplini keşfi: yapılandırılmış okuma ve kanıtlanmış geri alma.

Eski motor yalnızca **tek köklü basit FIFO**'ları değiştirebiliyordu; bu
güvenliydi ama kapsamı gereğinden dar tutuyordu: ``mq`` köklü çok kuyruklu
NIC'lerde (dizüstü Ethernet'lerin çoğu) hiçbir aday denenemiyor ve sonuç
"ağ zaten optimum" gibi görünüyordu. Oysa doğru ifade "bu aday denenemedi".

Bu modül kapsamı **kanıta bağlayarak** genişletir:

1. Mümkünse ``tc -j -d`` ile yapılandırılmış okuma yapılır; satır sayısına
   göre tahmin yürütülmez. Desteklenmiyorsa dar ve testli metin yoluna
   düşülür.
2. ``mq`` kökü **silinmez**. Kök korunur, yalnız tanınan yaprak kuyruklar
   kendi ``parent``'ları altında aday olur.
3. Bir qdisc'in aday olabilmesi için geri alma tarifinin **kanıtlanması**
   gerekir: tarif ``tc qdisc change`` ile uygulanır (mevcut değerlerin
   aynısı yazıldığı için no-op'tur) ve durum geri okunarak karşılaştırılır.
   Kanıtlanamayan yapı korunur.
4. Bağlı class ya da filter varsa, ya da seçenek allowlist'inde olmayan bir
   anahtar görülürse yapı korunur.

Kullanıcının kasıtlı CAKE/HTB/SQM yapılandırması varsayılan olarak asla
ezilmez.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from typing import Callable, Sequence

log = logging.getLogger("dpibypass.latency.qdisc")

#: Aday olarak denenebilecek kuyruk disiplinleri.
QDISC_TARGETS = ("fq_codel", "fq", "cake")

#: Yapısal kökler: bunlar silinmez, yaprakları incelenir.
STRUCTURAL_KINDS = ("mq", "mqprio")

#: Dokunulmayacak, kullanıcının kasıtlı yapılandırması sayılan kökler.
PRESERVED_KINDS = ("htb", "hfsc", "cbq", "drr", "qfq", "prio", "multiq",
                   "netem", "tbf", "hhf", "sfb", "sfq", "cake", "clsact",
                   "ingress", "noqueue")

_TIME_KEYS = ("target", "interval", "ce_threshold", "refill_delay",
              "timer_slack", "horizon")

#: Kind → {json anahtarı: tip}. Tip, geri yazma biçimini belirler:
#: ``int`` düz sayı, ``time`` mikrosaniye + ``us`` eki, ``flag`` bayrak
#: (True → anahtar, False → ``no`` önekli anahtar), ``raw`` olduğu gibi.
#: Bu allowlist dışında **bir tek** anahtar görülse bile yapı korunur.
RESTORABLE_OPTIONS: dict = {
    "pfifo": {"limit": "int"},
    "bfifo": {"limit": "int"},
    "pfifo_fast": {"bands": "ignore", "priomap": "ignore",
                   "multiqueue": "ignore"},
    "fq_codel": {
        "limit": "int", "flows": "int", "quantum": "int",
        "target": "time", "interval": "time", "ce_threshold": "time",
        "memory_limit": "int", "drop_batch": "int", "ecn": "flag",
    },
    "fq": {
        "limit": "int", "flow_limit": "int", "quantum": "int",
        "initial_quantum": "int", "buckets": "int", "orphan_mask": "int",
        "refill_delay": "time", "maxrate": "raw", "pacing": "flag",
    },
}

#: ``pfifo_fast``'ın bands/priomap değerleri çekirdek sabitidir; tc bunları
#: kabul etmez. Tarife konursa geri alma her seferinde başarısız olur.
_IGNORED_OPTIONS = ("bands", "priomap", "multiqueue")


@dataclass
class QdiscNode:
    kind: str = ""
    handle: str = ""
    parent: str = "root"          # "root" | "1:2" gibi
    options: dict = field(default_factory=dict)
    raw: str = ""

    @property
    def is_root(self) -> bool:
        return self.parent == "root"


@dataclass
class QdiscSlot:
    """Değiştirilebileceği **kanıtlanmış** bir kuyruk yuvası."""

    parent: str                   # "root" | "1:2"
    kind: str
    restore_args: list = field(default_factory=list)
    handle: str = ""
    label: str = ""

    def location(self) -> list:
        return ["root"] if self.parent == "root" else ["parent", self.parent]

    def to_dict(self) -> dict:
        return {"parent": self.parent, "kind": self.kind,
                "restore_args": list(self.restore_args),
                "handle": self.handle, "label": self.label}


@dataclass
class QdiscTopology:
    nodes: list = field(default_factory=list)
    structured: bool = False
    has_filters: bool = False
    has_classes: bool = False
    notes: list = field(default_factory=list)

    def root(self) -> "QdiscNode | None":
        for node in self.nodes:
            if node.is_root:
                return node
        return None

    def leaves_of(self, root_handle: str) -> list:
        """Kökün altındaki yaprak kuyruklar.

        ``tc``, ``mq`` yapraklarını ``parent :4`` biçiminde yazar: major
        numarası boştur ve 0 anlamına gelir. Bu yüzden karşılaştırma ham
        metinle değil, normalize edilmiş major numarasıyla yapılır.
        """
        major = _major(root_handle)
        return [node for node in self.nodes
                if not node.is_root and _major(node.parent) == major]


def _major(handle: str) -> str:
    """``"0:"`` → ``"0"``, ``":4"`` → ``"0"``, ``"1:2"`` → ``"1"``."""
    text = (handle or "").split(":")[0].strip()
    return text or "0"


def _rc(result) -> int:
    return int(getattr(result, "returncode", 1) or 0)


def _out(result) -> str:
    return str(getattr(result, "stdout", "") or "")


def normalize(output: str) -> str:
    return "\n".join(line.strip() for line in output.splitlines() if line.strip())


# --------------------------------------------------------------------------- #
# okuma
# --------------------------------------------------------------------------- #
def parse_json_qdiscs(output: str) -> "list | None":
    """``tc -j -d qdisc show`` çıktısını ayrıştır. Başarısızsa None."""
    try:
        data = json.loads(output)
    except ValueError:
        return None
    if not isinstance(data, list):
        return None
    nodes = []
    for entry in data:
        if not isinstance(entry, dict) or not entry.get("kind"):
            return None
        parent = "root" if entry.get("root") else str(entry.get("parent", ""))
        options = entry.get("options")
        nodes.append(QdiscNode(
            kind=str(entry["kind"]),
            handle=str(entry.get("handle", "")),
            parent=parent or "root",
            options=dict(options) if isinstance(options, dict) else {},
            raw=json.dumps(entry, sort_keys=True),
        ))
    return nodes


_TEXT_QDISC_RE = re.compile(
    r"^qdisc\s+(?P<kind>\S+)\s+(?P<handle>\S+)\s+"
    r"(?:(?P<root>root)|parent\s+(?P<parent>\S+))"
    r"(?:\s+refcnt\s+\d+)?(?P<rest>.*)$")


def parse_text_qdiscs(output: str) -> list:
    """``tc -j`` yokken kullanılan dar metin yolu."""
    nodes = []
    for line in normalize(output).splitlines():
        match = _TEXT_QDISC_RE.match(line)
        if match is None:
            nodes.append(QdiscNode(kind="?", raw=line))
            continue
        rest = (match.group("rest") or "").strip()
        nodes.append(QdiscNode(
            kind=match.group("kind"),
            handle=match.group("handle"),
            parent="root" if match.group("root") else match.group("parent"),
            options=_parse_text_options(rest),
            raw=line))
    return nodes


def _parse_text_options(rest: str) -> dict:
    """Metin seçeneklerini anahtar/değer sözlüğüne çevir.

    Bilinmeyen ya da ayrıştırılamayan bir şey görülürse sözlüğe ``__raw__``
    konur ve çağıran yapıyı korur — tahmin yürütmeyiz.
    """
    tokens = rest.split()
    options: dict = {}
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if not re.match(r"^[a-z_]+\Z", token):
            options["__raw__"] = rest
            return options
        following = tokens[index + 1] if index + 1 < len(tokens) else ""
        if following and not re.match(r"^[a-z_]+\Z", following):
            options[token] = following
            index += 2
        else:
            options[token] = True
            index += 1
    return options


def read_topology(runner: Callable, which_fn: Callable, interface: str,
                  timeout: int = 8) -> QdiscTopology:
    """Arayüzün qdisc/class/filter yapısını oku."""
    topology = QdiscTopology()
    if which_fn("tc") is None:
        topology.notes.append("tc bulunamadı; kuyruk disiplini incelenemedi")
        return topology

    result = runner(["tc", "-j", "-d", "qdisc", "show", "dev", interface],
                    timeout=timeout)
    nodes = parse_json_qdiscs(_out(result)) if _rc(result) == 0 else None
    if nodes is not None:
        topology.nodes = nodes
        topology.structured = True
    else:
        result = runner(["tc", "qdisc", "show", "dev", interface],
                        timeout=timeout)
        if _rc(result) != 0:
            topology.notes.append("Kuyruk disiplini güvenle okunamadı")
            return topology
        topology.nodes = parse_text_qdiscs(_out(result))
        topology.notes.append(
            "tc -j desteklenmiyor; dar metin yolu kullanıldı")

    for kind, attribute in (("class", "has_classes"), ("filter", "has_filters")):
        result = runner(["tc", kind, "show", "dev", interface], timeout=timeout)
        if _rc(result) == 0 and normalize(_out(result)):
            setattr(topology, attribute, True)
    return topology


# --------------------------------------------------------------------------- #
# geri alma tarifi
# --------------------------------------------------------------------------- #
def restore_args(node: QdiscNode) -> "list | None":
    """Bu qdisc'i olduğu gibi geri kuracak ``tc`` argümanları. Bilinmiyorsa None."""
    allow = RESTORABLE_OPTIONS.get(node.kind)
    if allow is None:
        return None
    args = [node.kind]
    for key, value in sorted(node.options.items()):
        if key in _IGNORED_OPTIONS:
            continue
        kind = allow.get(key)
        if kind is None or kind == "ignore":
            if kind == "ignore":
                continue
            return None          # allowlist dışı anahtar: yapıyı koru
        if kind == "flag":
            if value is True:
                args.append(key)
            elif value is False:
                args.append(f"no{key}")
            else:
                return None
            continue
        if isinstance(value, bool):
            return None
        text = str(value)
        if kind == "int":
            if not re.match(r"^[0-9]{1,19}\Z", text):
                return None
            args.extend([key, text])
        elif kind == "time":
            match = re.match(r"^([0-9]{1,19})(?:us)?\Z", text)
            if match is None:
                return None
            # Çıplak sayı iproute2'de mikrosaniyedir; eki açıkça yazarak
            # sürüm farklarında yanlış yorumlanmasını engelliyoruz.
            args.extend([key, match.group(1) + "us"])
        elif kind == "raw":
            if not re.match(r"^[A-Za-z0-9._]{1,24}\Z", text):
                return None
            args.extend([key, text])
        else:
            return None
    return args


def prove_restorable(runner: Callable, interface: str, slot: QdiscSlot,
                     timeout: int = 8) -> tuple[bool, str]:
    """Geri alma tarifini **uygulayarak** kanıtla.

    Tarif mevcut değerlerin aynısını yazdığı için ``tc qdisc change`` bir
    no-op'tur; başarılı olması, gerçek geri alma anında da başarılı olacağının
    kanıtıdır. Sürüm farkı, desteklenmeyen seçenek ya da yazılamayan alan
    burada ortaya çıkar ve yapı adaylıktan çıkarılır.

    Seçeneği olmayan yapılarda (``pfifo_fast``) yazılacak bir şey yoktur;
    kanıt gerektirmez.
    """
    if len(slot.restore_args) <= 1:
        return True, ""
    before = runner(["tc", "-d", "qdisc", "show", "dev", interface],
                    timeout=timeout)
    if _rc(before) != 0:
        return False, "mevcut durum okunamadı"
    cmd = (["tc", "qdisc", "change", "dev", interface] + slot.location()
           + list(slot.restore_args))
    result = runner(cmd, timeout=timeout)
    if _rc(result) != 0:
        return False, "geri alma tarifi çekirdek tarafından kabul edilmedi"
    after = runner(["tc", "-d", "qdisc", "show", "dev", interface],
                   timeout=timeout)
    if _rc(after) != 0:
        return False, "kanıt sonrası durum okunamadı"
    if normalize(_out(before)) != normalize(_out(after)):
        return False, "geri alma tarifi durumu birebir yeniden kuramıyor"
    return True, ""


# --------------------------------------------------------------------------- #
# aday yuvaları
# --------------------------------------------------------------------------- #
def plan_slots(topology: QdiscTopology, interface: str,
               runner: Callable | None = None,
               prove: bool = True) -> tuple[list, list]:
    """Değiştirilebilecek yuvaları ve atlama nedenlerini üret.

    Döner: ``(slots, notes)``. ``slots`` boşsa neden her zaman ``notes``
    içindedir — "ağ optimum" gibi bir sonuç asla üretilmez.
    """
    notes: list = list(topology.notes)
    if not topology.nodes:
        return [], notes

    if topology.has_filters or topology.has_classes:
        notes.append("Arayüzde bağlı filter/class var; kuyruk yapısı korundu")
        return [], notes

    root = topology.root()
    if root is None:
        notes.append("Kök qdisc bulunamadı; yapı korundu")
        return [], notes

    candidates: list = []
    if root.kind in STRUCTURAL_KINDS:
        leaves = topology.leaves_of(root.handle)
        if not leaves:
            notes.append(f"{root.kind} kökünün yaprakları okunamadı; korundu")
            return [], notes
        kinds = {leaf.kind for leaf in leaves}
        if len(kinds) != 1:
            notes.append(f"{root.kind} yaprakları türdeş değil; yapı korundu")
            return [], notes
        for leaf in leaves:
            candidates.append(leaf)
        notes.append(f"{root.kind} kökü korunuyor; {len(leaves)} yaprak "
                     f"kuyruk ({kinds.pop()}) aday olarak inceleniyor")
    elif root.kind in PRESERVED_KINDS:
        notes.append(f"Kullanıcı yapılandırması ({root.kind}) korundu")
        return [], notes
    elif root.kind in QDISC_TARGETS:
        # Zaten hedef kuyruklardan biri. Yine de aday kalır (başka bir hedef
        # ya da parametre denenebilir), ama durum açıkça yazılır: "zaten
        # etkin" ile "ağ optimum" aynı şey değildir.
        notes.append(f"{root.kind} zaten kök qdisc olarak etkin")
        candidates.append(root)
    elif topology.leaves_of(root.handle):
        notes.append("Çok katmanlı qdisc yapısı korundu")
        return [], notes
    else:
        candidates.append(root)

    slots: list = []
    for node in candidates:
        if node.kind == "?" or "__raw__" in node.options:
            notes.append("Qdisc seçenekleri güvenle ayrıştırılamadı; korundu")
            return [], notes
        args = restore_args(node)
        if args is None:
            notes.append(f"{node.kind} seçenekleri kesin geri alınamıyor; korundu")
            return [], notes
        slot = QdiscSlot(parent=node.parent, kind=node.kind, restore_args=args,
                         handle=node.handle,
                         label=("root" if node.is_root else node.parent))
        if prove and runner is not None:
            ok, why = prove_restorable(runner, interface, slot)
            if not ok:
                notes.append(f"{node.kind} ({slot.label}): {why}; yapı korundu")
                return [], notes
        slots.append(slot)
    return slots, notes


def apply_args(interface: str, slot: QdiscSlot, target: str,
               options: Sequence[str] = ()) -> list:
    return (["tc", "qdisc", "replace", "dev", interface] + slot.location()
            + [target] + list(options))


def restore_command(interface: str, slot: QdiscSlot) -> list:
    return (["tc", "qdisc", "replace", "dev", interface] + slot.location()
            + list(slot.restore_args))
