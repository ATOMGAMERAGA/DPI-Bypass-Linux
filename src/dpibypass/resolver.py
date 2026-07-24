"""DNS-over-HTTPS çözümleyici (Cloudflare birincil, Google ve Quad9 yedek).

DNS düzeyindeki engelleme Türkiye'de en yaygın ilk katmandır; DoH bunu
tamamen aşar. DoH bağlantısının kendisi de gerekirse atlatma stratejisiyle
kurulur (bkz. ``tlsclient``).
"""

from __future__ import annotations

import asyncio
import logging
import random
import socket
import struct
import time
from dataclasses import dataclass, field

from . import tlsclient
from .constants import DOH_PROVIDERS
from .strategies import Strategy

log = logging.getLogger("dpibypass.dns")

TYPE_A = 1
TYPE_AAAA = 28
TYPE_TXT = 16
TYPE_CNAME = 5


# --- tel biçimi -------------------------------------------------------------

def encode_name(name: str) -> bytes:
    out = b""
    for label in name.strip(".").split("."):
        data = label.encode("idna") if any(ord(c) > 127 for c in label) else label.encode()
        out += bytes([len(data)]) + data
    return out + b"\x00"


def build_query(name: str, qtype: int = TYPE_A, qid: int = 0) -> bytes:
    header = struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    return header + encode_name(name) + struct.pack("!HH", qtype, 1)


def _read_name(data: bytes, pos: int) -> tuple[str, int]:
    labels: list[str] = []
    jumped = False
    end = pos
    hops = 0
    while True:
        if pos >= len(data) or hops > 64:
            break
        length = data[pos]
        if length == 0:
            pos += 1
            if not jumped:
                end = pos
            break
        if length & 0xC0 == 0xC0:
            ptr = ((length & 0x3F) << 8) | data[pos + 1]
            if not jumped:
                end = pos + 2
            pos = ptr
            jumped = True
            hops += 1
            continue
        labels.append(data[pos + 1:pos + 1 + length].decode("ascii", "replace"))
        pos += 1 + length
        if not jumped:
            end = pos
    return ".".join(labels), end


@dataclass
class Record:
    name: str
    rtype: int
    ttl: int
    data: bytes


@dataclass
class Message:
    qid: int = 0
    rcode: int = 0
    question: str = ""
    qtype: int = 0
    answers: list[Record] = field(default_factory=list)

    def addresses(self) -> list[str]:
        out = []
        for rec in self.answers:
            if rec.rtype == TYPE_A and len(rec.data) == 4:
                out.append(socket.inet_ntop(socket.AF_INET, rec.data))
            elif rec.rtype == TYPE_AAAA and len(rec.data) == 16:
                out.append(socket.inet_ntop(socket.AF_INET6, rec.data))
        return out

    def texts(self) -> list[str]:
        out = []
        for rec in self.answers:
            if rec.rtype == TYPE_TXT and rec.data:
                pos = 0
                parts = []
                while pos < len(rec.data):
                    ln = rec.data[pos]
                    parts.append(rec.data[pos + 1:pos + 1 + ln].decode("utf-8", "replace"))
                    pos += 1 + ln
                out.append("".join(parts))
        return out

    def min_ttl(self, default: int = 300) -> int:
        ttls = [r.ttl for r in self.answers if r.ttl > 0]
        return max(30, min(ttls)) if ttls else default


def parse_message(data: bytes) -> Message:
    msg = Message()
    if len(data) < 12:
        return msg
    qid, flags, qdcount, ancount, _, _ = struct.unpack_from("!HHHHHH", data, 0)
    msg.qid = qid
    msg.rcode = flags & 0x0F
    pos = 12
    for i in range(qdcount):
        name, pos = _read_name(data, pos)
        if i == 0:
            msg.question = name
            if pos + 4 <= len(data):
                msg.qtype = struct.unpack_from("!H", data, pos)[0]
        pos += 4
    for _ in range(ancount):
        if pos >= len(data):
            break
        name, pos = _read_name(data, pos)
        if pos + 10 > len(data):
            break
        rtype, _rclass, ttl, rdlen = struct.unpack_from("!HHIH", data, pos)
        pos += 10
        msg.answers.append(Record(name, rtype, ttl, data[pos:pos + rdlen]))
        pos += rdlen
    return msg


# --- çözümleyici ------------------------------------------------------------

class Resolver:
    def __init__(self) -> None:
        self._cache: dict[tuple[str, int], tuple[float, Message, bytes]] = {}
        self._provider_order = list(range(len(DOH_PROVIDERS)))
        self._strategy: Strategy | None = None
        self._lock = asyncio.Lock()
        self.last_provider: str = "-"
        self.stats = {"query": 0, "cache_hit": 0, "fail": 0}

    def set_strategy(self, strategy: Strategy | None) -> None:
        """DoH bağlantılarının da kullanacağı atlatma stratejisi."""
        self._strategy = strategy

    def set_preferred(self, provider_name: str) -> None:
        """Kullanıcının seçtiği sağlayıcıyı sıranın başına al."""
        names = [p["name"].lower() for p in DOH_PROVIDERS]
        want = provider_name.strip().lower()
        if want in names:
            idx = names.index(want)
            self._provider_order = [idx] + [i for i in range(len(DOH_PROVIDERS)) if i != idx]

    def clear_cache(self) -> None:
        self._cache.clear()

    # -- düşük düzey -------------------------------------------------------
    async def _doh(self, provider: dict, wire: bytes, timeout: float) -> bytes:
        last_exc: Exception | None = None
        for addr in provider["addrs"]:
            try:
                status, body = await tlsclient.https_request(
                    addr,
                    provider["host"],
                    "POST",
                    provider["path"],
                    body=wire,
                    headers={
                        "Content-Type": "application/dns-message",
                        "Accept": "application/dns-message",
                    },
                    strategy=self._strategy,
                    timeout=timeout,
                )
                if status == 200 and len(body) >= 12:
                    self.last_provider = provider["name"]
                    return body
                last_exc = OSError(f"{provider['name']} HTTP {status}")
            except Exception as exc:  # ağ hatası, TLS hatası, zaman aşımı
                last_exc = exc
                log.debug("DoH %s@%s başarısız: %s", provider["name"], addr, exc)
        raise last_exc or OSError("DoH başarısız")

    async def query_wire(self, wire: bytes, timeout: float = 5.0) -> bytes:
        """Ham DNS sorgusunu DoH üzerinden ilet, ham yanıtı döndür."""
        qid = struct.unpack_from("!H", wire, 0)[0] if len(wire) >= 2 else 0
        outgoing = b"\x00\x00" + wire[2:]
        errors = []
        for idx in self._provider_order:
            provider = DOH_PROVIDERS[idx]
            try:
                body = await self._doh(provider, outgoing, timeout)
                return struct.pack("!H", qid) + body[2:]
            except Exception as exc:
                errors.append(f"{provider['name']}: {exc}")
        self.stats["fail"] += 1
        raise OSError("tüm DoH sağlayıcıları başarısız (" + "; ".join(errors) + ")")

    async def resolve_wire_cached(self, wire: bytes,
                                  timeout: float = 5.0) -> tuple[bytes, Message]:
        """Yerel DNS sunucusu için: önbellekli ham sorgu/yanıt.

        (istemciye gönderilecek ham yanıt, ayrıştırılmış yanıt) döndürür.
        """
        question = parse_message(wire)
        qid = question.qid
        key = (question.question.lower().strip("."), question.qtype)
        now = time.time()
        hit = self._cache.get(key)
        if hit and hit[0] > now:
            self.stats["cache_hit"] += 1
            raw = hit[2]
            return struct.pack("!H", qid) + raw[2:], hit[1]

        self.stats["query"] += 1
        raw = await self.query_wire(wire, timeout=timeout)
        msg = parse_message(raw)
        if msg.rcode == 0 and msg.answers:
            self._cache[key] = (now + msg.min_ttl(), msg, raw)
        return raw, msg

    # -- yüksek düzey ------------------------------------------------------
    async def query(self, name: str, qtype: int = TYPE_A,
                    timeout: float = 5.0, use_cache: bool = True) -> Message:
        key = (name.lower().strip("."), qtype)
        now = time.time()
        if use_cache:
            hit = self._cache.get(key)
            if hit and hit[0] > now:
                self.stats["cache_hit"] += 1
                return hit[1]

        self.stats["query"] += 1
        wire = build_query(name, qtype, qid=random.randint(1, 65535))
        raw = await self.query_wire(wire, timeout=timeout)
        msg = parse_message(raw)
        if msg.rcode == 0 and msg.answers:
            self._cache[key] = (now + msg.min_ttl(), msg, raw)
        return msg

    async def resolve(self, name: str, timeout: float = 5.0,
                      want_v6: bool = False) -> list[str]:
        """Alan adını IP listesine çevir (önce A, istenirse AAAA)."""
        addrs: list[str] = []
        try:
            msg = await self.query(name, TYPE_A, timeout)
            addrs.extend(msg.addresses())
        except Exception as exc:
            log.debug("A kaydı çözümlenemedi %s: %s", name, exc)
        if want_v6:
            try:
                msg6 = await self.query(name, TYPE_AAAA, timeout)
                addrs.extend(msg6.addresses())
            except Exception:
                pass
        if not addrs:
            # Son çare: sistem çözümleyicisi (zehirlenmiş olabilir, yine de dene)
            try:
                loop = asyncio.get_running_loop()
                infos = await loop.getaddrinfo(name, None, type=socket.SOCK_STREAM)
                addrs = list({i[4][0] for i in infos})
                log.debug("%s sistem çözümleyicisi ile çözüldü", name)
            except OSError:
                pass
        return addrs

    async def txt(self, name: str, timeout: float = 5.0) -> list[str]:
        msg = await self.query(name, TYPE_TXT, timeout)
        return msg.texts()


#: Süreç genelinde paylaşılan çözümleyici
shared = Resolver()
