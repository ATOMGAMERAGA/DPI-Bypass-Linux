"""Stratejilerin gerçek sokete uygulanması.

Burada yapılan her şey kullanıcı alanındadır: ham soket, çekirdek modülü ya
da NFQUEUE gerekmez. Yalnızca soket seçenekleri (TCP_NODELAY, IP_TTL,
MSG_OOB, TCP_REPAIR) ve gönderim sınırları kullanılır.
"""

from __future__ import annotations

import asyncio
import logging
import re
import socket

from . import rawfake, tlsutil
from .strategies import Strategy

log = logging.getLogger("dpibypass.desync")

OOB_BYTE = b"\x61"

_caps: dict[str, bool] = {}


def capabilities() -> dict[str, bool]:
    """Çalışma zamanı yetenekleri (bir kez saptanır)."""
    if _caps:
        return _caps
    seq_read = _probe_sequence_read()
    raw_ok = rawfake.available()
    _caps["seq_read"] = seq_read
    _caps["raw_socket"] = raw_ok
    _caps["rawfake"] = seq_read and raw_ok
    _caps["oob"] = True
    return _caps


def _probe_sequence_read() -> bool:
    """Kurulu bir bağlantının sıra numarası okunabiliyor mu?"""
    srv = cli = acc = None
    try:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        cli = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        cli.connect(srv.getsockname())
        acc, _ = srv.accept()
        return rawfake.read_sequence_numbers(cli) is not None
    except OSError as exc:
        log.info("sıra numarası okunamıyor (%s); sahte paket kipi atlanacak", exc)
        return False
    finally:
        for s in (acc, cli, srv):
            try:
                if s is not None:
                    s.close()
            except OSError:
                pass


def strategy_available(st: Strategy) -> bool:
    caps = capabilities()
    return all(caps.get(req, False) for req in st.requires)


# --- soket yardımcıları -----------------------------------------------------

def set_ttl(sock: socket.socket, ttl: int) -> None:
    try:
        if sock.family == socket.AF_INET6:
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_UNICAST_HOPS, ttl)
        else:
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
    except OSError as exc:
        log.debug("TTL ayarlanamadı: %s", exc)


def get_ttl(sock: socket.socket) -> int:
    try:
        if sock.family == socket.AF_INET6:
            return sock.getsockopt(socket.IPPROTO_IPV6, socket.IPV6_UNICAST_HOPS) or 64
        return sock.getsockopt(socket.IPPROTO_IP, socket.IP_TTL) or 64
    except OSError:
        return 64


async def _send_oob(loop: asyncio.AbstractEventLoop, sock: socket.socket) -> None:
    for _ in range(50):
        try:
            sock.send(OOB_BYTE, socket.MSG_OOB)
            return
        except BlockingIOError:
            await asyncio.sleep(0.002)
        except OSError as exc:
            log.debug("OOB baytı gönderilemedi: %s", exc)
            return


# --- kesme noktası çözümleme ------------------------------------------------

_TOKEN_RE = re.compile(r"^(snimid|sniend|sni|hostmid|host|mid)([+-]\d+)?$")


def _resolve_token(token: str, data: bytes, info: tlsutil.ClientHelloInfo | None,
                   host_off: int, host_len: int) -> int | None:
    """``snimid+2`` gibi bir belirteci tampon içindeki mutlak ofsete çevir."""
    token = token.strip().lower()
    if token.startswith("rec:"):
        token = token[4:]

    if token.lstrip("+-").isdigit():
        return int(token)

    match = _TOKEN_RE.match(token)
    if not match:
        return None
    kind, offset_str = match.group(1), match.group(2)
    delta = int(offset_str) if offset_str else 0

    has_sni = bool(info and info.sni_offset and info.sni_length)
    base: int | None = None

    if kind.startswith("sni"):
        if has_sni:
            assert info is not None
            if kind == "snimid":
                base = info.sni_offset + max(1, info.sni_length // 2)
            elif kind == "sniend":
                base = info.sni_offset + info.sni_length
            else:
                base = info.sni_offset
        elif host_len:
            # HTTP isteği: SNI yerine Host başlığı değerini kullan
            base = host_off + (max(1, host_len // 2) if kind == "snimid" else
                               host_len if kind == "sniend" else 0)
        else:
            # Ne SNI ne Host var: baştan küçük bir bölme yine de işe yarar
            base = min(3, max(1, len(data) // 2))
    elif kind.startswith("host"):
        if not host_len:
            return None
        base = host_off + (max(1, host_len // 2) if kind == "hostmid" else 0)
    elif kind == "mid":
        base = len(data) // 2

    return None if base is None else base + delta


def _positions(tokens: tuple[str, ...], data: bytes,
               info: tlsutil.ClientHelloInfo | None,
               host_off: int, host_len: int) -> list[int]:
    out: list[int] = []
    for tok in tokens:
        pos = _resolve_token(tok, data, info, host_off, host_len)
        if pos is not None and 0 < pos < len(data):
            out.append(pos)
    return sorted(set(out))


def prepare(data: bytes, st: Strategy) -> tuple[bytes, list[int], str | None]:
    """Stratejiyi bayt düzeyinde uygula.

    Döndürür: (dönüştürülmüş tampon, TCP bölme ofsetleri, saptanan ana bilgisayar)
    """
    info = tlsutil.parse_client_hello(data)
    host = info.sni if info else None
    host_off = host_len = 0
    if info is None and tlsutil.looks_like_http(data):
        http_host, host_off, host_len = tlsutil.parse_http_host(data)
        host = http_host
        if st.http_mangle:
            data = tlsutil.http_mangle_host(data)

    cuts: list[int] = []
    if st.tlsrec and info is not None:
        rec_cuts = []
        for tok in st.tlsrec:
            pos = _resolve_token(tok, data, info, host_off, host_len)
            if pos is not None:
                rec_cuts.append(pos - info.payload_offset)
        data, cuts = tlsutil.split_tls_records(data, rec_cuts)

    splits: list[int] = []
    if st.split:
        for tok in st.split:
            pos = _resolve_token(tok, data, info, host_off, host_len)
            if pos is None:
                continue
            pos = tlsutil.shift_offset(pos, cuts) if cuts else pos
            if 0 < pos < len(data):
                splits.append(pos)
        splits = sorted(set(splits))

    return data, splits, host


def _chunks(data: bytes, splits: list[int]) -> list[bytes]:
    if not splits:
        return [data]
    parts = []
    prev = 0
    for pos in splits:
        parts.append(data[prev:pos])
        prev = pos
    parts.append(data[prev:])
    return [p for p in parts if p]


# --- ana giriş noktası ------------------------------------------------------

async def send_first_payload(loop: asyncio.AbstractEventLoop, sock: socket.socket,
                             data: bytes, st: Strategy) -> str | None:
    """İlk istemci verisini stratejiye göre gönder; saptanan ana bilgisayarı döndür."""
    try:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    except OSError:
        pass

    payload, splits, host = prepare(data, st)
    parts = _chunks(payload, splits)
    mode = st.mode

    if mode == "none" or len(parts) == 1 and mode in ("split", "oob"):
        await loop.sock_sendall(sock, payload)
        return host

    if mode == "split":
        for i, part in enumerate(parts):
            await loop.sock_sendall(sock, part)
            if st.delay and i < len(parts) - 1:
                await asyncio.sleep(st.delay)
            else:
                await asyncio.sleep(0)
        return host

    if mode == "oob":
        for i, part in enumerate(parts):
            await loop.sock_sendall(sock, part)
            if i < len(parts) - 1:
                await _send_oob(loop, sock)
                await asyncio.sleep(st.delay or 0.002)
        return host

    if mode in ("disorder", "disoob"):
        orig_ttl = get_ttl(sock)
        set_ttl(sock, st.ttl)
        await loop.sock_sendall(sock, parts[0])
        # ilk parçanın düşük TTL ile tel üzerine çıkmasına izin ver
        await asyncio.sleep(0.006)
        set_ttl(sock, orig_ttl)
        if mode == "disoob":
            await _send_oob(loop, sock)
        for part in parts[1:]:
            await loop.sock_sendall(sock, part)
            await asyncio.sleep(st.delay or 0)
        return host

    if mode == "fake":
        # Sahte paket, çekirdeğin gönderim kuyruğuna hiç girmeden ham soketle
        # ve gerçek verinin sıra numarasıyla gönderilir; böylece sunucu onu
        # görmez ama DPI görür.
        fake = tlsutil.build_fake_client_hello(st.fake_sni)
        if not rawfake.send_fake(sock, fake, st.ttl):
            raise OSError("sahte paket gönderilemedi")
        await asyncio.sleep(0.004)
        for i, part in enumerate(parts):
            await loop.sock_sendall(sock, part)
            if i < len(parts) - 1:
                await asyncio.sleep(st.delay or 0.002)
        return host

    await loop.sock_sendall(sock, payload)
    return host
