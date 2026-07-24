"""TLS ClientHello ve HTTP istek ayrıştırma / kurcalama yardımcıları.

Bu modül saf bayt işlemleri yapar; ağ ile ilgisi yoktur, dolayısıyla
birim testleriyle doğrulanabilir.
"""

from __future__ import annotations

import os
import struct
from dataclasses import dataclass, field

TLS_HANDSHAKE = 0x16
TLS_CLIENT_HELLO = 0x01
EXT_SERVER_NAME = 0x0000


@dataclass
class ClientHelloInfo:
    """Bir TLS ClientHello içindeki ilgi çekici konumlar."""

    sni: str | None = None
    #: SNI ana bilgisayar adının tampon içindeki mutlak başlangıç ofseti
    sni_offset: int = 0
    sni_length: int = 0
    #: Kayıt (record) yükünün mutlak başlangıcı — her zaman 5
    payload_offset: int = 5
    record_length: int = 0
    extensions: list[int] = field(default_factory=list)


def _u16(buf: bytes, pos: int) -> int:
    return struct.unpack_from("!H", buf, pos)[0]


def _u24(buf: bytes, pos: int) -> int:
    return (buf[pos] << 16) | (buf[pos + 1] << 8) | buf[pos + 2]


def looks_like_tls(data: bytes) -> bool:
    return (
        len(data) >= 6
        and data[0] == TLS_HANDSHAKE
        and data[1] == 0x03
        and data[5] == TLS_CLIENT_HELLO
    )


def parse_client_hello(data: bytes) -> ClientHelloInfo | None:
    """ClientHello'yu ayrıştır; SNI konumunu döndür. Hatalıysa None."""
    if not looks_like_tls(data):
        return None
    try:
        info = ClientHelloInfo()
        info.record_length = _u16(data, 3)
        pos = 5
        hs_len = _u24(data, pos + 1)
        end_hs = pos + 4 + hs_len
        pos += 4
        pos += 2                       # client_version
        pos += 32                      # random
        pos += 1 + data[pos]           # session_id
        pos += 2 + _u16(data, pos)     # cipher_suites
        pos += 1 + data[pos]           # compression_methods
        if pos + 2 > len(data):
            return info
        ext_total = _u16(data, pos)
        pos += 2
        ext_end = min(pos + ext_total, end_hs, len(data))
        while pos + 4 <= ext_end:
            etype = _u16(data, pos)
            elen = _u16(data, pos + 2)
            body = pos + 4
            info.extensions.append(etype)
            if etype == EXT_SERVER_NAME and elen >= 5:
                q = body + 2           # server_name_list uzunluğu
                name_type = data[q]
                q += 1
                nlen = _u16(data, q)
                q += 2
                if name_type == 0 and q + nlen <= len(data):
                    info.sni = data[q:q + nlen].decode("ascii", errors="replace")
                    info.sni_offset = q
                    info.sni_length = nlen
            pos = body + elen
        return info
    except (IndexError, struct.error):
        return None


def sni_from_client_hello(data: bytes) -> str | None:
    info = parse_client_hello(data)
    return info.sni if info else None


# --- TLS kayıt parçalama ----------------------------------------------------

def split_tls_records(data: bytes, cuts: list[int]) -> tuple[bytes, list[int]]:
    """ClientHello'yu birden çok TLS kaydına böl.

    ``cuts`` kayıt yükü içindeki (0'dan başlayan) kesme noktalarıdır.
    Geriye yeni tampon ve uygulanan kesme noktaları döner. Bu işlem TLS
    açısından tamamen geçerlidir: bir el sıkışma mesajı birden çok kayda
    yayılabilir; sunucular bunu sorunsuz kabul eder, ancak durum bilgisi
    tutmayan DPI'lar SNI'yi göremez.
    """
    if len(data) < 6 or data[0] != TLS_HANDSHAKE:
        return data, []
    ver = data[1:3]
    rec_len = _u16(data, 3)
    payload = data[5:5 + rec_len]
    rest = data[5 + rec_len:]
    valid = sorted({c for c in cuts if 0 < c < len(payload)})
    if not valid:
        return data, []
    out = bytearray()
    prev = 0
    for cut in valid + [len(payload)]:
        chunk = payload[prev:cut]
        out += bytes([TLS_HANDSHAKE]) + ver + len(chunk).to_bytes(2, "big") + chunk
        prev = cut
    out += rest
    return bytes(out), valid


def shift_offset(offset: int, cuts: list[int]) -> int:
    """Kayıt parçalamasından sonra mutlak bir ofseti yeniden hesapla."""
    if not cuts:
        return offset
    payload_off = offset - 5
    added = sum(5 for c in cuts if c <= payload_off)
    return offset + added


# --- sahte ClientHello ------------------------------------------------------

def build_fake_client_hello(hostname: str = "www.microsoft.com") -> bytes:
    """DPI'ya gösterilmek üzere geçerli görünümlü sahte bir ClientHello üret.

    Bu paket düşük TTL ile gönderilir; hedef sunucuya asla ulaşmaz, yalnızca
    yol üstündeki DPI cihazı tarafından görülür.
    """
    host = hostname.encode("ascii", errors="ignore")

    sni_entry = b"\x00" + len(host).to_bytes(2, "big") + host
    sni_list = len(sni_entry).to_bytes(2, "big") + sni_entry
    ext_sni = b"\x00\x00" + len(sni_list).to_bytes(2, "big") + sni_list

    ext_groups = bytes.fromhex("000a00080006001d00170018")
    ext_ec_pf = bytes.fromhex("000b00020100")
    ext_sigalgs = bytes.fromhex("000d0012001004030804040105030805050108060601")
    ext_alpn = bytes.fromhex("0010000b000908687474702f312e31")
    ext_versions = bytes.fromhex("002b00050403040303")
    ext_sess = bytes.fromhex("00170000")
    extensions = (ext_sni + ext_versions + ext_groups + ext_ec_pf
                  + ext_sigalgs + ext_alpn + ext_sess)

    ciphers = bytes.fromhex(
        "1301130213031303c02bc02fc02cc030cca9cca8c013c014009c009d002f0035"
    )
    body = (
        b"\x03\x03"                                   # TLS 1.2 client_version
        + os.urandom(32)                              # random
        + b"\x20" + os.urandom(32)                    # session_id
        + len(ciphers).to_bytes(2, "big") + ciphers
        + b"\x01\x00"                                 # compression: null
        + len(extensions).to_bytes(2, "big") + extensions
    )
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + len(handshake).to_bytes(2, "big") + handshake


# --- HTTP -------------------------------------------------------------------

HTTP_METHODS = (b"GET ", b"POST", b"HEAD", b"PUT ", b"OPTI", b"DELE", b"PATC", b"CONN")


def looks_like_http(data: bytes) -> bool:
    return data[:4] in HTTP_METHODS


def parse_http_host(data: bytes) -> tuple[str | None, int, int]:
    """(host, host_değer_ofseti, host_değer_uzunluğu) döndür."""
    head = data[:2048]
    lower = head.lower()
    idx = lower.find(b"\nhost:")
    if idx < 0:
        if lower.startswith(b"host:"):
            idx = -1
        else:
            return None, 0, 0
    start = idx + 6
    while start < len(head) and head[start] in (0x20, 0x09):
        start += 1
    end = start
    while end < len(head) and head[end] not in (0x0D, 0x0A):
        end += 1
    host = head[start:end].decode("ascii", errors="replace").strip()
    if ":" in host:
        host = host.split(":", 1)[0]
    return (host or None), start, end - start


def http_mangle_host(data: bytes) -> bytes:
    """``Host:`` başlığını RFC'ye uygun ama DPI imzalarını bozacak şekilde yaz.

    - başlık adının harf büyüklüğü değiştirilir (hoSt:)
    - iki nokta sonrası boşluk yerine sekme konur (HTTP/1.1 LWS olarak geçerli)
    """
    lower = data.lower()
    idx = lower.find(b"\nhost:")
    if idx < 0:
        return data
    out = bytearray(data)
    out[idx + 1:idx + 5] = b"hOsT"
    pos = idx + 6
    if pos < len(out) and out[pos] == 0x20:
        out[pos] = 0x09
    return bytes(out)
