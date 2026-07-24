"""Ham soketle sahte paket enjeksiyonu.

``fake`` stratejisi, gerçek ClientHello'dan hemen önce **aynı sıra
numarasını taşıyan** sahte bir ClientHello'yu düşük TTL ile tel üzerine
koyar. Paket yol üstündeki DPI cihazına ulaşır ama TTL'i tükendiği için
hedef sunucuya varmaz. Sunucu yalnızca gerçek segmenti görür, DPI ise
zararsız bir SNI görüp bağlantıyı serbest bırakır.

Sahte paket normal soketten gönderilemez: çekirdek onu sıra numarasına
işler ve yeniden iletir. Bu yüzden paket ham soketle elle kurulur.
Gönderim sırası numarası, sokete geçici olarak TCP_REPAIR uygulanarak
okunur (yalnızca *okuma*; çekirdek kurulu bağlantıda yazmaya izin vermez).
"""

from __future__ import annotations

import logging
import socket
import struct

from .util import mark_socket

log = logging.getLogger("dpibypass.rawfake")

TCP_REPAIR = 19
TCP_REPAIR_QUEUE = 20
TCP_QUEUE_SEQ = 21
TCP_NO_QUEUE = 0
TCP_RECV_QUEUE = 1
TCP_SEND_QUEUE = 2

FIN, SYN, RST, PSH, ACK, URG = 0x01, 0x02, 0x04, 0x08, 0x10, 0x20


def read_sequence_numbers(sock: socket.socket) -> tuple[int, int] | None:
    """(gönderim sıra no, alım sıra no) — TCP_REPAIR ile geçici okuma."""
    opened = False
    try:
        sock.setsockopt(socket.IPPROTO_TCP, TCP_REPAIR, 1)
        opened = True
        sock.setsockopt(socket.IPPROTO_TCP, TCP_REPAIR_QUEUE, TCP_SEND_QUEUE)
        snd = sock.getsockopt(socket.IPPROTO_TCP, TCP_QUEUE_SEQ)
        sock.setsockopt(socket.IPPROTO_TCP, TCP_REPAIR_QUEUE, TCP_RECV_QUEUE)
        rcv = sock.getsockopt(socket.IPPROTO_TCP, TCP_QUEUE_SEQ)
        return snd & 0xFFFFFFFF, rcv & 0xFFFFFFFF
    except OSError as exc:
        log.debug("sıra numarası okunamadı: %s", exc)
        return None
    finally:
        if opened:
            try:
                sock.setsockopt(socket.IPPROTO_TCP, TCP_REPAIR_QUEUE, TCP_NO_QUEUE)
                sock.setsockopt(socket.IPPROTO_TCP, TCP_REPAIR, 0)
            except OSError:
                pass


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) | data[i + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def build_ipv4_tcp(src_ip: str, src_port: int, dst_ip: str, dst_port: int,
                   seq: int, ack: int, payload: bytes, ttl: int,
                   flags: int = PSH | ACK, window: int = 64240) -> bytes:
    """IP + TCP başlıklı tam bir paket kur."""
    src = socket.inet_aton(src_ip)
    dst = socket.inet_aton(dst_ip)

    tcp_header = struct.pack(
        "!HHIIBBHHH",
        src_port, dst_port, seq & 0xFFFFFFFF, ack & 0xFFFFFFFF,
        5 << 4,            # veri ofseti: 5 kelime (seçenek yok)
        flags, window, 0, 0,
    )
    pseudo = src + dst + struct.pack("!BBH", 0, socket.IPPROTO_TCP,
                                     len(tcp_header) + len(payload))
    checksum = _checksum(pseudo + tcp_header + payload)
    tcp_header = tcp_header[:16] + struct.pack("!H", checksum) + tcp_header[18:]

    total_length = 20 + len(tcp_header) + len(payload)
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, total_length,
        0, 0x4000,          # kimlik, DF bayrağı
        ttl, socket.IPPROTO_TCP, 0,
        src, dst,
    )
    ip_checksum = _checksum(ip_header)
    ip_header = ip_header[:10] + struct.pack("!H", ip_checksum) + ip_header[12:]
    return ip_header + tcp_header + payload


_raw_socket: socket.socket | None = None


def _get_raw_socket() -> socket.socket | None:
    global _raw_socket
    if _raw_socket is not None:
        return _raw_socket
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        mark_socket(sock)
        _raw_socket = sock
        return sock
    except OSError as exc:
        log.info("ham soket açılamadı (%s); sahte paket stratejileri kullanılamaz",
                 exc)
        return None


def available() -> bool:
    return _get_raw_socket() is not None


def send_fake(sock: socket.socket, payload: bytes, ttl: int) -> bool:
    """Kurulu bağlantının sıra numarasıyla sahte bir veri segmenti gönder."""
    if sock.family != socket.AF_INET:
        return False           # IPv6 için ham enjeksiyon desteklenmiyor
    raw = _get_raw_socket()
    if raw is None:
        return False
    seqs = read_sequence_numbers(sock)
    if seqs is None:
        return False
    snd_seq, rcv_seq = seqs
    try:
        src_ip, src_port = sock.getsockname()[:2]
        dst_ip, dst_port = sock.getpeername()[:2]
    except OSError:
        return False

    packet = build_ipv4_tcp(src_ip, src_port, dst_ip, dst_port,
                            snd_seq, rcv_seq, payload, ttl)
    try:
        raw.sendto(packet, (dst_ip, 0))
        return True
    except OSError as exc:
        log.debug("sahte paket gönderilemedi: %s", exc)
        return False
