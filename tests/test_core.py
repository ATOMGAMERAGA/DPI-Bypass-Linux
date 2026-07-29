"""Çekirdek mantık testleri.

Ağ gerektirmeyen her şey burada doğrulanır: ClientHello ayrıştırma, TLS
kayıt parçalama, strateji uygulaması (gerçek soketler üzerinden, yerel
geri döngüde), DNS tel biçimi ve operatör eşleştirme.

Çalıştırmak için:  python3 -m unittest discover -s tests -v
"""

from __future__ import annotations

import asyncio
import os
import shutil
import socket
import ssl
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))), "src"))

from dpibypass import desync, isps, resolver, strategies, tlsutil  # noqa: E402
from dpibypass.config import Config  # noqa: E402
from dpibypass.util import domain_matches  # noqa: E402


def real_client_hello(hostname: str = "discord.com") -> bytes:
    """Python'un TLS yığınından gerçek bir ClientHello üret."""
    context = ssl.create_default_context()
    incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
    obj = context.wrap_bio(incoming, outgoing, server_hostname=hostname)
    try:
        obj.do_handshake()
    except ssl.SSLWantReadError:
        pass
    return outgoing.read()


class TestClientHello(unittest.TestCase):
    def test_sni_parsed(self):
        data = real_client_hello("discord.com")
        info = tlsutil.parse_client_hello(data)
        self.assertIsNotNone(info)
        self.assertEqual(info.sni, "discord.com")
        self.assertEqual(data[info.sni_offset:info.sni_offset + info.sni_length],
                         b"discord.com")

    def test_not_tls(self):
        self.assertIsNone(tlsutil.parse_client_hello(b"GET / HTTP/1.1\r\n\r\n"))
        self.assertFalse(tlsutil.looks_like_tls(b"\x16\x03"))

    def test_fake_client_hello_is_parseable(self):
        fake = tlsutil.build_fake_client_hello("www.microsoft.com")
        info = tlsutil.parse_client_hello(fake)
        self.assertIsNotNone(info)
        self.assertEqual(info.sni, "www.microsoft.com")

    def test_record_split_preserves_handshake(self):
        data = real_client_hello("discord.com")
        info = tlsutil.parse_client_hello(data)
        cut = info.sni_offset + info.sni_length // 2 - info.payload_offset
        split, cuts = tlsutil.split_tls_records(data, [cut])
        self.assertEqual(cuts, [cut])
        self.assertEqual(len(split), len(data) + 5)

        # Kayıtları tekrar birleştir: özgün el sıkışma baytları çıkmalı
        payload = b""
        pos = 0
        records = 0
        while pos < len(split):
            self.assertEqual(split[pos], 0x16)
            length = struct.unpack_from("!H", split, pos + 3)[0]
            payload += split[pos + 5:pos + 5 + length]
            pos += 5 + length
            records += 1
        self.assertEqual(records, 2)
        self.assertEqual(payload, data[5:])

    def test_shift_offset(self):
        self.assertEqual(tlsutil.shift_offset(100, []), 100)
        # 40. bayttan bölündüyse, 100. mutlak ofset 5 bayt kayar
        self.assertEqual(tlsutil.shift_offset(100, [40]), 105)
        self.assertEqual(tlsutil.shift_offset(100, [200]), 100)

    def test_http_host(self):
        request = b"GET /api HTTP/1.1\r\nHost: discord.com\r\nAccept: */*\r\n\r\n"
        host, offset, length = tlsutil.parse_http_host(request)
        self.assertEqual(host, "discord.com")
        self.assertEqual(request[offset:offset + length], b"discord.com")
        mangled = tlsutil.http_mangle_host(request)
        self.assertIn(b"hOsT:", mangled)
        self.assertEqual(len(mangled), len(request))


class TestStrategyPreparation(unittest.TestCase):
    def test_every_strategy_prepares(self):
        data = real_client_hello("discord.com")
        for strategy in strategies.CATALOG:
            with self.subTest(strategy=strategy.name):
                payload, splits, host = desync.prepare(data, strategy)
                self.assertEqual(host, "discord.com")
                self.assertTrue(len(payload) >= len(data))
                for pos in splits:
                    self.assertGreater(pos, 0)
                    self.assertLess(pos, len(payload))
                if strategy.split and strategy.mode != "none":
                    self.assertTrue(splits, f"{strategy.name} bölme üretmedi")

    def test_split_position_inside_sni(self):
        data = real_client_hello("discord.com")
        strategy = strategies.BY_NAME["split-snimid"]
        payload, splits, _ = desync.prepare(data, strategy)
        info = tlsutil.parse_client_hello(payload)
        self.assertEqual(len(splits), 1)
        self.assertGreater(splits[0], info.sni_offset)
        self.assertLess(splits[0], info.sni_offset + info.sni_length)

    def test_chunks_roundtrip(self):
        data = real_client_hello("discord.com")
        for strategy in strategies.CATALOG:
            payload, splits, _ = desync.prepare(data, strategy)
            parts = desync._chunks(payload, splits)
            self.assertEqual(b"".join(parts), payload, strategy.name)

    def test_http_strategy(self):
        request = b"GET / HTTP/1.1\r\nHost: discord.com\r\nAccept: */*\r\n\r\n"
        strategy = strategies.BY_NAME["split-snimid"]
        payload, splits, host = desync.prepare(request, strategy)
        self.assertEqual(host, "discord.com")
        self.assertEqual(len(splits), 1)
        self.assertIn(b"hOsT", payload)


class EchoServer:
    """Gelen tüm baytları biriktiren küçük TCP sunucusu."""

    def __init__(self) -> None:
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(4)
        self.address = self.sock.getsockname()
        self.received = b""

    async def accept_once(self, expected: int) -> bytes:
        loop = asyncio.get_running_loop()
        self.sock.setblocking(False)
        conn, _ = await loop.sock_accept(self.sock)
        conn.setblocking(False)
        data = b""
        while len(data) < expected:
            try:
                chunk = await asyncio.wait_for(loop.sock_recv(conn, 65536), 5)
            except asyncio.TimeoutError:
                break
            if not chunk:
                break
            data += chunk
        conn.close()
        return data

    def close(self) -> None:
        self.sock.close()


class TestWireLevel(unittest.IsolatedAsyncioTestCase):
    """Stratejiler gerçek soketlerde veriyi bozmadan iletiyor mu?"""

    async def _run_strategy(self, strategy) -> tuple[bytes, bytes]:
        data = real_client_hello("discord.com")
        expected, _splits, _host = desync.prepare(data, strategy)
        server = EchoServer()
        loop = asyncio.get_running_loop()
        try:
            client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client.setblocking(False)
            receiver = asyncio.ensure_future(server.accept_once(len(expected)))
            await loop.sock_connect(client, server.address)
            await desync.send_first_payload(loop, client, data, strategy)
            received = await receiver
            client.close()
            return expected, received
        finally:
            server.close()

    async def test_all_strategies_deliver_intact(self):
        for strategy in strategies.CATALOG:
            if not desync.strategy_available(strategy):
                continue
            if strategy.mode == "fake":
                # Sahte paket kipi sıra numarası oyunu yapar; ayrı test edilir.
                continue
            with self.subTest(strategy=strategy.name):
                expected, received = await self._run_strategy(strategy)
                self.assertEqual(received, expected,
                                 f"{strategy.name} veriyi bozdu")

    async def test_oob_byte_is_not_delivered(self):
        """Bant dışı bayt, hedef sunucunun akışına karışmamalı."""
        strategy = strategies.BY_NAME["oob-snimid"]
        expected, received = await self._run_strategy(strategy)
        self.assertEqual(len(received), len(expected))
        self.assertNotIn(b"\x61" * 1, received[len(expected):])


class TestRawFake(unittest.TestCase):
    """Ham soketle üretilen sahte paket çekirdek tarafından kabul ediliyor mu?

    TTL yeterince yüksek tutulup geri döngüde denenir: sahte paket sunucuya
    ulaşır ve *gerçek* veri aynı sıra numarasını taşıdığı için yinelenmiş
    segment sayılıp düşürülür. Sunucunun tam olarak sahte içeriği görmesi,
    IP/TCP sağlama toplamlarının ve sıra numarasının doğru kurulduğunu
    kanıtlar.
    """

    def test_fake_packet_accepted_by_kernel(self):
        from dpibypass import rawfake

        if not rawfake.available():
            self.skipTest("ham soket açılamıyor (CAP_NET_RAW gerekir)")

        server = socket.socket()
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        client = socket.create_connection(server.getsockname())
        conn, _ = server.accept()
        try:
            if rawfake.read_sequence_numbers(client) is None:
                self.skipTest("sıra numarası okunamıyor")
            fake = b"SAHTE-CLIENTHELLO"
            self.assertTrue(rawfake.send_fake(client, fake, ttl=64))
            conn.settimeout(2.0)
            self.assertEqual(conn.recv(4096), fake)
        finally:
            for sock in (conn, client, server):
                sock.close()

    def test_checksum_known_value(self):
        from dpibypass.rawfake import _checksum

        # RFC 1071'deki örnek veri ve beklenen tamamlayıcı toplam
        self.assertEqual(_checksum(b"\x00\x01\xf2\x03\xf4\xf5\xf6\xf7"), 0x220D)


class TestDnsWire(unittest.TestCase):
    def test_query_roundtrip(self):
        wire = resolver.build_query("discord.com", resolver.TYPE_A, qid=0x1234)
        message = resolver.parse_message(wire)
        self.assertEqual(message.qid, 0x1234)
        self.assertEqual(message.question, "discord.com")
        self.assertEqual(message.qtype, resolver.TYPE_A)

    def test_answer_parsing(self):
        # elle kurulmuş bir yanıt: discord.com A 1.2.3.4
        header = struct.pack("!HHHHHH", 1, 0x8180, 1, 1, 0, 0)
        question = resolver.encode_name("discord.com") + struct.pack("!HH", 1, 1)
        answer = (b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 300, 4)
                  + socket.inet_aton("1.2.3.4"))
        message = resolver.parse_message(header + question + answer)
        self.assertEqual(message.rcode, 0)
        self.assertEqual(message.addresses(), ["1.2.3.4"])
        self.assertEqual(message.min_ttl(), 300)

    def test_txt_parsing(self):
        text = b"\x2d9121 | 88.240.0.0/13 | TR | ripencc | 2001-06-19"
        header = struct.pack("!HHHHHH", 2, 0x8180, 1, 1, 0, 0)
        question = resolver.encode_name("x.origin.asn.cymru.com") + \
            struct.pack("!HH", 16, 1)
        answer = (b"\xc0\x0c" + struct.pack("!HHIH", 16, 1, 60, len(text)) + text)
        message = resolver.parse_message(header + question + answer)
        self.assertEqual(message.texts()[0].split("|")[0].strip(), "9121")


class TestIspMatching(unittest.TestCase):
    def test_turk_telekom_home(self):
        info = isps.LinkInfo(interface="enp3s0", link_type="ethernet",
                             asn=9121, as_name="TURK-TELEKOM Turk Telekomunikasyon")
        profile, confidence = isps.match_profile(info)
        self.assertEqual(profile.id, "tt-home")
        self.assertGreater(confidence, 0.5)

    def test_turkcell_mobile(self):
        info = isps.LinkInfo(interface="wwan0", link_type="mobile",
                             asn=16135, as_name="TURKCELL-AS Turkcell Iletisim")
        profile, _ = isps.match_profile(info)
        self.assertEqual(profile.id, "turkcell-mobile")

    def test_superbox_by_ssid(self):
        info = isps.LinkInfo(interface="wlp2s0", link_type="wifi", ssid="SUPERBOX_A1B2",
                             asn=16135, as_name="TURKCELL-AS Turkcell")
        profile, _ = isps.match_profile(info)
        self.assertEqual(profile.id, "superbox")

    def test_vodafone_hotspot(self):
        info = isps.LinkInfo(interface="wlp2s0", link_type="wifi",
                             ssid="VodafoneWiFi", asn=15897,
                             as_name="VODAFONE-NET Vodafone Net Iletisim")
        profile, _ = isps.match_profile(info)
        self.assertIn(profile.id, ("vodafone-hotspot", "vodafone-home"))

    def test_unknown_operator(self):
        info = isps.LinkInfo(interface="eth0", link_type="ethernet",
                             asn=15169, as_name="GOOGLE")
        profile, confidence = isps.match_profile(info)
        self.assertEqual(profile.id, "unknown")
        self.assertEqual(confidence, 0.0)

    def test_all_profile_strategies_exist(self):
        for profile in isps.PROFILES:
            for name in profile.strategies:
                self.assertIn(name, strategies.BY_NAME,
                              f"{profile.id} bilinmeyen yöntem: {name}")

    def test_profile_labels_match_screenshot(self):
        expected = [
            "Türk Telekom (Mobil)", "Türk Telekom Evde İnternet",
            "Türk Telekom Hotspot", "Redbox (Türk Telekom)", "Turkcell (Mobil)",
            "Turkcell Superonline", "Superbox (Turkcell FWA)", "Turkcell Hotspot",
            "Vodafone (Mobil)", "Vodafone Evde İnternet", "Vodafone Hotspot",
            "TurkNet", "Diğer / Bilinmiyor",
        ]
        self.assertEqual([p.label for p in isps.PROFILES], expected)


class TestHelpers(unittest.TestCase):
    def test_domain_matches(self):
        domains = ["discord.com", "discordapp.net"]
        self.assertTrue(domain_matches("discord.com", domains))
        self.assertTrue(domain_matches("cdn.discordapp.net", domains))
        self.assertTrue(domain_matches("a.b.discord.com", domains))
        self.assertFalse(domain_matches("notdiscord.com", domains))
        self.assertFalse(domain_matches("", domains))

    def test_config_domains(self):
        config = Config(path="/nonexistent/config.json")
        config.data["extra_domains"] = ["ornek.com", "discord.com"]
        config.data["disabled_domains"] = ["pornhub.com"]
        domains = config.domains()
        self.assertIn("ornek.com", domains)
        self.assertNotIn("pornhub.com", domains)
        self.assertEqual(len(domains), len(set(domains)))

    def test_strategy_order(self):
        order = strategies.order_for(["oob-snimid", "yok-boyle-bir-sey"])
        self.assertEqual(order[0].name, "oob-snimid")
        self.assertNotIn("none", [s.name for s in order])
        self.assertEqual(len(order), len(strategies.CATALOG) - 1)


# --------------------------------------------------------------------------- #
# Vodafone sınırsız kipi
# --------------------------------------------------------------------------- #

def test_ttl_guard_desync_stratejilerinin_uzerinde():
    """Vodafone TTL koruması, hiçbir desync stratejisini kapsamamalı."""
    from dpibypass import strategies
    from dpibypass.constants import VODAFONE_TTL_GUARD, VODAFONE_TTL_VALUE
    en_yuksek = max(s.ttl for s in strategies.CATALOG)
    assert en_yuksek < VODAFONE_TTL_GUARD, (
        f"Bir strateji TTL={en_yuksek} kullanıyor; koruma eşiği "
        f"{VODAFONE_TTL_GUARD}. Eşiği yükselt, yoksa Vodafone modu "
        f"atlatmayı bozar."
    )
    assert VODAFONE_TTL_GUARD < VODAFONE_TTL_VALUE


class TestVodafoneGuard(unittest.TestCase):
    """Koruma eşiği testi; unittest ile de çalışsın diye sarmalanmıştır."""

    def test_ttl_guard_above_every_desync_strategy(self):
        test_ttl_guard_desync_stratejilerinin_uzerinde()

    def test_guard_below_normal_system_ttl(self):
        from dpibypass.constants import VODAFONE_TTL_GUARD
        # Normal işletim sistemi TTL'i 64'tür; eşik bunun altında kalmalı ki
        # sıradan paketler yeniden yazılabilsin.
        self.assertLess(VODAFONE_TTL_GUARD, 64)


class TestVodafoneConfig(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="dpibypass-test-")
        self.config = Config(path=os.path.join(self.tmp, "config.json"))

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_defaults_present_with_types(self):
        from dpibypass.config import DEFAULTS
        self.assertIs(DEFAULTS["vodafone_mode"], False)
        self.assertEqual(DEFAULTS["vodafone_networks"], [])
        self.assertIsInstance(DEFAULTS["vodafone_ttl"], int)
        self.assertIs(DEFAULTS["vodafone_disable_ipv6"], True)

    def test_defaults_ttl_matches_constant(self):
        from dpibypass.config import DEFAULTS
        from dpibypass.constants import VODAFONE_TTL_VALUE
        self.assertEqual(DEFAULTS["vodafone_ttl"], VODAFONE_TTL_VALUE)

    def test_add_has_remove_network(self):
        self.assertFalse(self.config.vodafone_has_network("abc"))
        self.config.vodafone_add_network("abc", "Telefonum", "wlan0")
        self.assertTrue(self.config.vodafone_has_network("abc"))
        entry = self.config.vodafone_networks()[0]
        self.assertEqual(entry["name"], "Telefonum")
        self.assertEqual(entry["interface"], "wlan0")

        self.config.vodafone_remove_network("abc")
        self.assertFalse(self.config.vodafone_has_network("abc"))

    def test_empty_key_ignored(self):
        self.config.vodafone_add_network("", "Adsız", "wlan0")
        self.assertEqual(self.config.vodafone_networks(), [])
        self.assertFalse(self.config.vodafone_has_network(""))

    def test_same_network_not_duplicated(self):
        self.config.vodafone_add_network("abc", "Telefonum", "wlan0")
        self.config.vodafone_add_network("abc", "Telefonum", "wlp2s0")
        nets = self.config.vodafone_networks()
        self.assertEqual(len(nets), 1)
        self.assertEqual(nets[0]["interface"], "wlp2s0")

    def test_at_most_ten_networks_oldest_dropped(self):
        from dpibypass.constants import VODAFONE_MAX_NETWORKS
        for index in range(VODAFONE_MAX_NETWORKS + 2):
            self.config.vodafone_add_network(f"key{index}", f"Ağ {index}",
                                             "wlan0")
        nets = self.config.vodafone_networks()
        self.assertEqual(len(nets), VODAFONE_MAX_NETWORKS)
        self.assertFalse(self.config.vodafone_has_network("key0"))
        self.assertFalse(self.config.vodafone_has_network("key1"))
        self.assertTrue(self.config.vodafone_has_network(
            f"key{VODAFONE_MAX_NETWORKS + 1}"))

    def test_survives_reload_from_disk(self):
        self.config.vodafone_add_network("abc", "Telefonum", "wlan0")
        self.config.update({"vodafone_mode": True})
        again = Config(path=self.config.path)
        self.assertTrue(again["vodafone_mode"])
        self.assertTrue(again.vodafone_has_network("abc"))

    def test_broken_entries_ignored(self):
        self.config.data["vodafone_networks"] = [
            {"key": "iyi", "name": "Ağ", "interface": "wlan0"},
            {"name": "anahtarsız"}, "metin", None, 42,
        ]
        nets = self.config.vodafone_networks()
        self.assertEqual(len(nets), 1)
        self.assertEqual(nets[0]["key"], "iyi")


class TestVodafoneRules(unittest.TestCase):
    """Kural metni üretimi — gerçek nft çalıştırmadan doğrulanır."""

    def setUp(self):
        from dpibypass.vodafone import VodafoneMode
        self.mode = VodafoneMode()
        self.script = self.mode._build_nft_script("test0")

    def test_script_contains_required_parts(self):
        for needle in ('oifname "test0"',
                       "ip ttl >= 32",
                       "ip ttl set 65",
                       "ip6 hoplimit >= 32",
                       "ip6 hoplimit set 65",
                       "counter",
                       "table inet dpibypass_ttl"):
            self.assertIn(needle, self.script, f"kural metninde yok: {needle}")

    def test_counter_comes_before_set(self):
        for line in self.script.splitlines():
            if "counter" in line:
                self.assertLess(line.index("counter"), line.index(" set "),
                                "counter, set işleminden önce gelmeli")

    def test_idempotent_table_pattern(self):
        # "table … / delete table … / table … {" kalıbı: tablo olsa da
        # olmasa da çalışır.
        head = self.script.splitlines()[:3]
        self.assertEqual(head[0], "table inet dpibypass_ttl")
        self.assertEqual(head[1], "delete table inet dpibypass_ttl")
        self.assertTrue(head[2].startswith("table inet dpibypass_ttl {"))

    def test_postrouting_priority_after_srcnat(self):
        self.assertIn("hook postrouting priority 300", self.script)

    def test_no_unconditional_ttl_set(self):
        """Eşiksiz bir 'ip ttl set' kuralı atlatmayı bozardı."""
        for line in self.script.splitlines():
            if "ttl set" in line or "hoplimit set" in line:
                self.assertIn(">=", line,
                              "TTL yeniden yazımı eşiksiz yazılmış")

    def test_guard_and_value_come_from_constants(self):
        from dpibypass.constants import (VODAFONE_TTL_GUARD,
                                         VODAFONE_TTL_VALUE)
        self.assertEqual(self.mode.guard, VODAFONE_TTL_GUARD)
        self.assertEqual(self.mode.ttl, VODAFONE_TTL_VALUE)

    def test_invalid_interface_names_rejected(self):
        from dpibypass.vodafone import VodafoneError
        for bad in ("eth0; rm -rf /", "a" * 20, "", "wlan0\nfoo", "wlan0\n",
                    "wlan 0", "wlan0'", 'wlan0"', "../etc", None, 5):
            with self.subTest(iface=bad):
                with self.assertRaises(VodafoneError):
                    self.mode._build_nft_script(bad)

    def test_valid_interface_names_accepted(self):
        for good in ("wlan0", "wlp2s0", "enp0s31f6", "usb0", "eth0.100",
                     "br-lan", "a" * 15):
            with self.subTest(iface=good):
                self.assertIn(f'oifname "{good}"',
                              self.mode._build_nft_script(good))

    def test_ttl_must_stay_above_guard(self):
        from dpibypass.vodafone import VodafoneError, VodafoneMode
        for bad in (0, 8, 32, 256, -1, "abc"):
            with self.subTest(ttl=bad):
                with self.assertRaises(VodafoneError):
                    VodafoneMode(ttl=bad)
        self.assertEqual(VodafoneMode(ttl=65).ttl, 65)
        self.assertEqual(VodafoneMode(ttl=129).ttl, 129)


class TestVodafoneTeardown(unittest.TestCase):
    """Kaldırma yollarının gerilemesini önleyen testler."""

    @staticmethod
    def _fake_run(calls, fail_when=None):
        """util.run yerine geçen, komutları kaydeden sahte çalıştırıcı."""
        import subprocess as sp

        def runner(cmd, **_kwargs):
            cmd = list(cmd)
            calls.append(cmd)
            code = 0
            if "-C" in cmd:
                code = 1          # bağlantı kuralı henüz yok
            if fail_when and fail_when(cmd):
                code = 3
            return sp.CompletedProcess(cmd, code, "", "sahte hata")
        return runner

    def test_ipv6_failure_keeps_ipv4_rule(self):
        """ip6tables başarısız olursa IPv4 zinciri silinmemeli."""
        from unittest import mock
        from dpibypass import vodafone as vmod

        calls: list[list[str]] = []
        failing = lambda cmd: cmd[0] == "ip6tables" and "-A" in cmd
        with mock.patch.object(vmod, "run", self._fake_run(calls, failing)), \
                mock.patch.object(vmod, "which", lambda name: "/sbin/" + name):
            mode = vmod.VodafoneMode()
            mode._backend, mode._backend_probed = "iptables", True
            mode.apply("wlan0", disable_ipv6=False)

        # IPv4 kuralının kurulduğu an
        installed = max(i for i, c in enumerate(calls)
                        if c[0] == "iptables" and "-A" in c
                        and "DPIBYPASS_TTL" in c)
        wiped = [c for c in calls[installed:]
                 if c[0] == "iptables" and ("-X" in c or "-F" in c)]
        self.assertEqual(wiped, [],
                         "IPv6 hatası IPv4 zincirini de silmiş: %r" % (wiped,))
        self.assertTrue(mode.active)

    def test_clear_failure_does_not_report_disabled(self):
        """nft kaldırması başarısızsa mod 'kapalı' gösterilmemeli."""
        import subprocess as sp
        from unittest import mock
        from dpibypass import vodafone as vmod

        mode = vmod.VodafoneMode()
        mode._backend, mode._backend_probed = "nft", True
        mode.active, mode.interface = True, "wlan0"

        def failing(cmd, **_kwargs):
            return sp.CompletedProcess(list(cmd), 1, "", "nft hatası")

        with mock.patch.object(vmod, "run", failing):
            self.assertFalse(mode.clear())
        self.assertTrue(mode.active,
                        "kural kalkmadığı hâlde mod kapalı gösteriliyor")

    def test_clear_success_reports_disabled(self):
        import subprocess as sp
        from unittest import mock
        from dpibypass import vodafone as vmod

        mode = vmod.VodafoneMode()
        mode._backend, mode._backend_probed = "nft", True
        mode.active, mode.interface = True, "wlan0"

        with mock.patch.object(
                vmod, "run",
                lambda cmd, **k: sp.CompletedProcess(list(cmd), 0, "", "")):
            self.assertTrue(mode.clear())
        self.assertFalse(mode.active)
        self.assertEqual(mode.interface, "")


class TestVodafoneDaemonTtl(unittest.IsolatedAsyncioTestCase):
    """'enabled' dalı return ile çıktığı için TTL eşitlemesi atlanmamalı."""

    async def test_ttl_synced_when_enabled_changes_together(self):
        import subprocess as sp
        from unittest import mock
        from dpibypass import daemon as dmod, vodafone as vmod

        tmp = tempfile.mkdtemp(prefix="dpibypass-daemon-")
        self.addCleanup(shutil.rmtree, tmp, True)

        ok = lambda cmd, **k: sp.CompletedProcess(list(cmd), 0, "", "")
        with mock.patch.object(vmod, "run", ok), \
                mock.patch.object(vmod, "which", lambda name: None):
            daemon = dmod.Daemon.__new__(dmod.Daemon)
            daemon.config = Config(path=os.path.join(tmp, "config.json"))
            daemon.config.update({"enabled": True, "vodafone_ttl": 65})
            daemon.vodafone = vmod.VodafoneMode()
            daemon.firewall = mock.Mock()
            daemon.proxy = mock.Mock(stop=mock.AsyncMock())
            daemon.dns_server = mock.Mock(stop=mock.AsyncMock())
            daemon.active_strategy = None

            # İki ayar tek istekte değişiyor (cli.py 'set' bunu böyle yollar)
            daemon.config.update({"enabled": False, "vodafone_ttl": 100})
            await daemon._apply_config_change(["enabled", "vodafone_ttl"])

        self.assertEqual(daemon.vodafone.ttl, 100,
                         "'enabled' ile birlikte değişince TTL eşitlenmedi")

    async def test_invalid_ttl_is_reverted_in_config(self):
        import subprocess as sp
        from unittest import mock
        from dpibypass import daemon as dmod, vodafone as vmod

        tmp = tempfile.mkdtemp(prefix="dpibypass-daemon-")
        self.addCleanup(shutil.rmtree, tmp, True)

        ok = lambda cmd, **k: sp.CompletedProcess(list(cmd), 0, "", "")
        with mock.patch.object(vmod, "run", ok), \
                mock.patch.object(vmod, "which", lambda name: None):
            daemon = dmod.Daemon.__new__(dmod.Daemon)
            daemon.config = Config(path=os.path.join(tmp, "config.json"))
            daemon.vodafone = vmod.VodafoneMode()
            daemon.network = None

            daemon.config.update({"vodafone_ttl": 8})   # koruma eşiğinin altı
            await daemon._apply_config_change(["vodafone_ttl"])

        self.assertEqual(daemon.vodafone.ttl, 65)
        self.assertEqual(daemon.config["vodafone_ttl"], 65,
                         "geçersiz TTL yapılandırmada bırakılmış")


if __name__ == "__main__":
    unittest.main(verbosity=2)
