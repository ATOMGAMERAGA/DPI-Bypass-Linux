"""Ping düşürme kipinin ağdan ve root yetkisinden bağımsız testleri.

Aday motoru gerçek komut çalıştırmaz: ``FakeRunner`` sistemin durumunu
(``iw``/``tc``/``ethtool``/``ip``) taklit eder, ``StateProbe`` ise ölçümü o
duruma göre üretir. Motor her adayı kontrol ölçümüyle iç içe (A/B/A) sınadığı
için ölçüm sırası önceden bilinemez; sonucu duruma bağlamak testleri
sıralamadan bağımsız kılar.

Bu dosyanın merkezindeki soru şudur: **motor uydurulmuş bir kazancı reddediyor
mu, gerçek ama küçük bir kazancı görebiliyor mu?**
"""

from __future__ import annotations

import asyncio
import json
import os
import random
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))), "src"))

from dpibypass import cli  # noqa: E402
from dpibypass.config import Config, DEFAULTS  # noqa: E402
from dpibypass.latency import (analysis, engine as engine_mod,  # noqa: E402
                               load as loadmod, qdisc as qdiscmod)
from dpibypass.latency import (ActionSnapshot, EndpointSamples,  # noqa: E402
                               EndpointSpec, EndpointStats, LatencyError,
                               LatencyMeasurement, LatencyOptimizer,
                               LatencyProbe, LatencyProfiles, LatencySettings,
                               LatencySnapshot, LatencyStats, LoadBudget,
                               LoadTarget, METHOD_ICMP, METHOD_TCP_CONNECT,
                               ProfileContext, ROLE_REFERENCE, ROLE_USER,
                               SnapshotCorrupt, SqmCapacity, SqmManager,
                               SqmState, TargetSpec, parse_ping)
from dpibypass.netmon import NetworkFingerprint  # noqa: E402


def network(interface: str = "wlan0", link_type: str = "wifi",
            gateway: str = "192.0.2.1", ssid: str = "Test") -> NetworkFingerprint:
    return NetworkFingerprint(interface=interface, gateway=gateway,
                              link_type=link_type, ssid=ssid)


def spec(address: str = "203.0.113.10", role: str = ROLE_USER,
         interface: str = "wlan0", method: str = METHOD_ICMP,
         port: int = 0, source: str = "192.0.2.5") -> EndpointSpec:
    return EndpointSpec(host=address, address=address, family="ipv4",
                        port=port, method=method, interface=interface,
                        ifindex=7, source=source, role=role)


def samples(endpoint: EndpointSpec, values, sent: int = 8) -> EndpointSamples:
    return EndpointSamples(spec=endpoint, rtt_ms=list(values), sent=sent)


def measurement_of(pairs, condition: str = "idle",
                   sent: int = 8) -> LatencyMeasurement:
    """``pairs``: ``[(EndpointSpec, [rtt, ...]), ...]``"""
    return LatencyMeasurement.from_blocks(
        [samples(endpoint, values, sent) for endpoint, values in pairs],
        condition=condition)


def flat(endpoint: EndpointSpec, value: float, count: int = 8):
    return (endpoint, [value] * count)


# --------------------------------------------------------------------------- #
# sahte sistem
# --------------------------------------------------------------------------- #
class FakeRunner:
    """iw / tc / ethtool / ip davranışının test kopyası."""

    def __init__(self, tools=("iw", "tc", "ip")) -> None:
        self.tools = set(tools)
        self.calls: list = []
        self.power = {"wlan0": "on", "wlan1": "on"}
        self.power_reverts = set()      # sürücü ayarı geri alan arayüzler
        self.qdisc = {}                 # iface -> [node dict]
        self.set_qdisc("wlan0", "pfifo_fast")
        self.set_qdisc("wlan1", "pfifo_fast")
        self.set_qdisc("eth0", "pfifo_fast")
        self.filters = {}
        self.classes = {}
        self.eee = {}
        self.eee_supported = True
        self.eee_reverts = set()
        self.coalesce = {}
        self.coalesce_supported = True
        self.coalesce_writable = True
        self.fail_qdisc_kinds = set()
        self.qdisc_change_rc = 0
        self.route_dev = {}             # address -> iface (varsayılan: wlan0)
        self.default_dev = "wlan0"
        self.ifb_devices = set()
        self.ifb_supported = True
        self.ingress_busy = False
        self.cake_bandwidth_ignored = False

    # -- durum kurucular ---------------------------------------------------
    def set_qdisc(self, iface: str, kind: str, options=None,
                  parent: str = "root") -> None:
        node = {"kind": kind, "handle": "0:", "options": dict(options or {})}
        if parent == "root":
            node["root"] = True
        else:
            node["parent"] = parent
        self.qdisc[iface] = [node]

    def set_mq(self, iface: str, leaf: str = "fq_codel", count: int = 2) -> None:
        nodes = [{"kind": "mq", "handle": "0:", "root": True, "options": {}}]
        for index in range(1, count + 1):
            nodes.append({"kind": leaf, "handle": "0:", "parent": f":{index}",
                          "options": {"limit": 10240}})
        self.qdisc[iface] = nodes

    def set_ethernet(self, iface: str = "eth0", eee: str = "enabled",
                     adaptive_rx: str = "on", rx_usecs: str = "50") -> None:
        self.tools.add("ethtool")
        self.eee[iface] = eee
        self.coalesce[iface] = {"adaptive-rx": adaptive_rx,
                                "rx-usecs": rx_usecs, "rx-frames": "0"}

    def which(self, name: str):
        return f"/usr/sbin/{name}" if name in self.tools else None

    def replaced(self, iface: str = "") -> list:
        return [call for call in self.calls
                if call[:3] == ["tc", "qdisc", "replace"]
                and (not iface or call[4] == iface)]

    def kind_of(self, iface: str) -> str:
        nodes = self.qdisc.get(iface) or []
        return nodes[0]["kind"] if nodes else ""

    # -- komutlar ----------------------------------------------------------
    def __call__(self, cmd, **_kwargs):
        cmd = list(cmd)
        self.calls.append(cmd)
        handler = getattr(self, "_handle_" + cmd[0].replace("-", "_"), None)
        if handler is not None:
            result = handler(cmd)
            if result is not None:
                return result
        return subprocess.CompletedProcess(cmd, 0, "", "")

    @staticmethod
    def _ok(cmd, out=""):
        return subprocess.CompletedProcess(cmd, 0, out, "")

    @staticmethod
    def _fail(cmd, rc=2, err="hata"):
        return subprocess.CompletedProcess(cmd, rc, "", err)

    def _handle_iw(self, cmd):
        if cmd[1:2] == ["dev"] and cmd[3:] == ["get", "power_save"]:
            return self._ok(cmd, f"Power save: {self.power.get(cmd[2], 'off')}\n")
        if cmd[3:5] == ["set", "power_save"]:
            if cmd[2] in self.power_reverts:
                # Sürücü/NetworkManager isteği kabul ediyor ama geri alıyor.
                return self._ok(cmd)
            self.power[cmd[2]] = cmd[5]
            return self._ok(cmd)
        return None

    def _handle_ip(self, cmd):
        if "route" in cmd and "get" in cmd:
            address = cmd[-1]
            dev = self.route_dev.get(address, self.default_dev)
            if "-j" in cmd:
                return self._ok(cmd, json.dumps(
                    [{"dst": address, "dev": dev, "prefsrc": "192.0.2.5"}]))
            return self._ok(cmd, f"{address} dev {dev} src 192.0.2.5 uid 0\n")
        if cmd[1:3] == ["link", "show"]:
            if cmd[3:5] == ["type", "ifb"]:
                return self._ok(cmd) if self.ifb_supported \
                    else self._fail(cmd, 1, "not supported")
            device = cmd[-1]
            return self._ok(cmd) if device in self.ifb_devices \
                else self._fail(cmd, 1, "does not exist")
        if cmd[1:3] == ["link", "add"]:
            if not self.ifb_supported:
                return self._fail(cmd)
            self.ifb_devices.add(cmd[4])
            return self._ok(cmd)
        if cmd[1:3] == ["link", "del"]:
            self.ifb_devices.discard(cmd[-1])
            return self._ok(cmd)
        return None

    def _handle_tc(self, cmd):
        if cmd[1:3] == ["filter", "show"]:
            return self._ok(cmd, self.filters.get(cmd[-1], ""))
        if cmd[1:3] == ["class", "show"]:
            return self._ok(cmd, self.classes.get(cmd[-1], ""))
        if cmd[1:3] in (["filter", "add"], ["filter", "del"]):
            return self._ok(cmd)
        if cmd[1:3] == ["class", "replace"]:
            return self._ok(cmd)
        words = set(cmd)
        if "qdisc" in words and "show" in words:
            iface = cmd[-1] if cmd[-1] not in ("ingress",) else cmd[-2]
            if cmd[-1] == "ingress":
                return self._ok(cmd, "qdisc ingress ffff: parent ffff:fff1\n"
                                if self.ingress_busy else "")
            if "-j" in cmd:
                return self._ok(cmd, json.dumps(self.qdisc.get(iface, [])))
            return self._ok(cmd, self._text_qdisc(iface))
        if "qdisc" in words and ("replace" in words or "add" in words):
            return self._qdisc_write(cmd)
        if "qdisc" in words and "change" in words:
            return self._ok(cmd) if self.qdisc_change_rc == 0 \
                else self._fail(cmd, self.qdisc_change_rc)
        if "qdisc" in words and "del" in words:
            return self._ok(cmd)
        return None

    def _text_qdisc(self, iface):
        lines = []
        for node in self.qdisc.get(iface, []):
            where = "root" if node.get("root") else f"parent {node['parent']}"
            options = " ".join(f"{key} {value}"
                               for key, value in sorted(node["options"].items()))
            lines.append(f"qdisc {node['kind']} {node['handle']} {where} "
                         f"refcnt 2 {options}".rstrip())
        return "\n".join(lines) + ("\n" if lines else "")

    def _qdisc_write(self, cmd):
        iface = cmd[cmd.index("dev") + 1]
        tail = cmd[cmd.index("dev") + 2:]
        if tail and tail[0] == "root":
            parent, tail = "root", tail[1:]
        elif tail and tail[0] == "parent":
            parent, tail = tail[1], tail[2:]
        else:
            parent, tail = "root", tail
        handle = "0:"
        if tail[:1] == ["handle"]:
            handle = tail[1]
            tail = tail[2:]
        if not tail:
            return self._ok(cmd)
        kind = tail[0]
        if kind in self.fail_qdisc_kinds:
            return self._fail(cmd, 2, "desteklenmiyor")
        options = {}
        rest = tail[1:]
        if kind == "cake":
            for index in range(0, len(rest) - 1):
                if rest[index] == "bandwidth":
                    options["bandwidth"] = ("unlimited"
                                            if self.cake_bandwidth_ignored
                                            else rest[index + 1])
            options.setdefault("bandwidth", "unlimited")
        node = {"kind": kind, "handle": handle, "options": options}
        if parent == "root":
            node["root"] = True
            self.qdisc[iface] = [node]
        else:
            node["parent"] = parent
            nodes = [item for item in self.qdisc.get(iface, [])
                     if item.get("parent") != parent]
            self.qdisc[iface] = nodes + [node]
        return self._ok(cmd)

    def _handle_ethtool(self, cmd):
        if cmd[1] == "--show-eee":
            if not self.eee_supported:
                return self._fail(cmd, 75, "Operation not supported")
            state = self.eee.get(cmd[2], "unsupported")
            body = "enabled - active" if state == "enabled" else state
            return self._ok(cmd, f"EEE settings for {cmd[2]}:\n"
                                 f"\tEEE status: {body}\n")
        if cmd[1] == "--set-eee":
            if not self.eee_supported:
                return self._fail(cmd, 75, "not supported")
            if cmd[2] not in self.eee_reverts:
                self.eee[cmd[2]] = "enabled" if cmd[4] == "on" else "disabled"
            return self._ok(cmd)
        if cmd[1] == "-c":
            if not self.coalesce_supported or cmd[2] not in self.coalesce:
                return self._fail(cmd, 75, "not supported")
            values = self.coalesce[cmd[2]]
            return self._ok(cmd, (
                f"Coalesce parameters for {cmd[2]}:\n"
                f"Adaptive RX: {values['adaptive-rx']}  TX: n/a\n"
                f"rx-usecs: {values['rx-usecs']}\n"
                f"rx-frames: {values['rx-frames']}\n"))
        if cmd[1] == "-C":
            if not self.coalesce_supported or cmd[2] not in self.coalesce:
                return self._fail(cmd, 75, "not supported")
            if not self.coalesce_writable:
                return self._ok(cmd)     # rc 0 ama değer değişmez
            pairs = cmd[3:]
            for index in range(0, len(pairs) - 1, 2):
                self.coalesce[cmd[2]][pairs[index]] = pairs[index + 1]
            return self._ok(cmd)
        return None

    def _handle_modinfo(self, cmd):
        return self._fail(cmd, 1, "not found")


class StateProbe:
    """Ölçümü FakeRunner üzerindeki gerçek sistem durumundan üretir."""

    def __init__(self, runner: FakeRunner, table: dict, default: float,
                 jitter: float = 0.0, seed: int = 5,
                 loss: "dict | None" = None) -> None:
        self.runner = runner
        self.table = table
        self.default = default
        self.jitter = jitter
        self.loss = loss or {}
        self.random = random.Random(seed)
        self.calls: list = []

    def state_key(self, interface: str) -> tuple:
        return (self.runner.power.get(interface, "off"),
                self.runner.kind_of(interface),
                self.runner.eee.get(interface, "disabled"),
                self.runner.coalesce.get(interface, {}).get("rx-usecs", "-"))

    def value_for(self, interface: str) -> float:
        key = self.state_key(interface)
        for pattern, value in self.table.items():
            if all(part is None or part == key[index]
                   for index, part in enumerate(pattern)):
                return value
        return self.default

    def measure(self, plan) -> LatencyMeasurement:
        self.calls.append((plan.interface, plan.arm, plan.block))
        base = self.value_for(plan.interface)
        dropped = self.loss.get(self.state_key(plan.interface)[1], 0)
        blocks = []
        for endpoint in plan.endpoints:
            count = max(0, plan.samples - dropped)
            values = [base + (self.random.gauss(0, self.jitter)
                              if self.jitter else 0.0)
                      for _index in range(count)]
            blocks.append(EndpointSamples(spec=endpoint, rtt_ms=values,
                                          sent=plan.samples))
        return LatencyMeasurement.from_blocks(blocks, condition=plan.condition)


class OptimizerCase(unittest.IsolatedAsyncioTestCase):
    def temp_dir(self) -> str:
        directory = tempfile.TemporaryDirectory(prefix="dpibypass-latency-")
        self.addCleanup(directory.cleanup)
        return directory.name

    def make_optimizer(self, runner: FakeRunner, probe,
                       directory: "str | None" = None,
                       settings: "LatencySettings | None" = None,
                       **kwargs) -> LatencyOptimizer:
        directory = directory or self.temp_dir()
        settings = settings or LatencySettings(scan_blocks=2, holdout_blocks=2,
                                               samples=6)
        return LatencyOptimizer(
            runner=runner, which_fn=runner.which, probe=probe,
            state_path=os.path.join(directory, "latency.json"),
            profile_path=os.path.join(directory, "profiles.json"),
            settings=settings, **kwargs)


# --------------------------------------------------------------------------- #
# yapılandırma
# --------------------------------------------------------------------------- #
class TestLatencyConfig(unittest.TestCase):
    def test_default_is_disabled(self):
        self.assertFalse(DEFAULTS["latency_mode"])

    def test_heavy_features_do_not_enable_themselves_after_an_update(self):
        """Yük testi ve SQM güncelleme sonrası kendiliğinden etkinleşmemeli."""
        self.assertFalse(DEFAULTS["latency_load_test"])
        self.assertFalse(DEFAULTS["latency_sqm"])
        self.assertEqual(DEFAULTS["latency_uplink_kbit"], 0)
        self.assertEqual(DEFAULTS["latency_downlink_kbit"], 0)
        self.assertEqual(DEFAULTS["latency_targets"], [])

    def test_old_config_loads_without_migration(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "config.json")
            with open(path, "w", encoding="utf-8") as handle:
                json.dump({"enabled": True, "mode": "smart"}, handle)
            config = Config(path)
            for key in ("latency_mode", "latency_load_test", "latency_sqm"):
                self.assertFalse(config[key], key)
            self.assertEqual(config["latency_targets"], [])


# --------------------------------------------------------------------------- #
# metrikler
# --------------------------------------------------------------------------- #
class TestMetrics(unittest.TestCase):
    def test_endpoint_stats_are_per_target(self):
        fast, slow = spec("203.0.113.1"), spec("203.0.113.2")
        block = measurement_of([(fast, [10.0] * 8), (slow, [100.0] * 8)])
        medians = sorted(item.median_ms for item in block.endpoints)
        self.assertEqual(medians, [10.0, 100.0])

    def test_aggregate_is_weighted_per_endpoint_not_per_sample(self):
        """Bir hedefin çok, diğerinin az yanıt vermesi özeti kaydıramaz."""
        fast, slow = spec("203.0.113.1"), spec("203.0.113.2")
        few = measurement_of([(fast, [10.0] * 2), (slow, [100.0] * 8)])
        many = measurement_of([(fast, [10.0] * 8), (slow, [100.0] * 2)])
        self.assertEqual(few.remote.median_ms, many.remote.median_ms)
        self.assertEqual(few.remote.median_ms, 55.0)

    def test_jitter_never_mixes_two_endpoints(self):
        """Farklı hedeflerin doğal RTT farkı jitter değildir."""
        first, second = spec("203.0.113.1"), spec("203.0.113.2")
        block = measurement_of([(first, [10.0] * 6), (second, [90.0] * 6)])
        for item in block.endpoints:
            self.assertEqual(item.jitter_ms, 0.0)
        self.assertEqual(block.remote.jitter_ms, 0.0)

    def test_coverage_tracks_silent_endpoints(self):
        first, second = spec("203.0.113.1"), spec("203.0.113.2")
        block = measurement_of([(first, [10.0] * 8), (second, [])])
        self.assertEqual(block.remote.endpoints_responding, 1)
        self.assertEqual(block.remote.endpoints_total, 2)
        self.assertEqual(block.remote.coverage, 0.5)
        # Susan hedef kaybı gizleyemez: özet kayıp oranı endpoint başına
        # eşit ağırlıklıdır.
        self.assertEqual(block.remote.packet_loss, 50.0)

    def test_p95_reliability_is_reported_not_assumed(self):
        endpoint = spec()
        thin = measurement_of([(endpoint, [10.0] * 5)], sent=5)
        thick = measurement_of([(endpoint, [10.0] * 40)], sent=40)
        self.assertFalse(thin.endpoints[0].p95_reliable)
        self.assertTrue(thick.endpoints[0].p95_reliable)

    def test_tcp_failures_are_not_called_packet_loss(self):
        tcp = spec(method=METHOD_TCP_CONNECT, port=443)
        icmp = spec(method=METHOD_ICMP)
        self.assertEqual(
            EndpointStats.from_samples(samples(tcp, [5.0], 4)).loss_label,
            "başarısızlık oranı")
        self.assertEqual(
            EndpointStats.from_samples(samples(icmp, [5.0], 4)).loss_label,
            "paket kaybı")

    def test_measurements_of_different_conditions_are_incomparable(self):
        endpoint = spec()
        idle = measurement_of([flat(endpoint, 10.0)], condition="idle")
        loaded = measurement_of([flat(endpoint, 10.0)], condition="load-up")
        ok, why = idle.comparable_with(loaded)
        self.assertFalse(ok)
        self.assertIn("koşul", why)

    def test_identity_change_makes_measurements_incomparable(self):
        first = measurement_of([flat(spec("203.0.113.1"), 10.0)])
        second = measurement_of([flat(spec("203.0.113.9"), 10.0)])
        ok, why = first.comparable_with(second)
        self.assertFalse(ok)
        self.assertIn("hedef", why)


# --------------------------------------------------------------------------- #
# ping ayrıştırma
# --------------------------------------------------------------------------- #
class TestPingParsing(unittest.TestCase):
    SUCCESS = ("PING 1.1.1.1 (1.1.1.1) 56(84) bytes of data.\n"
               "64 bytes from 1.1.1.1: icmp_seq=1 ttl=57 time=12.3 ms\n"
               "64 bytes from 1.1.1.1: icmp_seq=2 ttl=57 time<1 ms\n"
               "64 bytes from 1.1.1.1: icmp_seq=2 ttl=57 time=12.9 ms (DUP!)\n"
               "64 bytes from 1.1.1.1: icmp_seq=4 ttl=57 time=13.1 ms\n\n"
               "--- 1.1.1.1 ping statistics ---\n"
               "4 packets transmitted, 3 received, +1 duplicates, "
               "25% packet loss, time 3005ms\n")

    def test_time_less_than_and_duplicates(self):
        outcome = parse_ping(self.SUCCESS, 0, 4)
        self.assertEqual(outcome.rtt_ms, [12.3, 1.0, 13.1])
        self.assertEqual(outcome.duplicates, 1)
        self.assertEqual(outcome.transmitted, 4)
        self.assertEqual(outcome.errors.get("timeout"), 1)

    def test_real_transmitted_count_is_used_not_the_planned_one(self):
        text = self.SUCCESS.replace("4 packets transmitted", "2 packets transmitted")
        outcome = parse_ping(text, 0, 8)
        self.assertEqual(outcome.transmitted, 2)

    def test_truncated_output_keeps_the_valid_samples(self):
        outcome = parse_ping(
            "64 bytes from 8.8.8.8: icmp_seq=1 ttl=57 time=9.9 ms\n", 124, 8)
        self.assertEqual(outcome.rtt_ms, [9.9])
        self.assertEqual(outcome.errors.get("process"), 1)

    def test_unreachable_is_not_a_timeout(self):
        outcome = parse_ping("connect: Network is unreachable\n", 2, 8)
        self.assertEqual(outcome.rtt_ms, [])
        self.assertEqual(outcome.errors.get("unreachable"), 1)

    def test_missing_binary_is_a_process_error(self):
        outcome = parse_ping("", 127, 8)
        self.assertEqual(outcome.errors.get("process"), 1)
        self.assertEqual(outcome.transmitted, 0)

    def test_probe_forces_the_c_locale(self):
        """Yerelleşmiş çıktı ondalık ayırıcıyı bozar; komut C ile çalışmalı."""
        seen = {}

        def runner(cmd, **kwargs):
            seen["env"] = kwargs.get("env")
            return subprocess.CompletedProcess(cmd, 0, self.SUCCESS, "")

        probe = LatencyProbe(runner, lambda name: "/bin/ping")
        probe.sample_endpoint(spec(), 4)
        self.assertEqual(seen["env"].get("LC_ALL"), "C")


# --------------------------------------------------------------------------- #
# hedefler ve yol doğrulama
# --------------------------------------------------------------------------- #
class TestTargets(unittest.TestCase):
    def test_icmp_target_rejects_a_port(self):
        self.assertIn("port", TargetSpec("example.net", 443, "icmp").validate())

    def test_tcp_target_requires_a_port(self):
        self.assertIn("port", TargetSpec("example.net", 0, "tcp").validate())

    def test_invalid_hostname_is_rejected(self):
        self.assertIn("geçersiz", TargetSpec("bad host!", 0, "icmp").validate())

    def test_dns_time_is_separated_from_rtt(self):
        from dpibypass.latency.probe import PathResolver, TargetResolver
        runner = FakeRunner()
        resolved = TargetResolver(
            resolver=lambda *a, **k: [(2, 1, 6, "", ("198.51.100.7", 443))],
            path_resolver=PathResolver(runner, runner.which)).resolve(
                TargetSpec("example.net", 443, "tcp"), "wlan0")
        self.assertEqual(resolved.spec.address, "198.51.100.7")
        self.assertIsNotNone(resolved.dns_ms)

    def test_target_on_another_interface_is_not_measured(self):
        """Trafik başka arayüzden gidiyorsa hedefi zorla bağlamayız."""
        from dpibypass.latency.probe import PathResolver, TargetResolver, build_plan
        runner = FakeRunner()
        runner.route_dev["198.51.100.9"] = "tun0"     # VPN
        resolver = TargetResolver(path_resolver=PathResolver(runner, runner.which))
        plan = build_plan([TargetSpec("198.51.100.9", 0, "icmp")],
                          "wlan0", "192.0.2.1", resolver=resolver)
        self.assertEqual(plan.endpoints, [])
        self.assertTrue(any("tun0" in note for note in plan.notes))

    def test_unverified_route_marks_the_plan_unusable(self):
        from dpibypass.latency.probe import PathResolver, TargetResolver, build_plan
        runner = FakeRunner(tools=("tc",))           # ip yok
        resolver = TargetResolver(path_resolver=PathResolver(runner, runner.which))
        plan = build_plan([TargetSpec("198.51.100.9", 0, "icmp")],
                          "wlan0", "192.0.2.1", resolver=resolver)
        self.assertFalse(plan.path_verified)

    def test_reference_targets_are_labelled_as_such(self):
        from dpibypass.latency.probe import reference_targets
        for target in reference_targets():
            self.assertEqual(target.role, ROLE_REFERENCE)
            self.assertEqual(target.validate(), "")

    def test_tcp_probe_refuses_to_measure_without_a_socket_mark(self):
        """İşaret konamazsa ölçüm kendi proxy'mize düşebilir; örnek alınmaz."""
        probe = LatencyProbe(FakeRunner(), lambda name: "/bin/x")
        endpoint = spec(method=METHOD_TCP_CONNECT, port=443)
        with mock.patch("dpibypass.latency.probe.mark_socket",
                        return_value=False):
            block = probe.sample_endpoint(endpoint, 3)
        self.assertEqual(block.rtt_ms, [])
        self.assertEqual(block.errors.get("process"), 3)


# --------------------------------------------------------------------------- #
# istatistiksel karar
# --------------------------------------------------------------------------- #
class TestAnalysis(unittest.TestCase):
    def blocks(self, values, count=4, endpoints=None):
        endpoints = endpoints or [spec()]
        return [measurement_of([(endpoint, list(values))
                                for endpoint in endpoints])
                for _index in range(count)]

    def test_response_weight_shift_is_not_a_gain(self):
        """İki hedefin RTT'si aynı; yalnız yanıt ağırlıkları yer değiştiriyor."""
        fast, slow = spec("203.0.113.1"), spec("203.0.113.2")
        before = [measurement_of([(fast, [10.0] * 8), (slow, [100.0] * 16)],
                                 sent=16) for _ in range(4)]
        after = [measurement_of([(fast, [10.0] * 16), (slow, [100.0] * 8)],
                                sent=16) for _ in range(4)]
        # Eski motorun havuzlanmış median'ı burada 100 → 10 diyordu.
        self.assertEqual(before[0].remote.median_ms, after[0].remote.median_ms)
        result = analysis.compare(before, after, seed=1, resamples=300)
        self.assertNotEqual(result.outcome, analysis.OUTCOME_GAIN)

    def test_small_but_repeated_improvement_is_accepted(self):
        """10 → 9 ms: sabit 2 ms duvarı tek kriter olmamalı."""
        result = analysis.compare(self.blocks([10.0] * 16),
                                  self.blocks([9.0] * 16),
                                  seed=1, resamples=300)
        self.assertEqual(result.outcome, analysis.OUTCOME_GAIN)

    def test_sub_millisecond_improvement_can_be_evaluated(self):
        result = analysis.compare(self.blocks([10.0] * 16),
                                  self.blocks([9.4] * 16),
                                  seed=1, resamples=300)
        self.assertEqual(result.outcome, analysis.OUTCOME_GAIN)

    def test_noise_below_the_resolution_is_not_a_gain(self):
        result = analysis.compare(self.blocks([10.0] * 16),
                                  self.blocks([9.95] * 16),
                                  seed=1, resamples=300)
        self.assertNotEqual(result.outcome, analysis.OUTCOME_GAIN)

    def test_pure_noise_never_produces_a_systematic_winner(self):
        rng = random.Random(11)
        endpoint = spec()

        def noisy():
            return measurement_of(
                [(endpoint, [20.0 + rng.gauss(0, 3) for _ in range(16)])])

        for seed in range(6):
            result = analysis.compare([noisy() for _ in range(6)],
                                      [noisy() for _ in range(6)],
                                      seed=seed, resamples=300)
            self.assertNotEqual(result.outcome, analysis.OUTCOME_GAIN,
                                f"A/A seed={seed} kazanan üretti")

    def test_natural_drift_is_not_credited_to_the_candidate(self):
        """Ağ ölçüm boyunca kendiliğinden iyileşiyor; aday neredeyse etkisiz."""
        endpoint = spec()
        control, treatment = [], []
        for index in range(5):
            base = 30.0 - 2.0 * index
            control.append(measurement_of([(endpoint, [base] * 16)]))
            treatment.append(measurement_of([(endpoint, [base - 0.05] * 16)]))
        result = analysis.compare(control, treatment, seed=1, resamples=300)
        self.assertNotEqual(result.outcome, analysis.OUTCOME_GAIN)

    def test_p95_regression_vetoes_a_median_gain(self):
        endpoint = spec()
        control = [measurement_of([(endpoint, [20.0] * 15 + [22.0])])
                   for _ in range(4)]
        treatment = [measurement_of([(endpoint, [15.0] * 15 + [60.0])])
                     for _ in range(4)]
        result = analysis.compare(control, treatment, seed=1, resamples=300)
        self.assertEqual(result.outcome, analysis.OUTCOME_REGRESSION)
        self.assertIn("p95", result.reason)

    def test_losing_an_endpoint_is_a_regression_not_an_improvement(self):
        fast, slow = spec("203.0.113.1"), spec("203.0.113.2")
        control = [measurement_of([(fast, [10.0] * 8), (slow, [100.0] * 8)])
                   for _ in range(4)]
        treatment = [measurement_of([(fast, [10.0] * 8), (slow, [])])
                     for _ in range(4)]
        result = analysis.compare(control, treatment, seed=1, resamples=300)
        self.assertEqual(result.outcome, analysis.OUTCOME_REGRESSION)
        self.assertIn("kapsam", result.reason)

    def test_increased_loss_vetoes_even_a_faster_median(self):
        endpoint = spec()
        control = [measurement_of([(endpoint, [20.0] * 8)], sent=8)
                   for _ in range(4)]
        treatment = [measurement_of([(endpoint, [10.0] * 6)], sent=8)
                     for _ in range(4)]
        result = analysis.compare(control, treatment, seed=1, resamples=300)
        self.assertEqual(result.outcome, analysis.OUTCOME_REGRESSION)
        self.assertIn("kayıp", result.reason)

    def test_a_single_pair_is_inconclusive_not_a_gain(self):
        result = analysis.compare(self.blocks([10.0] * 8, count=1),
                                  self.blocks([5.0] * 8, count=1),
                                  seed=1, resamples=300)
        self.assertEqual(result.outcome, analysis.OUTCOME_INCONCLUSIVE)

    def test_bootstrap_is_deterministic_for_a_fixed_seed(self):
        deltas = [-1.0, -0.2, -3.0, 0.5]
        first = analysis.bootstrap_ci(deltas, 500, rng=random.Random(3))
        second = analysis.bootstrap_ci(deltas, 500, rng=random.Random(3))
        self.assertEqual(first, second)

    def test_user_targets_decide_over_reference_targets(self):
        user = spec("203.0.113.1", role=ROLE_USER)
        reference = spec("1.1.1.1", role=ROLE_REFERENCE)
        control = [measurement_of([(user, [20.0] * 12), (reference, [20.0] * 12)])
                   for _ in range(4)]
        # Yalnız referans hedefi iyileşiyor; kullanıcının hedefi aynı.
        treatment = [measurement_of([(user, [20.0] * 12),
                                     (reference, [10.0] * 12)])
                     for _ in range(4)]
        result = analysis.compare(control, treatment, seed=1, resamples=300)
        self.assertNotEqual(result.outcome, analysis.OUTCOME_GAIN)


# --------------------------------------------------------------------------- #
# kuyruk disiplini
# --------------------------------------------------------------------------- #
class TestQdisc(unittest.TestCase):
    def plan(self, runner: FakeRunner, iface: str = "eth0"):
        topology = qdiscmod.read_topology(runner, runner.which, iface)
        return qdiscmod.plan_slots(topology, iface, runner=runner)

    def test_mq_root_is_preserved_and_leaves_become_slots(self):
        runner = FakeRunner()
        runner.set_mq("eth0", "fq_codel", count=3)
        slots, notes = self.plan(runner)
        self.assertEqual(len(slots), 3)
        self.assertTrue(all(slot.parent != "root" for slot in slots))
        self.assertTrue(any("mq kökü korunuyor" in note for note in notes))

    def test_user_cake_configuration_is_never_replaced(self):
        runner = FakeRunner()
        runner.set_qdisc("eth0", "cake", {"bandwidth": "20Mbit"})
        slots, notes = self.plan(runner)
        self.assertEqual(slots, [])
        self.assertTrue(any("korundu" in note for note in notes))

    def test_attached_filters_stop_any_change(self):
        runner = FakeRunner()
        runner.set_mq("eth0")
        runner.filters["eth0"] = "filter parent 1: protocol ip pref 1 u32"
        slots, notes = self.plan(runner)
        self.assertEqual(slots, [])
        self.assertTrue(any("filter" in note for note in notes))

    def test_unknown_option_preserves_the_structure(self):
        runner = FakeRunner()
        runner.set_qdisc("eth0", "fq", {"limit": 10240, "horizon": "10s"})
        slots, notes = self.plan(runner)
        self.assertEqual(slots, [])
        self.assertTrue(any("geri alınamıyor" in note for note in notes))

    def test_restore_recipe_must_be_proven_before_use(self):
        runner = FakeRunner()
        runner.set_mq("eth0", "fq_codel")
        runner.qdisc_change_rc = 2       # çekirdek tarifi kabul etmiyor
        slots, notes = self.plan(runner)
        self.assertEqual(slots, [])
        self.assertTrue(any("kabul edilmedi" in note for note in notes))

    def test_pfifo_fast_recipe_carries_no_options(self):
        node = qdiscmod.parse_json_qdiscs(json.dumps([{
            "kind": "pfifo_fast", "handle": "0:", "root": True,
            "options": {"bands": 3, "priomap": [1, 2, 2]}}]))[0]
        self.assertEqual(qdiscmod.restore_args(node), ["pfifo_fast"])

    def test_fifo_limit_is_kept_in_the_recipe(self):
        node = qdiscmod.parse_json_qdiscs(json.dumps([{
            "kind": "pfifo", "handle": "8001:", "root": True,
            "options": {"limit": 1000}}]))[0]
        self.assertEqual(qdiscmod.restore_args(node), ["pfifo", "limit", "1000"])

    def test_time_options_are_written_back_with_an_explicit_unit(self):
        node = qdiscmod.parse_json_qdiscs(json.dumps([{
            "kind": "fq_codel", "handle": "0:", "root": True,
            "options": {"target": 4999, "interval": 99999}}]))[0]
        self.assertIn("4999us", qdiscmod.restore_args(node))

    def test_text_fallback_is_used_when_json_is_unavailable(self):
        runner = FakeRunner()

        def no_json(cmd, **kwargs):
            if "-j" in cmd:
                return subprocess.CompletedProcess(cmd, 1, "", "invalid option")
            return runner(cmd, **kwargs)

        topology = qdiscmod.read_topology(no_json, runner.which, "eth0")
        self.assertFalse(topology.structured)
        self.assertEqual(topology.root().kind, "pfifo_fast")


# --------------------------------------------------------------------------- #
# SQM
# --------------------------------------------------------------------------- #
class TestSqm(unittest.TestCase):
    def manager(self, runner: FakeRunner) -> SqmManager:
        return SqmManager(runner, runner.which)

    def test_shaping_is_refused_without_a_known_capacity(self):
        runner = FakeRunner()
        with self.assertRaises(Exception):
            self.manager(runner).apply("eth0", SqmCapacity(), 0.9,
                                       ["pfifo_fast"])

    def test_cake_is_applied_with_a_real_bandwidth(self):
        runner = FakeRunner()
        state = self.manager(runner).apply(
            "eth0", SqmCapacity(egress_kbit=20000, ingress_kbit=100000,
                                source="user"), 0.9, ["pfifo_fast"])
        self.assertTrue(state.egress_applied)
        self.assertEqual(state.egress_kbit, 18000)
        applied = [call for call in runner.calls if "cake" in call]
        self.assertTrue(any("18000kbit" in call for call in applied))

    def test_cake_without_an_effective_bandwidth_is_not_a_success(self):
        """``bandwidth`` yok sayıldıysa shaper devre dışıdır; başarı sayılmaz."""
        runner = FakeRunner()
        runner.cake_bandwidth_ignored = True
        with self.assertRaises(Exception):
            self.manager(runner).apply(
                "eth0", SqmCapacity(egress_kbit=20000, source="user"),
                0.9, ["pfifo_fast"])

    def test_existing_ingress_configuration_is_preserved(self):
        runner = FakeRunner()
        runner.ingress_busy = True
        state = self.manager(runner).apply(
            "eth0", SqmCapacity(egress_kbit=20000, ingress_kbit=100000,
                                source="user"), 0.9, ["pfifo_fast"])
        self.assertFalse(state.ingress_applied)
        self.assertFalse(state.ingress_qdisc_created)
        self.assertTrue(any("yalnız upload" in note for note in state.notes))

    def test_rollback_only_removes_resources_it_created(self):
        runner = FakeRunner()
        manager = self.manager(runner)
        state = manager.apply("eth0",
                              SqmCapacity(egress_kbit=20000, ingress_kbit=90000,
                                          source="user"),
                              0.9, ["pfifo_fast"])
        self.assertTrue(state.ifb_created)
        runner.calls.clear()
        self.assertTrue(manager.rollback(state))
        deletions = [call for call in runner.calls
                     if "del" in call or "flush" in call]
        for call in deletions:
            self.assertNotIn("flush", call)
            if call[:3] == ["ip", "link", "del"]:
                self.assertEqual(call[-1], "ifb-dpib")
        self.assertNotIn("ifb-dpib", runner.ifb_devices)

    def test_rollback_is_idempotent(self):
        runner = FakeRunner()
        manager = self.manager(runner)
        state = manager.apply("eth0",
                              SqmCapacity(egress_kbit=20000, source="user"),
                              0.9, ["pfifo_fast"])
        self.assertTrue(manager.rollback(state))
        self.assertTrue(manager.rollback(state))

    def test_ingress_is_skipped_when_ifb_is_unavailable(self):
        runner = FakeRunner()
        runner.ifb_supported = False
        state = self.manager(runner).apply(
            "eth0", SqmCapacity(egress_kbit=20000, ingress_kbit=90000,
                                source="user"), 0.9, ["pfifo_fast"])
        self.assertTrue(state.egress_applied)
        self.assertFalse(state.ingress_applied)
        self.assertTrue(any("upload" in note for note in state.notes))

    def test_rates_are_clamped_to_a_safe_range(self):
        from dpibypass.latency.sqm import clamp_rate, shaped_rate
        with self.assertRaises(Exception):
            clamp_rate(10)
        with self.assertRaises(Exception):
            clamp_rate("hızlı")
        self.assertEqual(shaped_rate(10000, 0.9), 9000)
        self.assertEqual(shaped_rate(10000, 0.1), 7000)      # alt sınır
        self.assertEqual(shaped_rate(10000, 5.0), 9800)      # üst sınır


# --------------------------------------------------------------------------- #
# kontrollü yük
# --------------------------------------------------------------------------- #
class TestLoad(unittest.TestCase):
    def test_load_needs_explicit_ownership_consent(self):
        target = LoadTarget(host="sunucum.example", port=5201, mode="tcp-sink")
        self.assertIn("onay", target.validate())
        target.owned = True
        self.assertEqual(target.validate(), "")

    def test_public_infrastructure_is_never_a_load_target(self):
        target = LoadTarget(host="8.8.8.8", port=443, mode="http-download",
                            owned=True)
        self.assertIn("genel altyapı", target.validate())

    def test_metered_connection_requires_a_second_consent(self):
        target = LoadTarget(host="sunucum.example", port=5201,
                            mode="tcp-sink", owned=True)
        self.assertIn("ayrı onay", target.validate(metered=True))
        target.metered_ack = True
        self.assertEqual(target.validate(metered=True), "")

    def test_budget_is_clamped_to_hard_limits(self):
        budget = LoadBudget(max_seconds=9999, max_bytes=10 ** 12,
                            streams=99).clamped()
        self.assertLessEqual(budget.max_seconds, loadmod.HARD_MAX_SECONDS)
        self.assertLessEqual(budget.max_bytes, loadmod.HARD_MAX_BYTES)
        self.assertLessEqual(budget.streams, 8)

    def test_generator_refuses_to_start_without_permission(self):
        generator = loadmod.LoadGenerator(
            LoadTarget(host="sunucum.example", port=5201, mode="tcp-sink"),
            LoadBudget())
        result = generator.start()
        self.assertFalse(result.started)
        self.assertEqual(result.stopped_reason, "izin yok")

    def test_description_shows_purpose_and_limits_before_starting(self):
        text = loadmod.describe(
            LoadTarget(host="sunucum.example", port=5201, mode="tcp-sink",
                       owned=True),
            LoadBudget(max_seconds=10, max_bytes=8 * 1024 * 1024))
        self.assertIn("sunucum.example", text)
        self.assertIn("10 sn", text)
        self.assertIn("8 MB", text)


# --------------------------------------------------------------------------- #
# eylemler, kanıt ve geri alma
# --------------------------------------------------------------------------- #
class TestActions(unittest.TestCase):
    def executor(self, runner: FakeRunner):
        from dpibypass.latency.actions import ActionExecutor
        return ActionExecutor(runner, runner.which)

    def test_return_code_zero_without_a_real_change_is_a_failure(self):
        """Sürücü isteği kabul edip sessizce yok sayarsa 'uygulandı' denmez."""
        runner = FakeRunner()
        runner.power_reverts.add("wlan0")
        with self.assertRaises(Exception) as caught:
            self.executor(runner).apply_wifi_power_save("wlan0", "off")
        self.assertIn("geri değiştiriyor", str(caught.exception))

    def test_eee_readback_is_verified(self):
        runner = FakeRunner()
        runner.set_ethernet("eth0")
        runner.eee_reverts.add("eth0")
        with self.assertRaises(Exception):
            self.executor(runner).apply_eee("eth0", "off")

    def test_coalesce_readback_is_verified(self):
        runner = FakeRunner()
        runner.set_ethernet("eth0")
        runner.coalesce_writable = False
        with self.assertRaises(Exception):
            self.executor(runner).apply_coalesce(
                "eth0", {"adaptive-rx": "off", "rx-usecs": "0"})

    def test_coalesce_writability_is_proven_with_a_noop(self):
        runner = FakeRunner()
        runner.set_ethernet("eth0")
        executor = self.executor(runner)
        current = executor.read_coalesce("eth0")
        self.assertTrue(executor.coalesce_writable("eth0", current))
        runner.coalesce_writable = False
        runner.coalesce["eth0"]["rx-usecs"] = "50"
        self.assertTrue(executor.coalesce_writable("eth0", current))

    def test_coalesce_candidates_are_more_than_a_single_zero(self):
        options = engine_mod.coalesce_candidates(
            {"adaptive-rx": "on", "rx-usecs": "64", "rx-frames": "0"})
        values = sorted(int(item["rx-usecs"]) for item in options)
        self.assertGreater(len(values), 1)
        self.assertIn(0, values)
        self.assertTrue(all(value < 64 for value in values))

    def test_every_action_kind_produces_a_signature(self):
        runner = FakeRunner()
        runner.set_ethernet("eth0")
        executor = self.executor(runner)
        for kind in ("wifi-power-save", "eee", "coalesce", "qdisc"):
            iface = "wlan0" if kind == "wifi-power-save" else "eth0"
            self.assertTrue(executor.signature(kind, iface), kind)

    def test_external_change_stops_the_rollback_from_overwriting(self):
        runner = FakeRunner()
        executor = self.executor(runner)
        action = ActionSnapshot(kind="wifi-power-save", interface="wlan0",
                                restore={"value": "on"}, signature="off")
        runner.power["wlan0"] = "on"        # kullanıcı araya girdi
        self.assertTrue(executor.restore(action))
        self.assertIn("dışarıdan", executor.external_change)

    def test_restore_refuses_a_recycled_interface_name(self):
        runner = FakeRunner()
        executor = self.executor(runner)
        action = ActionSnapshot(kind="wifi-power-save", interface="wlan0",
                                restore={"value": "on"}, ifindex=99)
        with mock.patch("dpibypass.latency.actions.ifindex_of", return_value=4):
            self.assertFalse(executor.restore(action))


# --------------------------------------------------------------------------- #
# snapshot
# --------------------------------------------------------------------------- #
class TestSnapshot(OptimizerCase):
    def optimizer(self):
        runner = FakeRunner()
        return runner, self.make_optimizer(runner, StateProbe(runner, {}, 20.0))

    def test_missing_snapshot_is_not_corrupt(self):
        _runner, optimizer = self.optimizer()
        self.assertIsNone(optimizer._load_snapshot())

    def test_corrupt_snapshot_is_distinguished_from_a_missing_one(self):
        _runner, optimizer = self.optimizer()
        with open(optimizer.state_path, "w", encoding="utf-8") as handle:
            handle.write("{ bu json degil")
        with self.assertRaises(SnapshotCorrupt):
            optimizer._load_snapshot()

    async def test_corrupt_snapshot_blocks_new_changes_and_keeps_the_file(self):
        runner, optimizer = self.optimizer()
        with open(optimizer.state_path, "w", encoding="utf-8") as handle:
            handle.write('{"interface": "wlan0", "link_type": "bilinmeyen"}')
        self.assertFalse(await optimizer.recover())
        self.assertEqual(optimizer.status.state, "snapshot-corrupt")
        # Dosya sessizce SİLİNMEZ: durum belirsizken kanıt korunur.
        self.assertTrue(os.path.exists(optimizer.state_path))
        status = await optimizer.optimize(network())
        self.assertEqual(status["state"], "snapshot-corrupt")
        self.assertEqual(runner.replaced(), [])

    def test_legacy_snapshot_is_still_restorable(self):
        snapshot = LatencySnapshot.from_dict({
            "interface": "wlan0", "link_type": "wifi",
            "wifi_power_save": "on",
            "qdisc": {"kind": "pfifo_fast", "restore_args": ["pfifo_fast"],
                      "applied_output": "qdisc fq_codel 0: root"},
        })
        self.assertEqual(len(snapshot.actions), 2)
        self.assertEqual(snapshot.version, 1)

    def test_snapshot_rejects_an_unsafe_restore_recipe(self):
        with self.assertRaises(ValueError):
            ActionSnapshot.from_dict({
                "kind": "qdisc", "interface": "wlan0",
                "restore": {"args": ["pfifo_fast; rm -rf /"], "parent": "root"}})


# --------------------------------------------------------------------------- #
# uçtan uca motor akışı
# --------------------------------------------------------------------------- #
class TestEngineFlow(OptimizerCase):
    def wifi_setup(self, gain: float = 6.0, **kwargs):
        runner = FakeRunner()
        # Wi-Fi güç tasarrufu kapalıyken RTT düşüyor; qdisc değişimi etkisiz.
        probe = StateProbe(runner, {("off", None, None, None): 20.0 - gain},
                           default=20.0, **kwargs)
        return runner, probe

    async def test_a_real_gain_is_applied_and_reported_honestly(self):
        runner, probe = self.wifi_setup()
        optimizer = self.make_optimizer(runner, probe)
        status = await optimizer.optimize(network())
        self.assertEqual(status["state"], "active")
        self.assertTrue(status["active"])
        self.assertEqual(status["best"], "wifi-power-save")
        self.assertEqual(runner.power["wlan0"], "off")
        self.assertTrue(status["verification"]["independent"])
        self.assertTrue(status["gain"]["median_ms"] < 0)

    async def test_no_gain_leaves_the_system_untouched(self):
        runner = FakeRunner()
        probe = StateProbe(runner, {}, default=20.0)
        optimizer = self.make_optimizer(runner, probe)
        status = await optimizer.optimize(network())
        self.assertIn(status["state"], ("no-gain", "inconclusive"))
        self.assertFalse(status["active"])
        self.assertEqual(status["applied"], [])
        self.assertEqual(runner.power["wlan0"], "on")
        self.assertEqual(runner.kind_of("wlan0"), "pfifo_fast")

    async def test_every_candidate_reports_a_concrete_outcome(self):
        runner, probe = self.wifi_setup()
        optimizer = self.make_optimizer(runner, probe)
        status = await optimizer.optimize(network())
        self.assertTrue(status["candidates"])
        for candidate in status["candidates"]:
            self.assertIn(candidate["status"],
                          ("tried", "rejected", "unsupported",
                           "budget-exhausted", "not-needed", "failed",
                           "cancelled"))
            self.assertTrue(candidate["verdict"])

    async def test_a_candidate_that_worsens_p95_is_rejected(self):
        runner = FakeRunner()

        class SpikyProbe(StateProbe):
            def measure(self, plan):
                block = super().measure(plan)
                if self.runner.power.get(plan.interface) == "off":
                    # median iyi ama kuyruk çok kötü
                    for item in block.endpoints:
                        item.p95_ms = (item.p95_ms or 0) + 40.0
                    block.remote = LatencyStats.from_endpoints(block.endpoints)
                return block

        probe = SpikyProbe(runner, {("off", None, None, None): 14.0}, 20.0)
        optimizer = self.make_optimizer(runner, probe)
        status = await optimizer.optimize(network())
        self.assertNotEqual(status["state"], "active")
        self.assertEqual(runner.power["wlan0"], "on")

    async def test_a_candidate_that_increases_loss_is_rejected(self):
        runner = FakeRunner()
        probe = StateProbe(runner, {("off", None, None, None): 10.0}, 20.0,
                           loss={})
        # Güç tasarrufu kapalıyken paketlerin bir kısmı düşüyor.
        original = probe.measure

        def lossy(plan):
            block = original(plan)
            if runner.power.get(plan.interface) == "off":
                for item in block.endpoints:
                    item.failure_rate = 40.0
                block.remote = LatencyStats.from_endpoints(block.endpoints)
            return block

        probe.measure = lossy
        optimizer = self.make_optimizer(runner, probe)
        status = await optimizer.optimize(network())
        self.assertNotEqual(status["state"], "active")
        self.assertEqual(runner.power["wlan0"], "on")

    async def test_external_change_stops_the_scan_without_overwriting(self):
        runner, probe = self.wifi_setup()
        optimizer = self.make_optimizer(runner, probe)
        original = optimizer.executor.apply_wifi_power_save
        state = {"count": 0}

        def meddle(iface, value):
            original(iface, value)
            state["count"] += 1
            if state["count"] == 1:
                # Başka bir program araya giriyor.
                runner.qdisc["wlan0"][0]["kind"] = "cake"

        optimizer.executor.apply_wifi_power_save = meddle
        status = await optimizer.optimize(network())
        self.assertIn(status["state"], ("external-change", "active", "no-gain",
                                        "inconclusive"))

    async def test_rollback_failure_is_never_reported_as_a_gain(self):
        runner, probe = self.wifi_setup()
        optimizer = self.make_optimizer(runner, probe)

        def refuse(action, sqm_manager=None):
            return False

        optimizer.executor.restore = refuse
        status = await optimizer.optimize(network())
        # Geri alınamayan bir deneme "kazanç" değildir; açıkça hata olarak
        # raporlanır ve 'active' bayrağı bir doğrulama iddiası taşımaz.
        self.assertEqual(status["state"], "rollback-failed")
        self.assertNotEqual(status["state"], "active")
        self.assertEqual(status["best"], "")

    async def test_cancellation_stops_the_flow_and_restores(self):
        runner, probe = self.wifi_setup()
        optimizer = self.make_optimizer(runner, probe)
        original = probe.measure
        calls = {"n": 0}

        def counting(plan):
            calls["n"] += 1
            if calls["n"] == 3:
                optimizer.request_cancel()
            return original(plan)

        probe.measure = counting
        status = await optimizer.optimize(network())
        self.assertNotEqual(status["state"], "active")
        self.assertEqual(runner.power["wlan0"], "on")

    async def test_budget_exhaustion_is_not_reported_as_no_gain(self):
        runner = FakeRunner()
        runner.default_dev = "eth0"
        runner.set_ethernet("eth0")
        probe = StateProbe(runner, {}, default=20.0)
        optimizer = self.make_optimizer(runner, probe, budget_seconds=-1.0)
        status = await optimizer.optimize(network("eth0", "ethernet"))
        skipped = " ".join(status["skipped"])
        self.assertIn("bütçe", skipped)
        statuses = {item["status"] for item in status["candidates"]}
        self.assertIn("budget-exhausted", statuses)

    async def test_disable_restores_everything(self):
        runner, probe = self.wifi_setup()
        optimizer = self.make_optimizer(runner, probe)
        await optimizer.optimize(network())
        self.assertEqual(runner.power["wlan0"], "off")
        self.assertTrue(await optimizer.disable())
        self.assertEqual(runner.power["wlan0"], "on")
        self.assertFalse(os.path.exists(optimizer.state_path))

    async def test_measurement_is_blocked_without_a_verified_path(self):
        runner = FakeRunner(tools=("iw", "tc"))       # ip yok → rota doğrulanamaz
        probe = StateProbe(runner, {}, default=20.0)
        optimizer = self.make_optimizer(runner, probe)
        status = await optimizer.optimize(network())
        self.assertEqual(status["state"], "unsupported")
        self.assertEqual(runner.replaced(), [])

    async def test_vpn_interfaces_are_never_touched(self):
        runner = FakeRunner()
        optimizer = self.make_optimizer(runner, StateProbe(runner, {}, 20.0))
        status = await optimizer.optimize(
            NetworkFingerprint(interface="tun0", gateway="10.8.0.1",
                               link_type="vpn"))
        self.assertEqual(status["state"], "unsupported")
        self.assertEqual(runner.calls, [])

    async def test_feature_off_means_no_network_traffic_and_no_changes(self):
        runner = FakeRunner()
        probe = StateProbe(runner, {}, default=20.0)
        optimizer = self.make_optimizer(runner, probe)
        self.assertTrue(await optimizer.disable())
        self.assertEqual(probe.calls, [])
        self.assertEqual(runner.replaced(), [])

    async def test_user_targets_replace_the_reference_indicator(self):
        runner, probe = self.wifi_setup()
        settings = LatencySettings(
            scan_blocks=2, holdout_blocks=2, samples=6,
            targets=[TargetSpec("203.0.113.77", 0, "icmp", label="Oyun")])
        optimizer = self.make_optimizer(runner, probe, settings=settings)
        status = await optimizer.optimize(network())
        self.assertIn("Oyun", " ".join(status["targets"]))

    async def test_without_user_targets_the_result_is_labelled_as_generic(self):
        runner, probe = self.wifi_setup()
        optimizer = self.make_optimizer(runner, probe)
        status = await optimizer.optimize(network())
        self.assertTrue(any("genel ağ göstergesi" in note
                            for note in status["skipped"]))


# --------------------------------------------------------------------------- #
# ağ başına öğrenme
# --------------------------------------------------------------------------- #
class TestProfiles(OptimizerCase):
    def context(self, **kwargs) -> ProfileContext:
        base = dict(interface="wlan0", condition="idle", targets="abc",
                    kernel="6.1.0", driver="wifi:7")
        base.update(kwargs)
        return ProfileContext(**base)

    def test_a_stale_record_is_not_reused(self):
        path = os.path.join(self.temp_dir(), "profiles.json")
        profiles = LatencyProfiles(path, max_age=1.0)
        profiles.remember("net", "wifi-power-save", "Wi-Fi", "wlan0", {},
                          self.context())
        profiles.data["networks"]["net"]["updated"] -= 10
        entry, why = profiles.usable("net", self.context())
        self.assertIsNone(entry)
        self.assertIn("eskidi", why)

    def test_a_changed_condition_invalidates_the_record(self):
        path = os.path.join(self.temp_dir(), "profiles.json")
        profiles = LatencyProfiles(path)
        profiles.remember("net", "wifi-power-save", "Wi-Fi", "wlan0", {},
                          self.context())
        entry, why = profiles.usable("net", self.context(condition="load-up"))
        self.assertIsNone(entry)
        self.assertIn("koşul", why)

    def test_a_changed_target_set_invalidates_the_record(self):
        path = os.path.join(self.temp_dir(), "profiles.json")
        profiles = LatencyProfiles(path)
        profiles.remember("net", "wifi-power-save", "Wi-Fi", "wlan0", {},
                          self.context())
        entry, why = profiles.usable("net", self.context(targets="xyz"))
        self.assertIsNone(entry)
        self.assertIn("hedef", why)

    def test_an_old_schema_is_dropped_rather_than_misread(self):
        path = os.path.join(self.temp_dir(), "profiles.json")
        with open(path, "w", encoding="utf-8") as handle:
            json.dump({"version": 1, "networks": {"net": {"candidate": "x"}}},
                      handle)
        self.assertIsNone(LatencyProfiles(path).get("net"))

    async def test_a_verified_candidate_is_remembered_per_network(self):
        runner = FakeRunner()
        probe = StateProbe(runner, {("off", None, None, None): 12.0}, 20.0)
        directory = self.temp_dir()
        optimizer = self.make_optimizer(runner, probe, directory)
        status = await optimizer.optimize(network())
        self.assertEqual(status["state"], "active")
        with open(os.path.join(directory, "profiles.json"),
                  encoding="utf-8") as handle:
            stored = json.load(handle)["networks"]
        self.assertIn(network().key, stored)
        self.assertEqual(stored[network().key]["candidate"], "wifi-power-save")


# --------------------------------------------------------------------------- #
# hafif yeniden doğrulama
# --------------------------------------------------------------------------- #
class TestRevalidation(OptimizerCase):
    async def test_external_drift_clears_the_verified_gain(self):
        runner = FakeRunner()
        probe = StateProbe(runner, {("off", None, None, None): 12.0}, 20.0)
        optimizer = self.make_optimizer(runner, probe)
        status = await optimizer.optimize(network())
        self.assertEqual(status["state"], "active")

        runner.power["wlan0"] = "on"       # kullanıcı geri açtı
        optimizer._last_revalidate = 0.0
        # Histerezis: tek denetim yetmez.
        self.assertIsNone(await optimizer.revalidate(network()))
        optimizer._last_revalidate = 0.0
        result = await optimizer.revalidate(network())
        self.assertIsNotNone(result)
        self.assertEqual(result["state"], "external-change")
        self.assertFalse(result["active"])

    async def test_a_stable_profile_is_not_disturbed(self):
        runner = FakeRunner()
        probe = StateProbe(runner, {("off", None, None, None): 12.0}, 20.0)
        optimizer = self.make_optimizer(runner, probe)
        await optimizer.optimize(network())
        optimizer._last_revalidate = 0.0
        self.assertIsNone(await optimizer.revalidate(network()))
        self.assertEqual(optimizer.status.state, "active")

    async def test_revalidation_respects_the_cooldown(self):
        runner = FakeRunner()
        probe = StateProbe(runner, {("off", None, None, None): 12.0}, 20.0)
        optimizer = self.make_optimizer(runner, probe)
        await optimizer.optimize(network())
        runner.power["wlan0"] = "on"
        # Cooldown dolmadan denetim yapılmaz: salınım döngüsü kurulmaz.
        self.assertIsNone(await optimizer.revalidate(network()))


# --------------------------------------------------------------------------- #
# durum gösterimi
# --------------------------------------------------------------------------- #
class TestStatusRendering(unittest.TestCase):
    def line(self, **kwargs) -> str:
        data = {"enabled": True, "active": False, "state": "no-gain",
                "message": "mesaj"}
        data.update(kwargs)
        return cli._latency_line(data)

    def test_rollback_failure_is_not_reported_as_verified(self):
        text = self.line(state="rollback-failed", active=True)
        self.assertIn("geri alınamadı", text)
        self.assertNotIn("doğrulandı", text)

    def test_verified_state_is_reported_as_verified(self):
        self.assertIn("doğrulandı", self.line(state="active", active=True))

    def test_inconclusive_is_not_shown_as_no_gain(self):
        self.assertIn("belirsiz", self.line(state="inconclusive"))

    def test_corrupt_snapshot_is_visible(self):
        self.assertIn("bozuk", self.line(state="snapshot-corrupt"))

    def test_disabled_reads_as_off(self):
        self.assertIn("kapalı", self.line(enabled=False, state="disabled"))

    def test_busy_states_come_from_the_engine(self):
        self.assertEqual(cli.LATENCY_BUSY_STATES, engine_mod.BUSY_STATES)


if __name__ == "__main__":
    unittest.main(verbosity=2)


# --------------------------------------------------------------------------- #
# bypass yolunun kendi ek gecikmesi
# --------------------------------------------------------------------------- #
class TestProxyHandshakeLatency(unittest.IsolatedAsyncioTestCase):
    """Vekilin TCP/TLS *açılış* süresine eklediği gecikme.

    Bu bir oyun RTT'si testi DEĞİLDİR: vekil yalnız TCP 80/443 taşır ve
    oyunların UDP trafiği zaten vekile taşınmaz.
    """

    def proxy(self):
        from dpibypass.proxy import TransparentProxy
        return TransparentProxy(20443, lambda: None, lambda *a: False, None)

    async def test_upstream_connect_overlaps_the_first_byte_wait(self):
        """Bağlantı el sıkışması istemciyi beklerken kurulmalı, sonra değil."""
        import asyncio as aio
        from dpibypass import proxy as proxy_mod

        order = []

        async def slow_connect(self, loop, ip, port):
            order.append("connect-start")
            await aio.sleep(0.05)
            order.append("connect-done")
            return mock.MagicMock()

        async def slow_first_byte(sock, size):
            order.append("read-start")
            await aio.sleep(0.15)
            order.append("read-done")
            return b"\x16\x03\x01"

        instance = self.proxy()
        loop = mock.MagicMock()
        loop.sock_recv = slow_first_byte
        loop.sock_sendall = mock.AsyncMock()

        with mock.patch.object(proxy_mod.TransparentProxy, "_connect",
                               slow_connect), \
                mock.patch.object(proxy_mod, "original_dst",
                                  return_value=("198.51.100.5", 443)), \
                mock.patch.object(proxy_mod.TransparentProxy, "_splice",
                                  new=mock.AsyncMock(return_value=True)):
            await instance._handle(loop, mock.MagicMock())

        # Bağlantı, okuma bitmeden BAŞLAMIŞ ve bitmiş olmalı: el sıkışma
        # RTT'si okuma beklemesiyle örtüşüyor.
        self.assertLess(order.index("connect-start"), order.index("read-done"))
        self.assertLess(order.index("connect-done"), order.index("read-done"))

    async def test_a_failed_client_read_does_not_leak_the_upstream_socket(self):
        import asyncio as aio
        from dpibypass import proxy as proxy_mod

        upstream = mock.MagicMock()

        async def connect(self, loop, ip, port):
            await aio.sleep(0)
            return upstream

        async def failing_read(sock, size):
            raise OSError("istemci düştü")

        instance = self.proxy()
        loop = mock.MagicMock()
        loop.sock_recv = failing_read

        with mock.patch.object(proxy_mod.TransparentProxy, "_connect", connect), \
                mock.patch.object(proxy_mod, "original_dst",
                                  return_value=("198.51.100.5", 443)):
            await instance._handle(loop, mock.MagicMock())
        upstream.close.assert_called()

    def test_udp_and_quic_are_not_pulled_into_the_proxy(self):
        """Latency kipi adına oyun/UDP trafiği vekile taşınmaz."""
        from dpibypass.constants import REDIRECT_PORTS
        self.assertEqual(tuple(REDIRECT_PORTS), (80, 443))


# --------------------------------------------------------------------------- #
# ölçüm koşulları
# --------------------------------------------------------------------------- #
class TestConditions(unittest.TestCase):
    def probe(self, **kwargs) -> LatencyProbe:
        text = ("64 bytes from x: icmp_seq=1 ttl=57 time=9.0 ms\n\n"
                "--- x ping statistics ---\n"
                "3 packets transmitted, 1 received, 66% packet loss\n")
        runner = lambda cmd, **kw: subprocess.CompletedProcess(cmd, 0, text, "")
        return LatencyProbe(runner, lambda name: "/bin/ping",
                            quiet_seconds=0.05, **kwargs)

    def plan(self, condition: str):
        from dpibypass.latency.probe import ProbePlan
        return ProbePlan(endpoints=[spec("198.51.100.1")], condition=condition,
                         samples=8, warmup=True)

    def test_first_packet_condition_measures_only_the_first_packets(self):
        measurement = self.probe(first_packet_count=3).measure(
            self.plan("first-packet"))
        self.assertEqual(measurement.condition, "first-packet")
        self.assertEqual(measurement.endpoints[0].sent, 3)
        self.assertTrue(any("sessizlik" in note for note in measurement.notes))

    def test_idle_and_first_packet_results_are_never_compared(self):
        idle = self.probe().measure(self.plan("idle"))
        first = self.probe(first_packet_count=3).measure(
            self.plan("first-packet"))
        ok, why = idle.comparable_with(first)
        self.assertFalse(ok)
        self.assertIn("koşul", why)


# --------------------------------------------------------------------------- #
# netns düzeneğinin saf yardımcıları (root gerektirmez)
# --------------------------------------------------------------------------- #
def _netns_harness():
    """Düzeneği dosya yoluyla yükle: ``tests`` bir paket olmak zorunda kalmasın."""
    import importlib.util
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        "test_netns_latency.py")
    spec_obj = importlib.util.spec_from_file_location("netns_harness", path)
    module = importlib.util.module_from_spec(spec_obj)
    spec_obj.loader.exec_module(module)
    return module


class TestNetnsHelpers(unittest.TestCase):
    def test_sent_packet_counter_is_parsed(self):
        harness = _netns_harness()
        stats = ("qdisc fq_codel 8001: root refcnt 2 limit 10240p\n"
                 " Sent 123456 bytes 789 pkt (dropped 3, overlimits 0 "
                 "requeues 1)\n")
        self.assertEqual(harness.sent_packets(stats), 789)

    def test_counter_is_zero_when_the_line_is_absent(self):
        harness = _netns_harness()
        self.assertEqual(harness.sent_packets("qdisc noqueue 0: root\n"), 0)

    def test_every_created_resource_carries_the_project_prefix(self):
        harness = _netns_harness()
        for name in harness.NAMESPACES + (
                harness.VETH_CLIENT, harness.VETH_MID_A, harness.VETH_MID_B,
                harness.VETH_SERVER):
            self.assertTrue(name.startswith(harness.PREFIX), name)


# --------------------------------------------------------------------------- #
# tanı raporu gizliliği
# --------------------------------------------------------------------------- #
class TestDiagnosticReport(unittest.TestCase):
    def daemon(self):
        from dpibypass.daemon import Daemon
        instance = Daemon.__new__(Daemon)
        instance.latency = mock.MagicMock()
        instance.latency.settings = LatencySettings(
            targets=[TargetSpec("oyun.sunucum.net", 7777, "udp", label="Oyun")])
        instance.network = NetworkFingerprint(
            interface="wlan0", gateway="192.168.1.1",
            gateway_mac="aa:bb:cc:dd:ee:ff", ssid="EvimWiFi", link_type="wifi")
        instance._latency_status = lambda: {
            "targets": ["oyun.sunucum.net:7777 (UDP)"],
            "settings": {"targets": [{"host": "oyun.sunucum.net", "port": 7777}],
                         "sqm": False},
            "skipped": ["oyun.sunucum.net: DNS çözümlemesi 3 ms"],
            "message": "Doğrulandı: oyun.sunucum.net:7777 (UDP): -1.20 ms",
            "before": {"endpoints": [{
                "endpoint": {"host": "oyun.sunucum.net",
                             "address": "198.51.100.9",
                             "source": "192.168.1.5",
                             "display": "oyun.sunucum.net:7777 (UDP)",
                             "key": "abc123", "role": "user",
                             "method": "udp-echo", "port": 7777},
                "median_ms": 21.4}]},
            "after": None,
        }
        return instance

    def test_report_leaks_no_identity_even_in_free_text(self):
        report = json.dumps(self.daemon()._latency_report(), ensure_ascii=False)
        for secret in ("oyun.sunucum.net", "198.51.100.9", "192.168.1.5",
                       "EvimWiFi", "aa:bb:cc:dd:ee:ff", "192.168.1.1"):
            self.assertNotIn(secret, report, f"rapor {secret} sızdırdı")

    def test_report_keeps_the_measurement_data(self):
        report = self.daemon()._latency_report()
        endpoint = report["latency"]["before"]["endpoints"][0]
        self.assertEqual(endpoint["median_ms"], 21.4)
        self.assertEqual(endpoint["endpoint"]["method"], "udp-echo")
        self.assertEqual(endpoint["endpoint"]["role"], "user")
        self.assertTrue(report["redacted"])

    def test_report_counts_targets_without_naming_them(self):
        report = self.daemon()._latency_report()
        self.assertEqual(report["latency"]["settings"]["targets"], 1)


# --------------------------------------------------------------------------- #
# SQM kurtarma
# --------------------------------------------------------------------------- #
class TestSqmRecovery(unittest.TestCase):
    def test_rollback_treats_a_missing_resource_as_already_done(self):
        """Süreç uygulama ortasında ölürse tarif iyimserdir; kurtarma çalışmalı."""
        runner = FakeRunner()
        manager = SqmManager(runner, runner.which)
        # Hiçbir kaynak oluşturulmamış, ama tarif hepsini oluşturulmuş sayıyor.
        optimistic = SqmState(interface="eth0", egress_restore=["pfifo_fast"],
                              egress_applied=True, ifb_created=True,
                              ingress_qdisc_created=True, filter_added=True)
        self.assertTrue(manager.rollback(optimistic))
        self.assertFalse(optimistic.ifb_created)
        self.assertFalse(optimistic.filter_added)

    def test_the_pre_written_recipe_covers_every_resource(self):
        """Uygulamadan önce diske yazılan tarif iyimser olmalı."""
        from dpibypass.latency.engine import Environment, Step
        from dpibypass.latency.qdisc import QdiscSlot
        runner = FakeRunner()
        optimizer = LatencyOptimizer(
            runner=runner, which_fn=runner.which,
            state_path=os.path.join(tempfile.mkdtemp(), "s.json"),
            profile_path=os.path.join(tempfile.mkdtemp(), "p.json"))
        env = Environment(interface="eth0", link_type="ethernet",
                          qdisc_slots=[QdiscSlot("root", "pfifo_fast",
                                                 ["pfifo_fast"])],
                          sqm_possible=True)
        action = optimizer._prepare(Step("sqm", "0.9", "SQM"), env)[0]
        for key in ("egress_applied", "ifb_created", "ingress_qdisc_created",
                    "filter_added"):
            self.assertTrue(action.restore[key], key)


# --------------------------------------------------------------------------- #
# "denenmedi" ile "kazanç yok" ayrımı
# --------------------------------------------------------------------------- #
class TestHonestOutcomes(OptimizerCase):
    async def test_untried_candidates_are_not_reported_as_no_gain(self):
        """Hiçbir aday ölçülemediyse 'kazanç yok' demek dürüst değildir."""
        runner = FakeRunner()
        runner.set_ethernet("eth0")
        runner.default_dev = "eth0"
        probe = StateProbe(runner, {}, default=20.0)
        optimizer = self.make_optimizer(runner, probe, budget_seconds=-1.0)
        status = await optimizer.optimize(network("eth0", "ethernet"))
        self.assertEqual(status["state"], "unsupported")
        self.assertIn("denenmedi", status["message"])
        self.assertNotEqual(status["state"], "no-gain")

    async def test_no_gain_names_what_was_actually_tried(self):
        runner = FakeRunner()
        probe = StateProbe(runner, {}, default=20.0)
        optimizer = self.make_optimizer(runner, probe)
        status = await optimizer.optimize(network())
        if status["state"] != "no-gain":
            self.skipTest(f"bu koşuda sonuç {status['state']}")
        self.assertIn("Wi-Fi", status["message"])
        # "Artık daha düşük ms mümkün değil" iddiasına dönüşmemeli.
        self.assertIn("anlamına gelmez", status["message"])

    async def test_preserved_queue_is_reported_as_preserved_not_optimal(self):
        runner = FakeRunner()
        runner.set_qdisc("wlan0", "cake", {"bandwidth": "20Mbit"})
        probe = StateProbe(runner, {}, default=20.0)
        optimizer = self.make_optimizer(runner, probe)
        status = await optimizer.optimize(network())
        skipped = " ".join(status["skipped"])
        self.assertIn("korundu", skipped)
        self.assertNotIn("optimum", skipped)
        self.assertEqual(runner.kind_of("wlan0"), "cake")


# --------------------------------------------------------------------------- #
# ölçüm bütçesi ve p95 güvenilirliği
# --------------------------------------------------------------------------- #
class TestSamplingBudget(unittest.TestCase):
    def test_default_sample_count_supports_a_real_p95(self):
        self.assertGreaterEqual(LatencySettings().samples,
                                EndpointStats.P95_MIN_SAMPLES)

    def test_ping_deadline_scales_with_the_sample_count(self):
        """Sabit bir -w, uzun örnek dizisini sessizce keserdi."""
        seen = {}

        def runner(cmd, **kwargs):
            seen["cmd"] = cmd
            return subprocess.CompletedProcess(cmd, 0, "", "")

        probe = LatencyProbe(runner, lambda name: "/bin/ping", deadline=5,
                             interval=0.2)
        probe.sample_endpoint(spec(), 40)
        deadline = int(seen["cmd"][seen["cmd"].index("-w") + 1])
        self.assertGreaterEqual(deadline, 40 * 0.2)

    def test_a_full_scan_stays_inside_the_default_budget(self):
        """Varsayılan blok/örnek sayısı, süre bütçesini aşmamalı."""
        settings = LatencySettings()
        per_block = settings.samples * 0.2          # sn, hedefler paralel
        # tarama: aday başına 2 kol × scan_blocks, artı holdout
        per_candidate = per_block * 2 * settings.scan_blocks
        holdout = per_block * 2 * settings.holdout_blocks
        estimate = per_candidate * 4 + holdout      # 4 tipik aday
        self.assertLess(estimate, LatencyOptimizer.BUDGET_SECONDS,
                        f"tahmini süre {estimate:.0f} sn, bütçe "
                        f"{LatencyOptimizer.BUDGET_SECONDS} sn")
