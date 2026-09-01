"""İzole gerçek Linux veri yolu testleri (opt-in).

Mock testler mantığı doğrular, veri yolunu doğrulamaz. Bu düzenek üç network
namespace kurar ve trafiğin gerçekten uygulanan kuyruktan geçtiğini sayaçlarla
gösterir::

    [istemci] --veth--> [darboğaz] --veth--> [hedef]
       kuyruk aday        sabit yol gecikmesi + KONTROL EDİLMEYEN
       burada denenir     dış kuyruk (tbf, büyük tampon)

Darboğaz namespace'i kasıtlıdır: gerçek hayatta modem/ISS kuyruğu bizim
kontrolümüzde değildir. Yalnız istemcideki tek kuyruğu ölçüp "bütün interneti
modelledik" demiyoruz.

Çalıştırma
----------
Bu testler **varsayılan olarak atlanır**. Root yetkisi, ``ip`` ve ``tc``
gerektirir ve yalnız açıkça istendiğinde çalışır::

    sudo DPIBYPASS_NETNS_TESTS=1 python3 -m unittest tests.test_netns_latency -v

Güvenlik
--------
* Ana makinenin fiziksel NIC'ine, default route'una ve firewall'una
  DOKUNULMAZ. Bütün kaynaklar ``dpib-`` önekli ve tam kimlikli oluşturulur;
  temizleme yalnız bunları hedefler.
* Üretim daemon'ının sanal/VPN arayüzlerini değiştirmeme koruması
  KAPATILMAZ. Testler namespace kapsamlı ayrı bir komut çalıştırıcı
  kullanır; bu, testin kendi yetkisidir.
* Buradaki kazanç **simüle edilmiş** bir ağda ölçülür. Kullanıcının
  ISS'sinde ölçülmüş kazanç değildir ve öyle sunulamaz.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))), "src"))

from dpibypass.latency import qdisc as qdiscmod  # noqa: E402
from dpibypass.latency.metrics import CONDITION_IDLE  # noqa: E402
from dpibypass.latency.probe import (LatencyProbe, PathResolver,  # noqa: E402
                                     ProbePlan, TargetResolver, TargetSpec,
                                     build_plan)

PREFIX = "dpib"
NS_CLIENT = f"{PREFIX}-cli"
NS_MIDDLE = f"{PREFIX}-mid"
NS_SERVER = f"{PREFIX}-srv"
NAMESPACES = (NS_CLIENT, NS_MIDDLE, NS_SERVER)

VETH_CLIENT = f"{PREFIX}-vc0"
VETH_MID_A = f"{PREFIX}-vm0"
VETH_MID_B = f"{PREFIX}-vm1"
VETH_SERVER = f"{PREFIX}-vs0"

CLIENT_IP = "10.77.1.1"
MID_A_IP = "10.77.1.2"
MID_B_IP = "10.77.2.1"
SERVER_IP = "10.77.2.2"

#: Simüle edilen tek yön yol gecikmesi (gidiş-dönüş ≈ 2×).
PATH_DELAY_MS = 20
#: Darboğazın kapasitesi ve kasıtlı olarak büyük tamponu (bufferbloat).
BOTTLENECK_KBIT = 10000
BOTTLENECK_LIMIT = 2000        # paket; kontrol edilmeyen şişkin kuyruk

ENABLED = os.environ.get("DPIBYPASS_NETNS_TESTS") == "1"


def _missing_requirement() -> str:
    if not ENABLED:
        return ("opt-in: DPIBYPASS_NETNS_TESTS=1 verilmedi "
                "(atlandı — BAŞARILI SAYILMAZ)")
    if not hasattr(os, "geteuid") or os.geteuid() != 0:
        return "root yetkisi yok; namespace kurulamaz (atlandı)"
    for tool in ("ip", "tc", "ping"):
        if shutil.which(tool) is None:
            return f"{tool} bulunamadı (atlandı)"
    probe = subprocess.run(["ip", "netns", "list"], capture_output=True,
                           text=True)
    if probe.returncode != 0:
        return f"ip netns kullanılamıyor: {probe.stderr.strip()} (atlandı)"
    return ""


def sh(*args, check: bool = True, timeout: int = 20):
    result = subprocess.run(list(args), capture_output=True, text=True,
                            timeout=timeout)
    if check and result.returncode != 0:
        raise RuntimeError(f"{' '.join(args)} → rc={result.returncode} "
                           f"{result.stderr.strip()}")
    return result


def ns(namespace: str, *args, **kwargs):
    return sh("ip", "netns", "exec", namespace, *args, **kwargs)


def ns_runner(namespace: str):
    """``dpibypass`` modüllerinin namespace içinde çalışması için çalıştırıcı."""
    def runner(cmd, timeout: int = 20, env=None, **_kwargs):
        full = ["ip", "netns", "exec", namespace] + list(cmd)
        child_env = None
        if env:
            child_env = dict(os.environ)
            child_env.update({str(k): str(v) for k, v in env.items()})
        try:
            return subprocess.run(full, capture_output=True, text=True,
                                  timeout=timeout, env=child_env)
        except subprocess.TimeoutExpired:
            return subprocess.CompletedProcess(full, 124, "", "zaman aşımı")
    return runner


def teardown_topology() -> None:
    """Yalnız bu testin oluşturduğu, tam kimlikli kaynakları kaldır."""
    for namespace in NAMESPACES:
        sh("ip", "netns", "del", namespace, check=False)
    for device in (VETH_CLIENT, VETH_MID_A, VETH_MID_B, VETH_SERVER):
        sh("ip", "link", "del", device, check=False)


def build_topology() -> None:
    teardown_topology()
    for namespace in NAMESPACES:
        sh("ip", "netns", "add", namespace)

    sh("ip", "link", "add", VETH_CLIENT, "type", "veth", "peer", "name",
       VETH_MID_A)
    sh("ip", "link", "add", VETH_MID_B, "type", "veth", "peer", "name",
       VETH_SERVER)
    sh("ip", "link", "set", VETH_CLIENT, "netns", NS_CLIENT)
    sh("ip", "link", "set", VETH_MID_A, "netns", NS_MIDDLE)
    sh("ip", "link", "set", VETH_MID_B, "netns", NS_MIDDLE)
    sh("ip", "link", "set", VETH_SERVER, "netns", NS_SERVER)

    ns(NS_CLIENT, "ip", "addr", "add", f"{CLIENT_IP}/24", "dev", VETH_CLIENT)
    ns(NS_MIDDLE, "ip", "addr", "add", f"{MID_A_IP}/24", "dev", VETH_MID_A)
    ns(NS_MIDDLE, "ip", "addr", "add", f"{MID_B_IP}/24", "dev", VETH_MID_B)
    ns(NS_SERVER, "ip", "addr", "add", f"{SERVER_IP}/24", "dev", VETH_SERVER)
    for namespace, device in ((NS_CLIENT, VETH_CLIENT), (NS_MIDDLE, VETH_MID_A),
                              (NS_MIDDLE, VETH_MID_B), (NS_SERVER, VETH_SERVER)):
        ns(namespace, "ip", "link", "set", device, "up")
        ns(namespace, "ip", "link", "set", "lo", "up")

    ns(NS_CLIENT, "ip", "route", "add", "default", "via", MID_A_IP)
    ns(NS_SERVER, "ip", "route", "add", "default", "via", MID_B_IP)
    ns(NS_MIDDLE, "sysctl", "-q", "-w", "net.ipv4.ip_forward=1")

    # Sabit yol gecikmesi (her iki yönde) — fiziğin payı.
    ns(NS_MIDDLE, "tc", "qdisc", "replace", "dev", VETH_MID_A, "root",
       "netem", "delay", f"{PATH_DELAY_MS}ms")
    # KONTROL EDİLMEYEN dış kuyruk: sınırlı kapasite + şişkin tampon.
    ns(NS_MIDDLE, "tc", "qdisc", "replace", "dev", VETH_MID_B, "root",
       "tbf", "rate", f"{BOTTLENECK_KBIT}kbit", "burst", "32kb",
       "limit", f"{BOTTLENECK_LIMIT * 1500}")


def client_probe() -> LatencyProbe:
    return LatencyProbe(ns_runner(NS_CLIENT), shutil.which, samples=20,
                        deadline=8, interval=0.05)


def client_plan(samples: int = 20) -> ProbePlan:
    runner = ns_runner(NS_CLIENT)
    resolver = TargetResolver(path_resolver=PathResolver(runner, shutil.which))
    return build_plan([TargetSpec(SERVER_IP, 0, "icmp", label="hedef ns")],
                      VETH_CLIENT, MID_A_IP, resolver=resolver,
                      condition=CONDITION_IDLE, samples=samples, warmup=True)


def qdisc_stats(namespace: str, device: str) -> str:
    return ns(namespace, "tc", "-s", "qdisc", "show", "dev", device).stdout


def sent_packets(stats: str) -> int:
    for line in stats.splitlines():
        line = line.strip()
        if line.startswith("Sent "):
            try:
                return int(line.split()[3])
            except (IndexError, ValueError):
                return 0
    return 0


class NetnsCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        reason = _missing_requirement()
        if reason:
            raise unittest.SkipTest(reason)
        build_topology()
        cls.addClassCleanup(teardown_topology)


class TestDatapath(NetnsCase):
    """Uygulanan qdisc'ten trafik gerçekten geçiyor mu?"""

    def test_applied_qdisc_actually_carries_traffic(self):
        runner = ns_runner(NS_CLIENT)
        runner(["tc", "qdisc", "replace", "dev", VETH_CLIENT, "root",
                "fq_codel"])
        before = sent_packets(qdisc_stats(NS_CLIENT, VETH_CLIENT))
        ns(NS_CLIENT, "ping", "-n", "-c", "5", "-i", "0.2", SERVER_IP)
        after = sent_packets(qdisc_stats(NS_CLIENT, VETH_CLIENT))
        self.assertGreater(after, before,
                           "uygulanan qdisc üzerinden paket geçmedi")
        self.assertIn("fq_codel", qdisc_stats(NS_CLIENT, VETH_CLIENT))

    def test_measured_rtt_matches_the_simulated_path_delay(self):
        measurement = client_probe().measure(client_plan())
        self.assertTrue(measurement.endpoints, "hedef ölçülemedi")
        endpoint = measurement.endpoints[0]
        self.assertIsNotNone(endpoint.median_ms)
        # Tek yön 20 ms → gidiş-dönüş ≈ 40 ms (netem yalnız bir yönde).
        self.assertGreater(endpoint.median_ms, PATH_DELAY_MS * 0.8)
        self.assertLess(endpoint.median_ms, PATH_DELAY_MS * 4)

    def test_probe_reports_the_real_path_interface(self):
        plan = client_plan()
        self.assertTrue(plan.path_verified)
        self.assertEqual(plan.endpoints[0].spec.interface, VETH_CLIENT)
        self.assertEqual(plan.endpoints[0].spec.source, CLIENT_IP)


class TestQueueDisciplines(NetnsCase):
    """FIFO tabanı · yalnız AQM · gerçek shaping+AQM karşılaştırması."""

    def apply_client_qdisc(self, *args) -> None:
        runner = ns_runner(NS_CLIENT)
        result = runner(["tc", "qdisc", "replace", "dev", VETH_CLIENT, "root"]
                        + list(args))
        self.assertEqual(result.returncode, 0, result.stderr)

    def loaded_rtt(self, seconds: float = 6.0) -> float:
        """Upload yükü altında RTT medyanı."""
        flood = subprocess.Popen(
            ["ip", "netns", "exec", NS_CLIENT, "ping", "-n", "-q", "-f",
             "-s", "1400", "-w", str(int(seconds)), SERVER_IP],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            time.sleep(0.7)
            measurement = client_probe().measure(client_plan(samples=25))
        finally:
            flood.terminate()
            try:
                flood.wait(timeout=5)
            except subprocess.TimeoutExpired:
                flood.kill()
        endpoint = measurement.endpoints[0]
        return endpoint.p95_ms if endpoint.p95_ms is not None else float("inf")

    def test_shaping_beats_a_bloated_fifo_under_load(self):
        """Gerçek bandwidth ile shaping, şişkin FIFO'dan iyi olmalı."""
        self.apply_client_qdisc("pfifo", "limit", "1000")
        fifo_p95 = self.loaded_rtt()

        shaped = ns_runner(NS_CLIENT)(
            ["tc", "qdisc", "replace", "dev", VETH_CLIENT, "root", "cake",
             "bandwidth", f"{int(BOTTLENECK_KBIT * 0.9)}kbit", "besteffort"])
        if shaped.returncode != 0:
            self.apply_client_qdisc("fq_codel")
            self.skipTest("sch_cake yok; CAKE karşılaştırması yapılamadı")
        shaped_p95 = self.loaded_rtt()

        # Bu SİMÜLE edilmiş bir ağdır; kullanıcının hattında ölçülmüş kazanç
        # değildir. Burada aranan şey mekanizmanın çalıştığıdır.
        self.assertLess(shaped_p95, fifo_p95,
                        f"shaping yük altında p95'i düşürmedi "
                        f"(fifo {fifo_p95:.1f} ms → cake {shaped_p95:.1f} ms)")

    def test_no_gain_scenario_does_not_fabricate_an_improvement(self):
        """Darboğaz kuyruğu yokken kuyruk değişimi kazanç üretmemeli."""
        # Dış darboğazı geçici olarak kaldır: kalan tek şey yol gecikmesidir
        # ve hiçbir istemci kuyruğu bunu kısaltamaz.
        ns(NS_MIDDLE, "tc", "qdisc", "del", "dev", VETH_MID_B, "root",
           check=False)
        self.addCleanup(
            ns, NS_MIDDLE, "tc", "qdisc", "replace", "dev", VETH_MID_B,
            "root", "tbf", "rate", f"{BOTTLENECK_KBIT}kbit", "burst", "32kb",
            "limit", f"{BOTTLENECK_LIMIT * 1500}")

        from dpibypass.latency import analysis
        probe = client_probe()
        control, treatment = [], []
        for index in range(4):
            self.apply_client_qdisc("pfifo", "limit", "1000")
            control.append(probe.measure(client_plan(samples=15)))
            self.apply_client_qdisc("fq_codel")
            treatment.append(probe.measure(client_plan(samples=15)))
        result = analysis.compare(control, treatment, seed=1, resamples=400)
        self.assertNotEqual(
            result.outcome, analysis.OUTCOME_GAIN,
            f"yol gecikmesi senaryosunda uydurma kazanç: {result.reason}")


class TestRestore(NetnsCase):
    """Geri alma yapılandırmayı birebir kuruyor mu, artık kaynak kalıyor mu?"""

    def test_restore_recipe_reproduces_the_configuration(self):
        runner = ns_runner(NS_CLIENT)
        runner(["tc", "qdisc", "replace", "dev", VETH_CLIENT, "root",
                "fq_codel", "limit", "10240", "target", "5000us"])
        topology = qdiscmod.read_topology(runner, shutil.which, VETH_CLIENT)
        slots, notes = qdiscmod.plan_slots(topology, VETH_CLIENT, runner=runner)
        self.assertTrue(slots, f"aday yuvası bulunamadı: {notes}")
        before = qdiscmod.normalize(
            runner(["tc", "-d", "qdisc", "show", "dev", VETH_CLIENT]).stdout)

        runner(["tc", "qdisc", "replace", "dev", VETH_CLIENT, "root", "fq"])
        runner(qdiscmod.restore_command(VETH_CLIENT, slots[0]))
        after = qdiscmod.normalize(
            runner(["tc", "-d", "qdisc", "show", "dev", VETH_CLIENT]).stdout)
        self.assertEqual(before, after)

    def test_sqm_rollback_leaves_no_orphan_ifb_or_filter(self):
        from dpibypass.latency.sqm import (IFB_DEVICE, SqmCapacity, SqmManager)
        runner = ns_runner(NS_CLIENT)
        runner(["tc", "qdisc", "replace", "dev", VETH_CLIENT, "root",
                "pfifo_fast"])
        manager = SqmManager(runner, shutil.which)
        try:
            state = manager.apply(
                VETH_CLIENT,
                SqmCapacity(egress_kbit=BOTTLENECK_KBIT,
                            ingress_kbit=BOTTLENECK_KBIT, source="user"),
                0.9, ["pfifo_fast"],
                engine="cake" if _cake_present(runner) else "htb+fq_codel")
        except Exception as exc:                       # pragma: no cover
            self.skipTest(f"SQM bu çekirdekte uygulanamadı: {exc}")

        self.assertTrue(manager.rollback(state))
        links = runner(["ip", "link", "show"]).stdout
        self.assertNotIn(IFB_DEVICE, links, "IFB aygıtı temizlenmedi")
        filters = runner(["tc", "filter", "show", "dev", VETH_CLIENT,
                          "parent", "ffff:"]).stdout
        self.assertEqual(filters.strip(), "", "ingress filtresi temizlenmedi")
        current = runner(["tc", "qdisc", "show", "dev", VETH_CLIENT]).stdout
        self.assertIn("pfifo_fast", current)

    def test_rollback_after_an_interrupted_apply_is_still_complete(self):
        from dpibypass.latency.sqm import IFB_DEVICE, SqmCapacity, SqmManager
        runner = ns_runner(NS_CLIENT)
        runner(["tc", "qdisc", "replace", "dev", VETH_CLIENT, "root",
                "pfifo_fast"])
        manager = SqmManager(runner, shutil.which)
        calls = {"n": 0}
        original = manager._run

        def fail_midway(cmd):
            calls["n"] += 1
            if calls["n"] > 3:
                raise RuntimeError("komut yarıda kaldı")
            return original(cmd)

        manager._run = fail_midway
        with self.assertRaises(Exception):
            manager.apply(VETH_CLIENT,
                          SqmCapacity(egress_kbit=BOTTLENECK_KBIT,
                                      ingress_kbit=BOTTLENECK_KBIT,
                                      source="user"),
                          0.9, ["pfifo_fast"])
        manager._run = original
        links = runner(["ip", "link", "show"]).stdout
        self.assertNotIn(IFB_DEVICE, links, "yarıda kalan uygulama IFB bıraktı")


def _cake_present(runner) -> bool:
    result = runner(["tc", "qdisc", "add", "dev", "lo", "root", "cake"])
    if result.returncode == 0:
        runner(["tc", "qdisc", "del", "dev", "lo", "root"])
        return True
    return False


if __name__ == "__main__":
    unittest.main(verbosity=2)
