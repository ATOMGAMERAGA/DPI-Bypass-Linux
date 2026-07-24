"""Çekirdek yönlendirme kuralları (nftables, yoksa iptables).

Yönlendirilen trafik yerel şeffaf vekile düşer. Kendi trafiğimiz ``FWMARK``
ile işaretlendiği için kurallardan muaftır; böylece döngü oluşmaz.

Yalnızca TCP 80/443 ve DNS (53) yönlendirilir. ICMP (ping), UDP oyun
trafiği, VoIP ve diğer her şey dokunulmadan geçer — bu yüzden gecikme ya da
ping üzerinde ölçülebilir bir etki oluşmaz.
"""

from __future__ import annotations

import ipaddress
import logging
from typing import Iterable

from .constants import DNS_PORT, FWMARK, PROXY_PORT, REDIRECT_PORTS
from .util import run, which

log = logging.getLogger("dpibypass.fw")

TABLE = "dpibypass"
CHAIN = "dpibypass"

PRIVATE4 = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16",
            "100.64.0.0/10", "224.0.0.0/4", "240.0.0.0/4")
PRIVATE6 = ("fc00::/7", "fe80::/10", "ff00::/8", "::1/128")


class FirewallError(RuntimeError):
    pass


class Firewall:
    """nftables ya da iptables üzerinden yönlendirme kurallarını yönetir."""

    def __init__(self, proxy_port: int = PROXY_PORT, dns_port: int = DNS_PORT,
                 fwmark: int = FWMARK) -> None:
        self.proxy_port = proxy_port
        self.dns_port = dns_port
        self.fwmark = fwmark
        self.backend = self._pick_backend()
        self.applied = False
        self.mode = "smart"
        self.dns_intercept = True
        self.block_quic = True
        self._ips4: set[str] = set()
        self._ips6: set[str] = set()

    # -- arka uç seçimi ----------------------------------------------------
    @staticmethod
    def _pick_backend() -> str | None:
        if which("nft"):
            probe = run(["nft", "list", "ruleset"], timeout=10)
            if probe.returncode == 0:
                return "nft"
        if which("iptables"):
            return "iptables"
        return None

    def describe(self) -> str:
        return {"nft": "nftables", "iptables": "iptables"}.get(self.backend or "", "yok")

    # -- genel API ---------------------------------------------------------
    def apply(self, mode: str = "smart", dns_intercept: bool = True,
              block_quic: bool = True) -> None:
        """Kuralları (yeniden) kur. ``mode``: smart | all | off."""
        self.mode = mode
        self.dns_intercept = dns_intercept
        self.block_quic = block_quic
        if self.backend is None:
            raise FirewallError(
                "Ne nftables ne iptables bulundu; yönlendirme kurulamıyor."
            )
        self.clear()
        if mode == "off":
            self.applied = False
            return
        if self.backend == "nft":
            self._apply_nft()
        else:
            self._apply_iptables()
        self.applied = True
        log.info("Yönlendirme kuralları kuruldu (%s, mod=%s)", self.describe(), mode)

    def clear(self) -> None:
        if self.backend == "nft":
            run(["nft", "delete", "table", "ip", TABLE], timeout=10)
            run(["nft", "delete", "table", "ip6", TABLE], timeout=10)
        elif self.backend == "iptables":
            self._clear_iptables()
        self.applied = False

    def add_ips(self, ips: Iterable[str]) -> int:
        """Çözümlenen IP'leri yönlendirilecekler kümesine ekle."""
        if not self.applied or self.mode != "smart":
            return 0
        new4, new6 = [], []
        for raw in ips:
            try:
                addr = ipaddress.ip_address(raw)
            except ValueError:
                continue
            if addr.is_private or addr.is_loopback or addr.is_link_local:
                continue
            if addr.version == 4 and raw not in self._ips4:
                self._ips4.add(raw)
                new4.append(raw)
            elif addr.version == 6 and raw not in self._ips6:
                self._ips6.add(raw)
                new6.append(raw)
        if not new4 and not new6:
            return 0
        if self.backend == "nft":
            if new4:
                run(["nft", "add", "element", "ip", TABLE, "blocked4",
                     "{ " + ", ".join(new4) + " }"], timeout=10)
            if new6:
                run(["nft", "add", "element", "ip6", TABLE, "blocked6",
                     "{ " + ", ".join(new6) + " }"], timeout=10)
        else:
            for ip in new4:
                self._iptables_add_ip(ip)
        return len(new4) + len(new6)

    def status(self) -> dict:
        return {
            "backend": self.describe(),
            "applied": self.applied,
            "mode": self.mode,
            "ips": len(self._ips4) + len(self._ips6),
            "dns_intercept": self.dns_intercept,
            "block_quic": self.block_quic,
        }

    # -- nftables ----------------------------------------------------------
    def _apply_nft(self) -> None:
        ports = ", ".join(str(p) for p in REDIRECT_PORTS)
        mark = f"0x{self.fwmark:08x}"

        rules4 = [f"meta mark {mark} return"]
        if self.dns_intercept:
            rules4.append(f"udp dport 53 redirect to :{self.dns_port}")
            rules4.append(f"tcp dport 53 redirect to :{self.dns_port}")
        rules4.append("ip daddr { " + ", ".join(PRIVATE4) + " } return")
        if self.mode == "all":
            rules4.append(f"tcp dport {{ {ports} }} redirect to :{self.proxy_port}")
        else:
            rules4.append(
                f"ip daddr @blocked4 tcp dport {{ {ports} }} "
                f"redirect to :{self.proxy_port}"
            )

        quic4 = []
        if self.block_quic:
            quic4.append(f"meta mark {mark} return")
            if self.mode == "all":
                quic4.append("udp dport 443 reject with icmp type port-unreachable")
            else:
                quic4.append(
                    "ip daddr @blocked4 udp dport 443 reject "
                    "with icmp type port-unreachable"
                )

        script = [
            f"table ip {TABLE} {{",
            "  set blocked4 { type ipv4_addr; flags interval; }",
            f"  chain {CHAIN}_nat {{",
            "    type nat hook output priority dstnat; policy accept;",
            *[f"    {r}" for r in rules4],
            "  }",
        ]
        if quic4:
            script += [
                f"  chain {CHAIN}_quic {{",
                "    type filter hook output priority filter; policy accept;",
                *[f"    {r}" for r in quic4],
                "  }",
            ]
        script.append("}")

        # IPv6 (yalnız TCP yönlendirmesi; DNS zaten IPv4 üzerinden yakalanır)
        rules6 = [f"meta mark {mark} return",
                  "ip6 daddr { " + ", ".join(PRIVATE6) + " } return"]
        if self.mode == "all":
            rules6.append(f"tcp dport {{ {ports} }} redirect to :{self.proxy_port}")
        else:
            rules6.append(
                f"ip6 daddr @blocked6 tcp dport {{ {ports} }} "
                f"redirect to :{self.proxy_port}"
            )
        script += [
            f"table ip6 {TABLE} {{",
            "  set blocked6 { type ipv6_addr; flags interval; }",
            f"  chain {CHAIN}_nat {{",
            "    type nat hook output priority dstnat; policy accept;",
            *[f"    {r}" for r in rules6],
            "  }",
            "}",
        ]

        text = "\n".join(script) + "\n"
        res = run(["nft", "-f", "-"], input_text=text, timeout=20)
        if res.returncode != 0:
            log.error("nft kuralları uygulanamadı: %s", res.stderr.strip())
            log.debug("Kural metni:\n%s", text)
            raise FirewallError(res.stderr.strip() or "nft hatası")

        # Zaten bilinen IP'leri kümeye geri koy
        if self._ips4 or self._ips6:
            saved4, saved6 = list(self._ips4), list(self._ips6)
            self._ips4.clear()
            self._ips6.clear()
            self.applied = True
            self.add_ips(saved4 + saved6)

    # -- iptables ----------------------------------------------------------
    def _apply_iptables(self) -> None:
        ipt = ["iptables", "-w", "5"]
        run([*ipt, "-t", "nat", "-N", CHAIN], timeout=10)
        run([*ipt, "-t", "nat", "-F", CHAIN], timeout=10)
        run([*ipt, "-t", "nat", "-A", CHAIN, "-m", "mark",
             "--mark", str(self.fwmark), "-j", "RETURN"], timeout=10)
        if self.dns_intercept:
            for proto in ("udp", "tcp"):
                run([*ipt, "-t", "nat", "-A", CHAIN, "-p", proto, "--dport", "53",
                     "-j", "REDIRECT", "--to-ports", str(self.dns_port)], timeout=10)
        for net in PRIVATE4:
            run([*ipt, "-t", "nat", "-A", CHAIN, "-d", net, "-j", "RETURN"], timeout=10)
        if self.mode == "all":
            for port in REDIRECT_PORTS:
                run([*ipt, "-t", "nat", "-A", CHAIN, "-p", "tcp", "--dport", str(port),
                     "-j", "REDIRECT", "--to-ports", str(self.proxy_port)], timeout=10)
        run([*ipt, "-t", "nat", "-C", "OUTPUT", "-j", CHAIN], timeout=10)
        run([*ipt, "-t", "nat", "-A", "OUTPUT", "-j", CHAIN], timeout=10)

        if self.block_quic and self.mode == "all":
            run([*ipt, "-A", "OUTPUT", "-p", "udp", "--dport", "443",
                 "-m", "mark", "!", "--mark", str(self.fwmark),
                 "-j", "REJECT", "--reject-with", "icmp-port-unreachable"], timeout=10)

        for ip in list(self._ips4):
            self._iptables_add_ip(ip)

    def _iptables_add_ip(self, ip: str) -> None:
        ipt = ["iptables", "-w", "5"]
        for port in REDIRECT_PORTS:
            run([*ipt, "-t", "nat", "-A", CHAIN, "-d", ip, "-p", "tcp",
                 "--dport", str(port), "-j", "REDIRECT",
                 "--to-ports", str(self.proxy_port)], timeout=10)
        if self.block_quic:
            run([*ipt, "-A", "OUTPUT", "-d", ip, "-p", "udp", "--dport", "443",
                 "-m", "mark", "!", "--mark", str(self.fwmark),
                 "-j", "REJECT", "--reject-with", "icmp-port-unreachable"], timeout=10)

    def _clear_iptables(self) -> None:
        ipt = ["iptables", "-w", "5"]
        while run([*ipt, "-t", "nat", "-C", "OUTPUT", "-j", CHAIN],
                  timeout=10).returncode == 0:
            run([*ipt, "-t", "nat", "-D", "OUTPUT", "-j", CHAIN], timeout=10)
        run([*ipt, "-t", "nat", "-F", CHAIN], timeout=10)
        run([*ipt, "-t", "nat", "-X", CHAIN], timeout=10)
        # QUIC reddetme kuralları
        for ip in list(self._ips4):
            run([*ipt, "-D", "OUTPUT", "-d", ip, "-p", "udp", "--dport", "443",
                 "-m", "mark", "!", "--mark", str(self.fwmark),
                 "-j", "REJECT", "--reject-with", "icmp-port-unreachable"], timeout=10)
        run([*ipt, "-D", "OUTPUT", "-p", "udp", "--dport", "443",
             "-m", "mark", "!", "--mark", str(self.fwmark),
             "-j", "REJECT", "--reject-with", "icmp-port-unreachable"], timeout=10)
