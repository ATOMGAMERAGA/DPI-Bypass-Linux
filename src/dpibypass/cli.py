"""Komut satırı aracı: dpi-bypass

GUI olmadan da her şey buradan yönetilebilir.
"""

from __future__ import annotations

import argparse
import json
import sys
import time

from .constants import SOCKET_GROUP
from .ipc import IpcClient
from .version import APP_NAME, AUTHOR, __version__

GREEN = "\033[32m"
RED = "\033[31m"
YELLOW = "\033[33m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"


def _color(text: str, code: str) -> str:
    return text if not sys.stdout.isatty() else f"{code}{text}{RESET}"


def _fail(response: dict) -> int:
    print(_color("Hata: ", RED) + str(response.get("error")))
    if response.get("code") == "no-service":
        print(f"{DIM}Servisi başlatın: sudo systemctl start dpi-bypass{RESET}")
    elif response.get("code") == "permission":
        print(f"{DIM}Kullanıcınızı gruba ekleyin: "
              f"sudo usermod -aG {SOCKET_GROUP} $USER{RESET}")
    return 1


def cmd_status(client: IpcClient, args) -> int:
    response = client.call("status")
    if not response.get("ok"):
        return _fail(response)
    data = response["data"]
    if args.json:
        print(json.dumps(data, indent=2, ensure_ascii=False))
        return 0

    labels = {
        "active": _color("ETKİN", GREEN),
        "dns-only": _color("DNS KORUMASI", GREEN),
        "searching": _color("ARANIYOR", YELLOW),
        "starting": _color("BAŞLIYOR", YELLOW),
        "failed": _color("BAŞARISIZ", RED),
        "disabled": _color("KAPALI", DIM),
    }
    strategy = data.get("strategy")
    print(f"{BOLD}{APP_NAME} {data['version']}{RESET}")
    print(f"  Durum      : {labels.get(data['status'], data['status'])} "
          f"— {data['detail']}")
    print(f"  Operatör   : {data['isp']['label']} "
          f"(%{int(data['isp']['confidence'] * 100)} güven)")
    print(f"  Ağ         : {data['network'].get('name', '-')}"
          + (f" · AS{data['link']['asn']} {data['link']['as_name']}"
             if data['link'].get('as_name') else ""))
    method = f"{strategy['label']} ({strategy['name']})" if strategy else "gerekmiyor"
    print(f"  Yöntem     : {method}")
    print(f"  DNS        : {data['dns'].get('provider', '-')} "
          f"({data['dns'].get('query', 0)} sorgu)")
    print(f"  Yönlendirme: {data['firewall']['backend']} · "
          f"{data['firewall']['ips']} IP · kip {data['firewall']['mode']}")
    print(f"  Trafik     : {data['proxy']['connections']} bağlantı, "
          f"{data['proxy']['bypassed']} atlatıldı")
    return 0


def cmd_search(client: IpcClient, args) -> int:
    response = client.call("search", reason="komut satırı")
    if not response.get("ok"):
        return _fail(response)
    print("Yöntem aranıyor…")
    if args.wait:
        for _ in range(60):
            time.sleep(2)
            status = client.call("status")
            if not status.get("ok"):
                return _fail(status)
            if status["data"]["status"] not in ("searching", "starting"):
                return cmd_status(client, argparse.Namespace(json=False))
        print("Zaman aşımı.")
        return 1
    return 0


def cmd_test(client: IpcClient, args) -> int:
    response = client.call("test", strategy=args.strategy)
    if not response.get("ok"):
        return _fail(response)
    result = response["data"]
    if result["ok"]:
        print(_color("✓ ", GREEN) + f"{result['target']} erişilebilir "
              f"({result['latency_ms']} ms) — {result['label']}")
        return 0
    print(_color("✕ ", RED) + f"{result['target']} açılmadı: {result['error']}")
    return 1


def cmd_strategies(client: IpcClient, args) -> int:
    response = client.call("strategies")
    if not response.get("ok"):
        return _fail(response)
    for strategy in response["data"]:
        print(f"  {strategy['name']:<22} {strategy['label']}")
    return 0


def cmd_isps(client: IpcClient, args) -> int:
    response = client.call("isps")
    if not response.get("ok"):
        return _fail(response)
    for profile in response["data"]:
        print(f"  {profile['id']:<18} {profile['label']}")
    return 0


def cmd_detect(client: IpcClient, args) -> int:
    response = client.call("detect")
    if not response.get("ok"):
        return _fail(response)
    data = response["data"]
    print(f"Operatör : {data['isp']['label']} "
          f"(%{int(data['confidence'] * 100)} güven)")
    link = data["link"]
    print(f"Arayüz   : {link['interface']} ({link['link_type']})"
          + (f" · SSID {link['ssid']}" if link["ssid"] else ""))
    print(f"Genel IP : {link['public_ip']} · AS{link['asn']} {link['as_name']} "
          f"{link['country']}")
    return 0


def cmd_toggle(client: IpcClient, args) -> int:
    response = client.call("enable" if args.command == "enable" else "disable")
    if not response.get("ok"):
        return _fail(response)
    print("Koruma açıldı." if args.command == "enable" else "Koruma kapatıldı.")
    return 0


def cmd_logs(client: IpcClient, args) -> int:
    since = 0.0
    while True:
        response = client.call("logs", since=since)
        if not response.get("ok"):
            return _fail(response)
        for entry in response["data"]:
            since = entry["ts"]
            stamp = time.strftime("%H:%M:%S", time.localtime(entry["ts"]))
            print(f"{DIM}{stamp}{RESET} {entry['level']:<7} {entry['msg']}")
        if not args.follow:
            return 0
        time.sleep(2)


def cmd_set(client: IpcClient, args) -> int:
    values: dict = {}
    for item in args.pairs:
        if "=" not in item:
            print(f"'{item}' anahtar=değer biçiminde olmalı")
            return 1
        key, value = item.split("=", 1)
        if value.lower() in ("true", "evet", "on", "1"):
            parsed = True
        elif value.lower() in ("false", "hayır", "hayir", "off", "0"):
            parsed = False
        elif value.isdigit():
            parsed = int(value)
        else:
            parsed = value
        values[key.strip()] = parsed
    response = client.call("config.set", values=values)
    if not response.get("ok"):
        return _fail(response)
    print("Değişen ayarlar: " + (", ".join(response["data"]["changed"]) or "yok"))
    return 0


def cmd_config(client: IpcClient, args) -> int:
    response = client.call("config.get")
    if not response.get("ok"):
        return _fail(response)
    print(json.dumps(response["data"], indent=2, ensure_ascii=False))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="dpi-bypass",
        description=f"{APP_NAME} {__version__} — yazan: {AUTHOR}",
    )
    sub = parser.add_subparsers(dest="command")

    p_status = sub.add_parser("status", help="genel durum")
    p_status.add_argument("--json", action="store_true")
    p_status.set_defaults(func=cmd_status)

    p_search = sub.add_parser("search", help="çalışan yöntemi yeniden ara")
    p_search.add_argument("--wait", action="store_true", help="bitene kadar bekle")
    p_search.set_defaults(func=cmd_search)

    p_test = sub.add_parser("test", help="discord.com erişimini sına")
    p_test.add_argument("strategy", nargs="?", help="belirli bir yöntem adı")
    p_test.set_defaults(func=cmd_test)

    sub.add_parser("strategies", help="yöntem listesi").set_defaults(
        func=cmd_strategies)
    sub.add_parser("isps", help="operatör profilleri").set_defaults(func=cmd_isps)
    sub.add_parser("detect", help="operatörü yeniden sapta").set_defaults(
        func=cmd_detect)
    sub.add_parser("enable", help="korumayı aç").set_defaults(func=cmd_toggle)
    sub.add_parser("disable", help="korumayı kapat").set_defaults(func=cmd_toggle)
    sub.add_parser("config", help="ayarları göster").set_defaults(func=cmd_config)

    p_logs = sub.add_parser("logs", help="servis günlüğü")
    p_logs.add_argument("-f", "--follow", action="store_true")
    p_logs.set_defaults(func=cmd_logs)

    p_set = sub.add_parser("set", help="ayar değiştir (örn: mode=all)")
    p_set.add_argument("pairs", nargs="+")
    p_set.set_defaults(func=cmd_set)

    args = parser.parse_args(argv)
    if not getattr(args, "func", None):
        parser.print_help()
        return 0

    client = IpcClient()
    try:
        return args.func(client, args)
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
