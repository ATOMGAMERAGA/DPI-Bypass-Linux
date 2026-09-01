"""Komut satırı aracı: dpi-bypass

GUI olmadan da her şey buradan yönetilebilir.
"""

from __future__ import annotations

import argparse
import json
import sys
import time

from . import session_access
from . import latency as latency_states
from .ipc import IpcClient
from .util import is_root, run, which
from .version import APP_NAME, AUTHOR, __version__
from .vodafone import helper_path

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
    if response.get("code") in ("permission", "no-service"):
        # Gerçek sebebi tahmin etme: grup üyeliği, oturum grup listesi, servis
        # ve soket izinleri farklı sorunlardır ve farklı çözümleri vardır.
        report = session_access.analyze()
        if not report.ok:
            print(f"{DIM}{report.title}: {report.detail}{RESET}")
            if report.remedy:
                print(f"{DIM}Çözüm: {report.remedy}{RESET}")
            print(f"{DIM}Ayrıntı: dpi-bypass doctor{RESET}")
            return 1
    if response.get("code") == "no-service":
        print(f"{DIM}Servisi başlatın: sudo systemctl start dpi-bypass{RESET}")
    return 1


def cmd_doctor(client: IpcClient, args) -> int:
    """Denetim soketine erişimin neden çalışmadığını ayrıntılı gösterir."""
    report = session_access.analyze()
    if args.json:
        print(json.dumps(report.to_dict(), indent=2, ensure_ascii=False))
        return 0 if report.ok else 1

    print(f"{BOLD}DPI Bypass erişim tanısı{RESET}")
    print(f"  Kullanıcı      : {report.user or '-'} (uid {report.uid})")
    print(f"  Grup           : {report.group}"
          + (f" (gid {report.group_gid})" if report.group_gid is not None
             else _color(" — sistemde yok", RED)))
    print("  Grup veritabanı: "
          + (_color("üye", GREEN) if report.member_in_db
             else _color("üye değil", RED)))
    print("  Bu oturum      : "
          + (_color("grup alınmış", GREEN) if report.member_in_process
             else _color("grup alınmamış", YELLOW)))
    socket_facts = report.socket
    if socket_facts.exists:
        print(f"  Soket          : {socket_facts.path} · "
              f"uid {socket_facts.uid} · gid {socket_facts.gid}"
              + (f" ({socket_facts.group_name})" if socket_facts.group_name else "")
              + f" · kip 0{(socket_facts.mode or 0):o}")
    else:
        print(f"  Soket          : {_color('yok', RED)} ({socket_facts.path})")
    print("  Sonuç          : "
          + (_color(report.title, GREEN) if report.ok
             else _color(report.title, RED)))
    if report.detail:
        print(f"  Açıklama       : {report.detail}")
    if report.remedy and not report.ok:
        print(f"  Çözüm          : {report.remedy}")
    if report.can_reexec:
        print(f"{DIM}Bu durum oturum kapatmadan düzelir: 'dpi-bypass' ya da "
              f"arayüz kendini 'sg' ile yeniden başlatır.{RESET}")
    return 0 if report.ok else 1


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
    vodafone = data.get("vodafone")
    if vodafone:
        print(f"  Vodafone modu : {_vodafone_line(vodafone)}")
    latency = data.get("latency")
    if latency:
        print(f"  Ping düşürme  : {_latency_line(latency)}")
    return 0


def _vodafone_line(vodafone: dict) -> str:
    """Durum çıktısındaki tek satırlık Vodafone özeti."""
    if not vodafone.get("mode"):
        return _color("kapalı", DIM)
    if vodafone.get("active"):
        return (_color("etkin", GREEN)
                + f" ({vodafone.get('interface', '-')}, "
                f"TTL {vodafone.get('ttl', '-')}, "
                f"{vodafone.get('packets', 0)} paket)")
    if not vodafone.get("registered"):
        return _color("beklemede", YELLOW) + \
            f" — bu ağ kayıtlı değil ({vodafone.get('network', '-')})"
    return _color("beklemede", YELLOW) + " — kural uygulanmadı"


#: Ölçüm/aday taraması sürerken görülen durumlar. Motorla tek kaynaktan
#: beslenir; kopyalanmaz.
LATENCY_BUSY_STATES = latency_states.BUSY_STATES


def _latency_line(latency: dict) -> str:
    """Durum satırı. Kararlı durum KODUNA bakar, mesaj metnine değil."""
    state = latency.get("state")
    enabled = bool(latency.get("enabled"))
    # Hata durumları 'active' bayrağından ÖNCE gelir: geri alma başarısızsa
    # 'active' hâlâ True'dur (değişiklik sistemde duruyor olabilir), ama bu
    # "doğrulandı" demek değildir.
    if state == latency_states.STATE_ROLLBACK_FAILED:
        return _color("geri alınamadı", RED) + f" — {latency.get('message', '')}"
    if state == latency_states.STATE_SNAPSHOT_CORRUPT:
        return _color("geri alma kaydı bozuk", RED) + \
            f" — {latency.get('message', '')}"
    if state == latency_states.STATE_FAILED:
        return _color("başarısız", RED) + f" — {latency.get('message', '')}"
    if state == latency_states.STATE_EXTERNAL:
        return _color("dış değişiklik", YELLOW) + f" — {latency.get('message', '')}"
    if not enabled and state == latency_states.STATE_DISABLED:
        return _color("kapalı", DIM)
    if not enabled:
        return _color("kapalı", DIM)
    if state == latency_states.STATE_ACTIVE and latency.get("active"):
        return _color("doğrulandı", GREEN) + f" — {latency.get('message', '')}"
    if state in LATENCY_BUSY_STATES:
        return _color("ölçülüyor", YELLOW) + f" — {latency.get('message', '')}"
    if state == latency_states.STATE_NO_GAIN:
        return _color("kazanç yok", YELLOW) + f" — {latency.get('message', '')}"
    if state == latency_states.STATE_INCONCLUSIVE:
        return _color("belirsiz", YELLOW) + f" — {latency.get('message', '')}"
    if state == latency_states.STATE_UNSUPPORTED:
        return _color("desteklenmiyor", DIM) + f" — {latency.get('message', '')}"
    if state == latency_states.STATE_ALREADY:
        return _color("zaten yapılandırılmış", DIM) + \
            f" — {latency.get('message', '')}"
    return f"{latency.get('message', latency.get('state', '—'))}"


def _print_gain(gain: dict, indent: str = "  ") -> None:
    """Yalnızca gerçekten ölçülmüş farkı yazar."""
    labels = (("median_ms", "median"), ("p95_ms", "p95"),
              ("jitter_ms", "jitter"), ("packet_loss", "kayıp"))
    parts = [f"{gain[key]:+g} {label}" for key, label in labels
             if gain.get(key) is not None]
    if parts:
        print(f"{indent}Kazanç : " + " · ".join(parts))


def _print_measurement(measurement: dict, indent: str = "  ") -> None:
    """Ölçümü **endpoint bazında** yazdır; havuzlanmış tek sayı yeterli değil."""
    remote = measurement.get("remote") or {}
    gateway = measurement.get("gateway") or {}
    print(f"{indent}Koşul   : {measurement.get('condition', 'idle')}"
          + ("" if measurement.get("path_verified", True)
             else _color("  (ölçüm yolu doğrulanamadı)", RED)))
    print(f"{indent}Yöntem  : {measurement.get('method', '-')}")
    for endpoint in measurement.get("endpoints") or []:
        spec = endpoint.get("endpoint") or {}
        name = spec.get("display") or spec.get("address", "?")
        role = spec.get("role", "")
        tag = " [referans]" if role == "reference" else ""
        if endpoint.get("median_ms") is None:
            print(f"{indent}  {name}{tag}: yanıt yok "
                  f"({_errors_text(endpoint.get('errors') or {})})")
            continue
        line = (f"{indent}  {name}{tag}: median {endpoint['median_ms']:g} ms · "
                f"min {endpoint['minimum_ms']:g} ms · "
                f"p95 {endpoint['p95_ms']:g} ms · "
                f"jitter {endpoint['jitter_ms']:g} ms · "
                f"%{endpoint['failure_rate']:g} {endpoint.get('loss_label', '')}")
        if not endpoint.get("p95_reliable", True):
            line += " · p95 için örnek az"
        print(line)
        if endpoint.get("dns_ms") is not None:
            print(f"{indent}    DNS çözümleme {endpoint['dns_ms']:g} ms "
                  f"(RTT'ye dahil değil)")
        errors = endpoint.get("errors") or {}
        if errors:
            print(f"{indent}    hatalar: {_errors_text(errors)}")
    if remote.get("median_ms") is not None:
        print(f"{indent}Toplu   : median {remote['median_ms']:g} ms · "
              f"p95 {remote['p95_ms']:g} ms · jitter {remote['jitter_ms']:g} ms "
              f"(hedef başına eşit ağırlıklı, kapsam "
              f"{remote.get('endpoints_responding', 0)}/"
              f"{remote.get('endpoints_total', 0)})")
    else:
        print(f"{indent}Toplu   : ölçülemedi")
    if gateway.get("median_ms") is not None:
        print(f"{indent}Ağ geçidi: median {gateway['median_ms']:g} ms · "
              f"p95 {gateway['p95_ms']:g} ms · "
              f"jitter {gateway['jitter_ms']:g} ms")
    for note in (measurement.get("notes") or [])[:4]:
        print(f"{indent}  · {note}")


def _errors_text(errors: dict) -> str:
    labels = {"timeout": "zaman aşımı", "unreachable": "erişilemez",
              "refused": "reddedildi", "parse": "ayrıştırılamadı",
              "process": "komut hatası", "no-reply": "yanıt yok"}
    return ", ".join(f"{labels.get(key, key)}×{value}"
                     for key, value in sorted(errors.items())) or "-"


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


def cmd_vodafone(client: IpcClient, args) -> int:
    """Vodafone sınırsız kipi: durum görüntüle, aç, kapat."""
    if args.action == "status":
        response = client.call("vodafone.verify")
        if not response.get("ok"):
            return _fail(response)
        data = response["data"]
        print(f"{BOLD}Vodafone sınırsız modu{RESET}")
        print(f"  Durum   : {_vodafone_line(data)}")
        print(f"  Arka uç : {data.get('backend', '-')}")
        print(f"  Ağ      : {data.get('network', '-')}"
              + (" (kayıtlı)" if data.get("registered") else " (kayıtlı değil)"))
        print(f"  IPv6    : "
              + ("arayüzde kapatıldı" if data.get("ipv6_disabled")
                 else "dokunulmadı"))
        networks = data.get("networks") or []
        if networks:
            print("  Kayıtlı ağlar:")
            for net in networks:
                print(f"    · {net.get('name', '-')} "
                      f"({net.get('interface', '-')})")
        return 0

    action = "enable" if args.action == "on" else "disable"

    # Root isek doğrudan servise söyle; değilsek arayüzle aynı yetkilendirme
    # yolunu kullan (pkexec → polkit → yardımcı betik).
    if is_root():
        response = client.call(f"vodafone.{action}")
        if not response.get("ok"):
            return _fail(response)
    else:
        helper = helper_path()
        if helper is None:
            print(_color("Hata: ", RED) + "vodafone-helper bulunamadı; "
                  "kurulum eksik görünüyor.")
            return 1
        if which("pkexec") is None:
            print(_color("Hata: ", RED) + "pkexec bulunamadı; polkit paketi "
                  "kurulu değil.")
            return 1
        result = run(["pkexec", helper, action], timeout=300, capture=False)
        if result.returncode in (126, 127):
            print("İşlem iptal edildi (yetki verilmedi).")
            return 1
        if result.returncode != 0:
            print(_color("Hata: ", RED) + "Vodafone modu değiştirilemedi.")
            return 1

    print("Vodafone sınırsız modu açıldı." if args.action == "on"
          else "Vodafone sınırsız modu kapatıldı.")
    # Durum çıktısı yalnızca bilgilendirmedir; çıkış kodunu etkilemez.
    cmd_vodafone(client, argparse.Namespace(action="status"))
    return 0


def cmd_latency(client: IpcClient, args) -> int:
    """Ölçümlü düşük gecikme kipini yönet."""
    action = args.action
    params = list(getattr(args, "params", []) or [])

    if action == "target":
        return _latency_target(client, params)
    if action == "calibrate":
        return _latency_calibrate(client, params)
    if action == "cancel":
        response = client.call("latency.cancel")
        if not response.get("ok"):
            return _fail(response)
        print("Ölçüm durduruldu; uygulanmış ayarlar geri alındı.")
        _print_latency_status(response["data"])
        return 0

    if action == "report":
        response = client.call("latency.report")
        if not response.get("ok"):
            return _fail(response)
        print(json.dumps(response["data"], indent=2, ensure_ascii=False))
        return 0

    if action == "test":
        response = client.call("latency.test",
                               condition=getattr(args, "condition", "idle"))
        if not response.get("ok"):
            return _fail(response)
        print(f"{BOLD}Gecikme ölçümü{RESET}")
        _print_measurement(response["data"])
        return 0

    if action == "on":
        response = client.call("latency.enable")
        if not response.get("ok"):
            return _fail(response)
        print("Ping düşürme açıldı; her aday kontrol ölçümüyle iç içe "
              "(A/B/A) sınanıyor. Bu birkaç dakika sürebilir…")
        for _index in range(360):
            time.sleep(1)
            response = client.call("latency.status")
            if not response.get("ok"):
                return _fail(response)
            if response["data"].get("state") not in LATENCY_BUSY_STATES:
                break
    elif action == "off":
        response = client.call("latency.disable")
        if not response.get("ok"):
            return _fail(response)
        print("Ping düşürme kapatıldı; değişiklikler geri alındı.")
    else:
        response = client.call("latency.status")
        if not response.get("ok"):
            return _fail(response)

    data = response["data"]
    if getattr(args, "json", False):
        print(json.dumps(data, indent=2, ensure_ascii=False))
        return 0
    _print_latency_status(data)
    return 0


def _print_latency_status(data: dict) -> None:
    print(f"{BOLD}Ping düşürme (Beta){RESET}")
    print(f"  Tercih  : {'açık' if data.get('enabled') else 'kapalı'}"
          f"   ·   Yürürlükte: "
          f"{'evet' if data.get('active') else 'hayır'}")
    print(f"  Durum   : {_latency_line(data)}")
    print(f"  Arayüz  : {data.get('interface') or '-'}")
    settings = data.get("settings") or {}
    targets = settings.get("targets") or []
    if targets:
        print("  Hedefler: " + ", ".join(
            f"{item['host']}:{item['port']}/{item['protocol']}"
            if item.get("port") else f"{item['host']}/{item['protocol']}"
            for item in targets))
    else:
        print("  Hedefler: " + _color(
            "tanımlı değil — genel ağ göstergesi kullanılıyor "
            "(oyun ping'i değildir)", YELLOW))
    if settings.get("sqm"):
        print(f"  SQM     : açık · upload {settings.get('uplink_kbit', 0)} kbit · "
              f"download {settings.get('downlink_kbit', 0)} kbit")
    if data.get("applied"):
        print("  Uygulanan: " + ", ".join(data["applied"]))
    for note in data.get("skipped") or []:
        print(f"  Atlanan : {note}")
    for candidate in data.get("candidates") or []:
        mark = _color("✓", GREEN) if candidate.get("verified") else _color("✕", DIM)
        score = candidate.get("score")
        print(f"  {mark} {candidate.get('label', candidate.get('key'))}"
              + (f" · puan {score:g}" if score is not None else "")
              + f" · [{candidate.get('status', '-')}] "
              f"{candidate.get('verdict', '')}")
        comparison = candidate.get("comparison") or {}
        for note in (comparison.get("notes") or [])[:2]:
            print(f"      · {note}")
    verification = data.get("verification") or {}
    if verification:
        print(f"  Doğrulama: bağımsız holdout, "
              f"{verification.get('blocks', '?')} blok çifti")
    if data.get("before"):
        print("  Önce:")
        _print_measurement(data["before"], "    ")
    if data.get("after") and data.get("state") == "active":
        print("  Sonra:")
        _print_measurement(data["after"], "    ")
        _print_gain(data.get("gain") or {}, "  ")


def _latency_target(client: IpcClient, params: list) -> int:
    """``latency target list|add|remove|clear`` — sessiz port taraması yok."""
    response = client.call("config.get")
    if not response.get("ok"):
        return _fail(response)
    targets = list(response["data"].get("latency_targets") or [])
    verb = params[0] if params else "list"

    if verb == "list":
        if not targets:
            print("Tanımlı ölçüm hedefi yok. Örnek:")
            print("  dpi-bypass latency target add oyun.sunucum.net:7777 udp "
                  "\"Oyun sunucusu\"")
            return 0
        for index, item in enumerate(targets):
            port = f":{item['port']}" if item.get("port") else ""
            print(f"  [{index}] {item['host']}{port} "
                  f"{item.get('protocol', 'icmp')} "
                  f"{item.get('label', '')}")
        return 0

    if verb == "add":
        if len(params) < 2:
            print(_color("Kullanım: ", RED)
                  + "latency target add HOST[:PORT] [icmp|tcp|udp|tls] [ETİKET]")
            return 2
        host = params[1]
        port = 0
        if ":" in host and not host.startswith("["):
            host, _sep, raw_port = host.rpartition(":")
            try:
                port = int(raw_port)
            except ValueError:
                print(_color("Hata: ", RED) + f"geçersiz port: {raw_port}")
                return 2
        protocol = params[2] if len(params) > 2 else ("tcp" if port else "icmp")
        label = params[3] if len(params) > 3 else ""
        targets.append({"host": host, "port": port, "protocol": protocol,
                        "label": label})
    elif verb == "remove":
        if len(params) < 2:
            print(_color("Kullanım: ", RED) + "latency target remove SIRA")
            return 2
        try:
            targets.pop(int(params[1]))
        except (ValueError, IndexError):
            print(_color("Hata: ", RED) + "geçersiz sıra numarası")
            return 2
    elif verb == "clear":
        targets = []
    else:
        print(_color("Hata: ", RED) + f"bilinmeyen alt komut: {verb}")
        return 2

    response = client.call("config.set", values={"latency_targets": targets})
    if not response.get("ok"):
        return _fail(response)
    print("Ölçüm hedefleri güncellendi. Yeni hedeflerle doğrulamak için:")
    print("  dpi-bypass latency test   ·   dpi-bypass latency on")
    return 0


def _latency_calibrate(client: IpcClient, params: list) -> int:
    """Hat kapasitesini kullanıcıdan al. PHY link hızı kapasite sayılmaz."""
    if not params:
        print(_color("Kullanım: ", RED)
              + "latency calibrate UPLOAD_KBIT [DOWNLOAD_KBIT]")
        print("  Değerleri hız testinizden ya da ISS sözleşmenizden alın.")
        print("  Ethernet/Wi-Fi link hızı internet kapasiteniz DEĞİLDİR.")
        return 2
    try:
        uplink = int(params[0])
        downlink = int(params[1]) if len(params) > 1 else 0
    except ValueError:
        print(_color("Hata: ", RED) + "kapasite kbit/s cinsinden tam sayı olmalı")
        return 2
    response = client.call("config.set", values={
        "latency_uplink_kbit": uplink, "latency_downlink_kbit": downlink})
    if not response.get("ok"):
        return _fail(response)
    print(f"Hat kapasitesi kaydedildi: upload {uplink} kbit/s"
          + (f", download {downlink} kbit/s" if downlink else ""))
    print(_color("Not: ", YELLOW)
          + "SQM kipi ayrıca açılmalıdır — 'dpi-bypass set latency_sqm=true'. "
            "Bu kip bant genişliğinden feragat ederek yük altındaki gecikmeyi "
            "düşürür; hız-gecikme takası görünürdür.")
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

    p_doctor = sub.add_parser(
        "doctor", help="denetim soketine erişim tanısı (grup/oturum/soket)")
    p_doctor.add_argument("--json", action="store_true")
    p_doctor.set_defaults(func=cmd_doctor)

    p_logs = sub.add_parser("logs", help="servis günlüğü")
    p_logs.add_argument("-f", "--follow", action="store_true")
    p_logs.set_defaults(func=cmd_logs)

    p_set = sub.add_parser("set", help="ayar değiştir (örn: mode=all)")
    p_set.add_argument("pairs", nargs="+")
    p_set.set_defaults(func=cmd_set)

    p_vodafone = sub.add_parser(
        "vodafone", help="Vodafone sınırsız kipi (hotspot TTL düzeltmesi)")
    p_vodafone.add_argument("action", choices=("status", "on", "off"),
                            nargs="?", default="status")
    p_vodafone.set_defaults(func=cmd_vodafone)

    p_latency = sub.add_parser(
        "latency", help="ölçümlü düşük gecikme optimizasyonu (Beta)")
    p_latency.add_argument(
        "action",
        choices=("status", "on", "off", "test", "target", "calibrate",
                 "report", "cancel"),
        nargs="?", default="status")
    p_latency.add_argument("params", nargs="*",
                           help="alt komut argümanları (target/calibrate)")
    p_latency.add_argument("--json", action="store_true",
                           help="durumu JSON olarak yaz")
    p_latency.add_argument(
        "--condition", default="idle",
        choices=("idle", "first-packet", "natural-traffic"),
        help="ölçüm koşulu (test)")
    p_latency.set_defaults(func=cmd_latency)

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
