"""Sabitler: yollar, portlar, paket işaretleri."""

from __future__ import annotations

import os

# --- yollar -----------------------------------------------------------------
CONFIG_DIR = "/etc/dpi-bypass"
CONFIG_FILE = os.path.join(CONFIG_DIR, "config.json")
STATE_DIR = "/var/lib/dpi-bypass"
STATE_FILE = os.path.join(STATE_DIR, "state.json")
RUN_DIR = "/run/dpi-bypass"
SOCKET_PATH = os.path.join(RUN_DIR, "daemon.sock")
LOG_DIR = "/var/log/dpi-bypass"
LOG_FILE = os.path.join(LOG_DIR, "service.log")

SOCKET_GROUP = "dpi-bypass"
# Denetim soketinin beklenen kipi. Soket root daemon'ı yönetir; bu yüzden
# yalnızca sahibi (root) ve 'dpi-bypass' grubu erişebilir. Grup çözülemezse
# soket 0666 yapılmaz — güvenli varsayılan 0600'e düşmektir.
SOCKET_MODE = 0o660
SOCKET_MODE_DEGRADED = 0o600

# IPC satırları yeni satırla sonlandırılmış JSON çerçeveleridir. Hem sunucu
# hem istemci aynı üst sınırı uygular; böylece bozuk bir yerel eş uç sınırsız
# bellek büyümesine veya asyncio StreamReader limit hatasına yol açamaz.
IPC_MAX_MESSAGE_BYTES = 256 * 1024

# --- Vodafone sınırsız kipi -------------------------------------------------
# Vodafone modunda TTL yeniden yazımı yalnızca bu değerin ÜSTÜNDEKİ paketlere
# uygulanır. strategies.py'deki disorder/fake stratejileri kasıtlı olarak
# düşük TTL kullanır (2-8); onlara dokunulursa atlatma çalışmaz.
VODAFONE_TTL_GUARD = 32
VODAFONE_TTL_VALUE = 65

VODAFONE_TABLE = "dpibypass_ttl"
VODAFONE_CHAIN = "DPIBYPASS_TTL"   # iptables zincir adı

# Modun etkin olacağı ağların üst sınırı; en eskisi düşürülür.
VODAFONE_MAX_NETWORKS = 10

# Arayüzün eski IPv6 ayarı burada tutulur: servis beklenmedik biçimde
# sonlanırsa --cleanup dalı değeri buradan okuyup geri yazabilir.
VODAFONE_STATE_FILE = os.path.join(RUN_DIR, "vodafone.json")

# Ping düşürme kipinin değiştirdiği geçici ayarların geri alma tarifi. Dosya
# /run altında olduğu için yeniden başlatmada kalıcı sistem ayarı bırakılmaz;
# servis çöküp systemd tarafından yeniden başlatılırsa önce bu tarif uygulanır.
LATENCY_STATE_FILE = os.path.join(RUN_DIR, "latency.json")

# Ağ başına doğrulanmış en iyi aday. /run değil /var/lib altında: bu bilgi
# yeniden başlatmalar arasında korunur ve her açılışta uzun benchmark
# yapılmasını önler. Yalnızca "hangi adayı önce dene" bilgisidir; sistemde
# kalıcı bir ağ ayarı bırakmaz.
LATENCY_PROFILE_FILE = os.path.join(STATE_DIR, "latency-profiles.json")

# pkexec ile çağrılan yetkilendirme yardımcıları (install.sh buraya kurar).
VODAFONE_HELPER = "/usr/libexec/dpi-bypass/vodafone-helper"
VODAFONE_ACTION = "xyz.atomland.DpiBypass.vodafone-mode"

ACCESS_HELPER = "/usr/libexec/dpi-bypass/dpi-bypass-access-helper"
ACCESS_ACTION = "xyz.atomland.DpiBypass.repair-access"
#: Kaynak ağacından ya da /usr/local öneki ile kurulduğunda aranacak yerler.
ACCESS_HELPER_FALLBACKS = (
    ACCESS_HELPER,
    "/usr/local/libexec/dpi-bypass/dpi-bypass-access-helper",
)

# --- ağ ---------------------------------------------------------------------
# Kendi trafiğimizi yönlendirme kurallarından muaf tutmak için kullanılan işaret.
# 0x44 0x50 0x49 = "DPI"
FWMARK = 0x445049

PROXY_PORT = 20443   # şeffaf TCP vekil sunucusu
DNS_PORT = 20453     # yerel DoH -> düz DNS köprüsü

# Şeffaf yönlendirmenin uygulandığı TCP portları
REDIRECT_PORTS = (80, 443)

# --- DNS --------------------------------------------------------------------
# Birincil: Cloudflare, yedekler: Google ve Quad9 (kullanıcı isteği).
DOH_PROVIDERS = [
    {
        "name": "Cloudflare",
        "host": "cloudflare-dns.com",
        "path": "/dns-query",
        "addrs": ["1.1.1.1", "1.0.0.1"],
        "v6": ["2606:4700:4700::1111", "2606:4700:4700::1001"],
    },
    {
        "name": "Google",
        "host": "dns.google",
        "path": "/dns-query",
        "addrs": ["8.8.8.8", "8.8.4.4"],
        "v6": ["2001:4860:4860::8888", "2001:4860:4860::8844"],
    },
    {
        "name": "Quad9",
        "host": "dns.quad9.net",
        "path": "/dns-query",
        "addrs": ["9.9.9.9", "149.112.112.112"],
        "v6": ["2620:fe::fe", "2620:fe::9"],
    },
]

# --- test hedefi ------------------------------------------------------------
# Bir yöntem bulunduğunda gerçekten çalışıyor mu diye bakılan adres.
TEST_TARGETS = [
    ("discord.com", 443, "/"),
    ("gateway.discord.gg", 443, "/"),
    ("cdn.discordapp.com", 443, "/"),
]

# Yönlendirilecek (engelli kabul edilen) alan adları.
DEFAULT_BLOCKED_DOMAINS = [
    # Discord
    "discord.com",
    "discordapp.com",
    "discordapp.net",
    "discord.gg",
    "discord.media",
    "discord.dev",
    "discordstatus.com",
    "gateway.discord.gg",
    "cdn.discordapp.com",
    "media.discordapp.net",
    "images-ext-1.discordapp.net",
    "images-ext-2.discordapp.net",
    "latency.discord.media",
    "router.discordapp.net",
    # Türkiye'de DPI ile sık engellenen diğer alan adları
    "roblox.com",
    "rbxcdn.com",
    "instagram.com",
    "cdninstagram.com",
    "wattpad.com",
    "onlyfans.com",
    "rutracker.org",
    "1337x.to",
    "thepiratebay.org",
    "nyaa.si",
    "pornhub.com",
    "xvideos.com",
    "redtube.com",
    "xhamster.com",
]
