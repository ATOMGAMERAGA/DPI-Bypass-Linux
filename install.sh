#!/usr/bin/env bash
# DPI Bypass — tek satırlık kurulum betiği
# Yazan: Atom Gamer Arda A.G.A
#
#   curl -fsSL https://raw.githubusercontent.com/atomgameraga/DPI-Bypass-Linux/main/install.sh | sudo bash
#
# İşletim sistemini kendi saptar, gereken paketleri kurar, servisi
# etkinleştirir ve GUI uygulamasını hazır hale getirir.

set -euo pipefail

APP_NAME="DPI Bypass"
APP_ID="xyz.atomland.DpiBypass"
APP_VERSION="1.1.0"
REPO="${DPI_BYPASS_REPO:-atomgameraga/DPI-Bypass-Linux}"
BRANCH="${DPI_BYPASS_BRANCH:-main}"

PREFIX="/usr"
LIBDIR="$PREFIX/lib/dpi-bypass"
# polkit .policy dosyasındaki exec.path ile birebir aynı olmalı
LIBEXECDIR="$PREFIX/libexec/dpi-bypass"
BINDIR="$PREFIX/bin"
DATADIR="$PREFIX/share"
UNITDIR="/usr/lib/systemd/system"
CONFDIR="/etc/dpi-bypass"
GROUP="dpi-bypass"
SERVICE="dpi-bypass.service"

if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
    C_OK=$'\033[32m'; C_ERR=$'\033[31m'; C_WARN=$'\033[33m'
    C_INFO=$'\033[36m'; C_B=$'\033[1m'; C_D=$'\033[2m'; C_R=$'\033[0m'
else
    C_OK=""; C_ERR=""; C_WARN=""; C_INFO=""; C_B=""; C_D=""; C_R=""
fi

step()  { printf '%s▶%s %s\n' "$C_INFO" "$C_R" "$*"; }
ok()    { printf '%s✔%s %s\n' "$C_OK" "$C_R" "$*"; }
warn()  { printf '%s!%s %s\n' "$C_WARN" "$C_R" "$*"; }
die()   { printf '%s✖%s %s\n' "$C_ERR" "$C_R" "$*" >&2; exit 1; }

banner() {
    printf '\n%s╭──────────────────────────────────────────────╮%s\n' "$C_B" "$C_R"
    printf '%s│%s  %s %s — Linux kurulumu%s\n' "$C_B" "$C_R" "$APP_NAME" "$APP_VERSION" ""
    printf '%s│%s  %sYazan: Atom Gamer Arda A.G.A%s\n' "$C_B" "$C_R" "$C_D" "$C_R"
    printf '%s╰──────────────────────────────────────────────╯%s\n\n' "$C_B" "$C_R"
}

# ---------------------------------------------------------------- root -----
require_root() {
    if [ "$(id -u)" -ne 0 ]; then
        if command -v sudo >/dev/null 2>&1; then
            warn "Yönetici hakları gerekiyor, sudo ile yeniden çalıştırılıyor…"
            exec sudo -E bash "$0" "$@"
        fi
        die "Bu betik root olarak çalışmalı: sudo bash install.sh"
    fi
}

# ------------------------------------------------------------- dağıtım -----
DISTRO_ID=""; DISTRO_NAME=""; DISTRO_LIKE=""; PKG=""

os_release_field() {
    # os-release'i alt kabukta okur; NAME/VERSION gibi değişkenler betiğin
    # kendi değişkenlerini ezmesin diye asla doğrudan source edilmez.
    # shellcheck disable=SC1091
    ( . /etc/os-release 2>/dev/null; eval "printf '%s' \"\${$1:-}\"" )
}

detect_distro() {
    if [ -r /etc/os-release ]; then
        DISTRO_ID="$(os_release_field ID)"
        DISTRO_NAME="$(os_release_field PRETTY_NAME)"
        [ -n "$DISTRO_NAME" ] || DISTRO_NAME="$(os_release_field NAME)"
        [ -n "$DISTRO_NAME" ] || DISTRO_NAME="bilinmeyen"
        DISTRO_LIKE="$(os_release_field ID_LIKE)"
    else
        DISTRO_NAME="bilinmeyen"
    fi

    if   command -v dnf         >/dev/null 2>&1; then PKG="dnf"
    elif command -v dnf5        >/dev/null 2>&1; then PKG="dnf5"
    elif command -v apt-get     >/dev/null 2>&1; then PKG="apt"
    elif command -v pacman      >/dev/null 2>&1; then PKG="pacman"
    elif command -v zypper      >/dev/null 2>&1; then PKG="zypper"
    elif command -v yum         >/dev/null 2>&1; then PKG="yum"
    elif command -v apk         >/dev/null 2>&1; then PKG="apk"
    elif command -v xbps-install>/dev/null 2>&1; then PKG="xbps"
    elif command -v eopkg       >/dev/null 2>&1; then PKG="eopkg"
    elif command -v emerge      >/dev/null 2>&1; then PKG="emerge"
    else PKG=""
    fi

    ok "İşletim sistemi: ${C_B}${DISTRO_NAME}${C_R} (paket yöneticisi: ${PKG:-yok})"
}

try_install() {
    # Paketleri tek tek dener; bulunmayan paket kurulumu durdurmaz.
    local pm="$1"; shift
    for pkg in "$@"; do
        case "$pm" in
            dnf|dnf5|yum) $pm install -y "$pkg" >/dev/null 2>&1 || true ;;
            apt)          DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "$pkg" >/dev/null 2>&1 || true ;;
            pacman)       pacman -S --needed --noconfirm "$pkg" >/dev/null 2>&1 || true ;;
            zypper)       zypper --non-interactive install -y "$pkg" >/dev/null 2>&1 || true ;;
            apk)          apk add --no-cache "$pkg" >/dev/null 2>&1 || true ;;
            xbps)         xbps-install -y "$pkg" >/dev/null 2>&1 || true ;;
            eopkg)        eopkg install -y "$pkg" >/dev/null 2>&1 || true ;;
            emerge)       emerge --noreplace "$pkg" >/dev/null 2>&1 || true ;;
        esac
    done
}

install_dependencies() {
    step "Gerekli paketler kuruluyor (bu biraz sürebilir)…"
    case "$PKG" in
        dnf|dnf5|yum)
            try_install "$PKG" python3 python3-gobject gtk4 libadwaita \
                nftables iproute iw NetworkManager polkit curl ca-certificates
            ;;
        apt)
            apt-get update -qq >/dev/null 2>&1 || true
            try_install apt python3 python3-gi python3-gi-cairo \
                gir1.2-gtk-4.0 gir1.2-adw-1 nftables iproute2 iw \
                network-manager curl ca-certificates
            # polkit paketi dağıtım sürümüne göre farklı adlandırılır
            try_install apt polkitd policykit-1
            ;;
        pacman)
            try_install pacman python python-gobject gtk4 libadwaita \
                nftables iproute2 iw networkmanager polkit curl ca-certificates
            ;;
        zypper)
            try_install zypper python3 python3-gobject python3-gobject-Gdk \
                typelib-1_0-Gtk-4_0 typelib-1_0-Adw-1 nftables iproute2 \
                iw NetworkManager polkit curl ca-certificates
            ;;
        apk)
            try_install apk python3 py3-gobject3 gtk4.0 libadwaita \
                nftables iproute2 iw networkmanager polkit curl ca-certificates
            ;;
        xbps)
            try_install xbps python3 python3-gobject gtk4 libadwaita \
                nftables iproute2 iw NetworkManager polkit curl
            ;;
        eopkg)
            try_install eopkg python3 python-gobject libgtk-4 libadwaita \
                nftables iproute2 networkmanager polkit curl
            ;;
        emerge)
            warn "Gentoo saptandı; paketleri kendiniz kurmanız gerekebilir:"
            printf '    dev-python/pygobject gui-libs/gtk:4 gui-libs/libadwaita net-firewall/nftables\n'
            ;;
        *)
            warn "Paket yöneticisi tanınamadı; bağımlılıklar elle kurulmalı."
            ;;
    esac
    ok "Paket adımı tamamlandı."
}

check_requirements() {
    command -v python3 >/dev/null 2>&1 || die "python3 bulunamadı."
    local pyver
    pyver="$(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])')"
    case "$pyver" in
        3.[0-7]) die "Python 3.8 veya üzeri gerekiyor (bulunan: $pyver)" ;;
    esac
    ok "Python $pyver uygun."

    if command -v nft >/dev/null 2>&1; then
        ok "nftables kullanılacak."
    elif command -v iptables >/dev/null 2>&1; then
        warn "nftables yok; iptables kullanılacak."
    else
        die "nftables ya da iptables gerekli."
    fi
}

# ------------------------------------------------------------- kaynak ------
SRC_DIR=""
TMP_DIR=""

obtain_sources() {
    local here
    here="$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd || echo "")"
    if [ -n "$here" ] && [ -d "$here/src/dpibypass" ]; then
        SRC_DIR="$here"
        ok "Kaynaklar yerel dizinden alınıyor: $SRC_DIR"
        return
    fi

    step "Kaynak kodu indiriliyor (github.com/$REPO@$BRANCH)…"
    TMP_DIR="$(mktemp -d)"
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "https://codeload.github.com/$REPO/tar.gz/$BRANCH" \
            | tar -xz -C "$TMP_DIR" || die "İndirme başarısız."
    elif command -v wget >/dev/null 2>&1; then
        wget -qO- "https://codeload.github.com/$REPO/tar.gz/$BRANCH" \
            | tar -xz -C "$TMP_DIR" || die "İndirme başarısız."
    elif command -v git >/dev/null 2>&1; then
        git clone --depth 1 -b "$BRANCH" "https://github.com/$REPO.git" \
            "$TMP_DIR/repo" >/dev/null 2>&1 || die "git clone başarısız."
    else
        die "curl, wget ya da git gerekli."
    fi
    # Arşiv "DPI-Bypass-Linux-main/" gibi tek bir üst dizine açılır; paket
    # dizini bu yüzden üç düzey aşağıdadır. -printf yerine dirname kullanılır,
    # böylece busybox find (Alpine) ile de çalışır.
    local found=""
    found="$(find "$TMP_DIR" -maxdepth 4 -type d -path '*/src/dpibypass' \
        2>/dev/null | head -1)"
    if [ -z "$found" ]; then
        found="$(find "$TMP_DIR" -type d -path '*/src/dpibypass' 2>/dev/null | head -1)"
    fi
    [ -n "$found" ] || die "Kaynak ağacı bulunamadı (arşiv beklenen yapıda değil)."
    SRC_DIR="$(dirname "$(dirname "$found")")"
    [ -d "$SRC_DIR/src/dpibypass" ] && [ -d "$SRC_DIR/data" ] && [ -d "$SRC_DIR/bin" ] \
        || die "Kaynak ağacı eksik: $SRC_DIR"
    ok "Kaynaklar hazır."
}

cleanup_tmp() {
    [ -n "$TMP_DIR" ] && rm -rf "$TMP_DIR" || true
}
trap cleanup_tmp EXIT

# ------------------------------------------------------------- kurulum -----
install_files() {
    step "Dosyalar kuruluyor…"

    rm -rf "$LIBDIR/dpibypass"
    install -d -m 0755 "$LIBDIR"
    cp -r "$SRC_DIR/src/dpibypass" "$LIBDIR/dpibypass"
    find "$LIBDIR" -name '__pycache__' -type d -exec rm -rf {} + 2>/dev/null || true
    chmod -R a+rX "$LIBDIR"

    install -d -m 0755 "$BINDIR"
    for launcher in dpi-bypass dpi-bypassd dpi-bypass-gui; do
        install -m 0755 "$SRC_DIR/bin/$launcher" "$BINDIR/$launcher"
    done

    # Vodafone kipi için polkit ile çağrılan yetkilendirme yardımcısı
    install -d -m 0755 "$LIBEXECDIR"
    install -m 0755 "$SRC_DIR/bin/vodafone-helper" "$LIBEXECDIR/vodafone-helper"

    # Simgeler
    for size in 16 22 24 32 48 64 128 256 512; do
        src="$SRC_DIR/data/icons/hicolor/${size}x${size}/apps/$APP_ID.png"
        [ -f "$src" ] || continue
        install -Dm0644 "$src" \
            "$DATADIR/icons/hicolor/${size}x${size}/apps/$APP_ID.png"
    done
    install -Dm0644 "$SRC_DIR/data/icons/hicolor/scalable/apps/$APP_ID.svg" \
        "$DATADIR/icons/hicolor/scalable/apps/$APP_ID.svg"
    install -Dm0644 \
        "$SRC_DIR/data/icons/hicolor/symbolic/apps/$APP_ID-symbolic.svg" \
        "$DATADIR/icons/hicolor/symbolic/apps/$APP_ID-symbolic.svg"

    # Masaüstü girdileri ve üst veri
    install -Dm0644 "$SRC_DIR/data/$APP_ID.desktop" \
        "$DATADIR/applications/$APP_ID.desktop"
    install -Dm0644 "$SRC_DIR/data/$APP_ID.metainfo.xml" \
        "$DATADIR/metainfo/$APP_ID.metainfo.xml"
    install -Dm0644 "$SRC_DIR/data/$APP_ID-autostart.desktop" \
        "/etc/xdg/autostart/$APP_ID-autostart.desktop"

    # polkit kuralı (grup üyeleri servisi parolasız yönetebilsin)
    if [ -d /usr/share/polkit-1/rules.d ]; then
        install -Dm0644 "$SRC_DIR/data/polkit/49-dpi-bypass.rules" \
            "/usr/share/polkit-1/rules.d/49-dpi-bypass.rules"
    fi

    # polkit eylemi: Vodafone kipi açılıp kapatılırken yönetici parolası sorar
    install -Dm0644 "$SRC_DIR/data/polkit/$APP_ID.policy" \
        "$DATADIR/polkit-1/actions/$APP_ID.policy"

    # systemd birimi
    if [ ! -d "$UNITDIR" ]; then UNITDIR="/lib/systemd/system"; fi
    install -d -m 0755 "$UNITDIR"
    install -Dm0644 "$SRC_DIR/data/systemd/$SERVICE" "$UNITDIR/$SERVICE"

    install -d -m 0755 "$CONFDIR" /var/lib/dpi-bypass /var/log/dpi-bypass

    if command -v gtk-update-icon-cache >/dev/null 2>&1; then
        gtk-update-icon-cache -qtf "$DATADIR/icons/hicolor" >/dev/null 2>&1 || true
    fi
    if command -v update-desktop-database >/dev/null 2>&1; then
        update-desktop-database -q "$DATADIR/applications" >/dev/null 2>&1 || true
    fi
    ok "Dosyalar yerine kondu."
}

setup_group() {
    if ! getent group "$GROUP" >/dev/null 2>&1; then
        groupadd --system "$GROUP" >/dev/null 2>&1 || true
    fi
    local target_user="${SUDO_USER:-}"
    if [ -z "$target_user" ] && [ -n "${PKEXEC_UID:-}" ]; then
        # PKEXEC_UID sayısaldır; kullanıcı adına çevir
        target_user="$(id -nu "$PKEXEC_UID" 2>/dev/null || true)"
    fi
    if [ -z "$target_user" ] || [ "$target_user" = "root" ]; then
        target_user="$(logname 2>/dev/null || true)"
    fi
    if [ -z "$target_user" ] || [ "$target_user" = "root" ]; then
        # Açık oturumlardaki ilk normal kullanıcı
        target_user="$(who 2>/dev/null | awk '$1 != "root" {print $1; exit}')"
    fi
    if [ -z "$target_user" ] || [ "$target_user" = "root" ]; then
        # Tek bir normal kullanıcı varsa onu seç (UID 1000-60000)
        target_user="$(awk -F: '$3 >= 1000 && $3 < 60000 && $7 !~ /(nologin|false)$/ \
            {print $1}' /etc/passwd 2>/dev/null | head -2 | \
            { mapfile -t users; [ "${#users[@]}" -eq 1 ] && printf '%s' "${users[0]}"; })"
    fi
    if [ -n "$target_user" ] && [ "$target_user" != "root" ] \
       && id "$target_user" >/dev/null 2>&1; then
        usermod -aG "$GROUP" "$target_user" >/dev/null 2>&1 || true
        ok "Kullanıcı '$target_user' '$GROUP' grubuna eklendi."
        INSTALL_USER="$target_user"
    else
        warn "Masaüstü kullanıcısı saptanamadı. Şunu elle çalıştırın:"
        printf '    sudo usermod -aG %s KULLANICI_ADINIZ\n' "$GROUP"
        INSTALL_USER=""
    fi
}

enable_service() {
    step "Servis etkinleştiriliyor…"
    if ! command -v systemctl >/dev/null 2>&1; then
        warn "systemd bulunamadı; servis elle başlatılmalı: dpi-bypassd"
        return
    fi
    systemctl daemon-reload >/dev/null 2>&1 || \
        warn "systemd birimleri yeniden yüklenemedi."
    systemctl enable "$SERVICE" >/dev/null 2>&1 || \
        warn "Servis açılışa eklenemedi."
    systemctl restart "$SERVICE" >/dev/null 2>&1 || warn "Servis başlatılamadı."
    sleep 2
    if systemctl is-active --quiet "$SERVICE"; then
        ok "Servis çalışıyor ve sistem açılışında otomatik başlayacak."
    else
        warn "Servis başlamadı. Günlük: journalctl -u $SERVICE -n 40"
    fi
}

verify_gui() {
    if python3 -c "
import gi
gi.require_version('Gtk', '4.0')
gi.require_version('Adw', '1')
from gi.repository import Gtk, Adw
" >/dev/null 2>&1; then
        ok "GTK4 + libadwaita arayüz bağımlılıkları tamam."
    else
        warn "GTK4/libadwaita Python bağlayıcıları eksik; arayüz açılmayabilir."
        case "$PKG" in
            apt)    printf '    sudo apt install python3-gi gir1.2-gtk-4.0 gir1.2-adw-1\n' ;;
            dnf|dnf5|yum) printf '    sudo dnf install python3-gobject gtk4 libadwaita\n' ;;
            pacman) printf '    sudo pacman -S python-gobject gtk4 libadwaita\n' ;;
            zypper) printf '    sudo zypper install python3-gobject typelib-1_0-Gtk-4_0 typelib-1_0-Adw-1\n' ;;
        esac
    fi
}

final_message() {
    printf '\n%s╭──────────────────────────────────────────────╮%s\n' "$C_OK" "$C_R"
    printf '%s│%s  %sKURULDU:%s %s %s\n' "$C_OK" "$C_R" "$C_B" "$C_R" "$APP_NAME" "$APP_VERSION"
    printf '%s╰──────────────────────────────────────────────╯%s\n\n' "$C_OK" "$C_R"

    printf '  %sUygulama adı :%s %s\n' "$C_D" "$C_R" "$APP_NAME"
    printf '  %sServis       :%s %s (etkin, açılışta başlar)\n' "$C_D" "$C_R" "$SERVICE"
    printf '  %sYapılandırma :%s %s/config.json\n' "$C_D" "$C_R" "$CONFDIR"
    printf '  %sYazan        :%s Atom Gamer Arda A.G.A\n\n' "$C_D" "$C_R"

    printf '  %sBuradan sonrasına GUI uygulamasından devam edin.%s\n' "$C_B" "$C_R"
    printf '  Etkinlikler (Super tuşu) → %s"DPI Bypass"%s\n' "$C_B" "$C_R"
    printf '  ya da terminalden: %sdpi-bypass-gui%s\n\n' "$C_B" "$C_R"

    if [ -n "${INSTALL_USER:-}" ]; then
        printf '  %sNot:%s Grup üyeliği yeni eklendiği için ilk açılışta uygulama\n' "$C_WARN" "$C_R"
        printf '       kendini bir kez yeniden başlatabilir. Sorun çıkarsa oturumu\n'
        printf '       kapatıp açmanız yeterli.\n\n'
    fi

    printf '  %sKomut satırı:%s dpi-bypass status | search | test | logs -f\n' "$C_D" "$C_R"
    printf '  %sKaldırmak için:%s sudo bash install.sh --uninstall\n\n' "$C_D" "$C_R"
}

# ----------------------------------------------------------- kaldırma ------
uninstall() {
    banner
    step "Kaldırılıyor…"
    if command -v systemctl >/dev/null 2>&1; then
        systemctl disable --now "$SERVICE" >/dev/null 2>&1 || true
    fi
    "$BINDIR/dpi-bypassd" --cleanup >/dev/null 2>&1 || true
    rm -f "$UNITDIR/$SERVICE" "/lib/systemd/system/$SERVICE"
    rm -f "$BINDIR/dpi-bypass" "$BINDIR/dpi-bypassd" "$BINDIR/dpi-bypass-gui"
    rm -rf "$LIBDIR" "$LIBEXECDIR"
    rm -f "$DATADIR/applications/$APP_ID.desktop"
    rm -f "$DATADIR/metainfo/$APP_ID.metainfo.xml"
    rm -f "/etc/xdg/autostart/$APP_ID-autostart.desktop"
    rm -f "/usr/share/polkit-1/rules.d/49-dpi-bypass.rules"
    rm -f "$DATADIR/polkit-1/actions/$APP_ID.policy"
    rm -f "$DATADIR"/icons/hicolor/*/apps/"$APP_ID".png
    rm -f "$DATADIR/icons/hicolor/scalable/apps/$APP_ID.svg"
    rm -f "$DATADIR/icons/hicolor/symbolic/apps/$APP_ID-symbolic.svg"
    command -v systemctl >/dev/null 2>&1 && systemctl daemon-reload || true
    ok "Kaldırıldı. Ayarlar $CONFDIR içinde bırakıldı."
    printf '  Ayarları da silmek için: sudo rm -rf %s /var/lib/dpi-bypass\n' "$CONFDIR"
}

# --------------------------------------------------------------- akış ------
main() {
    case "${1:-}" in
        --uninstall|-u|uninstall)
            require_root "$@"
            uninstall
            exit 0
            ;;
        --help|-h)
            printf 'Kullanım: sudo bash install.sh [--uninstall]\n'
            exit 0
            ;;
    esac

    require_root "$@"
    banner
    detect_distro
    install_dependencies
    check_requirements
    obtain_sources
    install_files
    setup_group
    enable_service
    verify_gui
    final_message
}

main "$@"
