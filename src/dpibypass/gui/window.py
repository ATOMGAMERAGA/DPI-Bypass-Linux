"""Ana pencere — GNOME (GTK4 + libadwaita) arayüzü."""

from __future__ import annotations

import os
import time

from gi.repository import Adw, Gio, GLib, Gtk

from ..constants import SOCKET_GROUP
from ..version import APP_ID, APP_NAME, AUTHOR, WEBSITE, __version__
from .client import DaemonClient
from .widgets import (Banner, HAS_ABOUT_DIALOG, button_row, combo_row,
                      message, spin_row, switch_row, toolbar_view)

MODE_LABELS = [
    ("smart", "Akıllı — yalnızca engelli siteler"),
    ("all", "Tüm siteler — her şey vekilden geçer"),
]
DNS_LABELS = [
    ("cloudflare", "Cloudflare (1.1.1.1) — birincil"),
    ("google", "Google (8.8.8.8)"),
    ("quad9", "Quad9 (9.9.9.9)"),
]

STATUS_VIEW = {
    "active": ("Koruma etkin", "security-high-symbolic", "dpi-ok"),
    "dns-only": ("DNS koruması etkin", "security-medium-symbolic", "dpi-ok"),
    "searching": ("Yöntem aranıyor…", "content-loading-symbolic", "dpi-busy"),
    "starting": ("Başlatılıyor…", "content-loading-symbolic", "dpi-busy"),
    "failed": ("Çalışan yöntem bulunamadı", "security-low-symbolic", "dpi-fail"),
    "disabled": ("Koruma kapalı", "security-low-symbolic", "dpi-off"),
    "offline": ("Servise bağlanılamadı", "network-offline-symbolic", "dpi-fail"),
}


class MainWindow(Adw.ApplicationWindow):
    def __init__(self, app: Adw.Application) -> None:
        super().__init__(application=app, title=APP_NAME)
        self.set_default_size(880, 720)
        self.set_size_request(360, 480)

        self.client = DaemonClient()
        self.status: dict = {}
        self.config: dict = {}
        self.strategy_list: list[dict] = []
        self.isp_list: list[dict] = []
        self._loading = True
        self._log_since = 0.0
        self._log_lines: list[str] = []

        self._build_ui()
        self._bootstrap()
        GLib.timeout_add_seconds(2, self._tick)

    # ------------------------------------------------------------------ #
    # arayüz kurulumu
    # ------------------------------------------------------------------ #
    def _build_ui(self) -> None:
        self.toasts = Adw.ToastOverlay()

        self.stack = Adw.ViewStack(vexpand=True)
        self.stack.add_titled_with_icon(
            self._page_status(), "durum", "Durum", "security-high-symbolic")
        self.stack.add_titled_with_icon(
            self._page_settings(), "ayarlar", "Ayarlar", "emblem-system-symbolic")
        self.stack.add_titled_with_icon(
            self._page_domains(), "siteler", "Siteler", "web-browser-symbolic")
        self.stack.add_titled_with_icon(
            self._page_logs(), "gunluk", "Günlük", "text-x-generic-symbolic")

        header = Adw.HeaderBar()
        switcher = Adw.ViewSwitcher(stack=self.stack,
                                    policy=Adw.ViewSwitcherPolicy.WIDE)
        header.set_title_widget(switcher)

        menu = Gio.Menu()
        menu.append("Yöntemi yeniden ara", "win.search")
        menu.append("Servisi yeniden başlat", "win.restart")
        menu.append("Bu ağı unut", "win.forget")
        menu.append(f"{APP_NAME} hakkında", "win.about")
        menu_button = Gtk.MenuButton(icon_name="open-menu-symbolic",
                                     menu_model=menu, tooltip_text="Menü")
        header.pack_end(menu_button)

        self.banner = Banner()
        content = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        content.append(self.banner)
        content.append(self.stack)

        switcher_bar = Adw.ViewSwitcherBar(stack=self.stack, reveal=False)
        breakpoint_box = toolbar_view(header, content, switcher_bar)
        self.toasts.set_child(breakpoint_box)
        self.set_content(self.toasts)

        # dar ekranlarda alt geçiş çubuğunu göster
        self.connect("notify::default-width", self._on_resize)
        self._switcher_bar = switcher_bar
        self._switcher = switcher

        self._install_actions()

    def _install_actions(self) -> None:
        for name, handler in (
            ("search", lambda *_: self.do_search()),
            ("restart", lambda *_: self.restart_service()),
            ("forget", lambda *_: self.forget_network()),
            ("about", lambda *_: self.show_about()),
        ):
            action = Gio.SimpleAction.new(name, None)
            action.connect("activate", handler)
            self.add_action(action)

    def _on_resize(self, *_args) -> None:
        narrow = self.get_width() < 600
        self._switcher_bar.set_reveal(narrow)
        self._switcher.set_visible(not narrow)

    # -- Durum sayfası -----------------------------------------------------
    def _page_status(self) -> Gtk.Widget:
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=18,
                      margin_top=28, margin_bottom=28,
                      margin_start=12, margin_end=12)

        self.status_icon = Gtk.Image(icon_name=APP_ID, pixel_size=96)
        self.status_icon.add_css_class("dpi-status-icon")
        self.status_spinner = Gtk.Spinner(width_request=96, height_request=96)
        self.status_spinner.set_visible(False)
        icon_box = Gtk.Box(halign=Gtk.Align.CENTER)
        icon_box.append(self.status_icon)
        icon_box.append(self.status_spinner)
        box.append(icon_box)

        self.status_title = Gtk.Label(label="Bağlanılıyor…", halign=Gtk.Align.CENTER)
        self.status_title.add_css_class("title-1")
        box.append(self.status_title)

        self.status_subtitle = Gtk.Label(label="", halign=Gtk.Align.CENTER,
                                         wrap=True, justify=Gtk.Justification.CENTER)
        self.status_subtitle.add_css_class("dim-label")
        box.append(self.status_subtitle)

        self.toggle_button = Gtk.Button(label="Korumayı kapat",
                                        halign=Gtk.Align.CENTER)
        self.toggle_button.add_css_class("pill")
        self.toggle_button.add_css_class("suggested-action")
        self.toggle_button.connect("clicked", lambda _b: self.toggle_protection())
        box.append(self.toggle_button)

        actions = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12,
                          halign=Gtk.Align.CENTER)
        search_btn = Gtk.Button(label="Yöntemi yeniden ara")
        search_btn.connect("clicked", lambda _b: self.do_search())
        test_btn = Gtk.Button(label="discord.com'u test et")
        test_btn.connect("clicked", lambda _b: self.do_test())
        actions.append(search_btn)
        actions.append(test_btn)
        box.append(actions)

        group = Adw.PreferencesGroup(title="Bağlantı")
        self.rows = {}
        for key, title in (
            ("isp", "Operatör"),
            ("network", "Ağ"),
            ("strategy", "Kullanılan yöntem"),
            ("dns", "DNS"),
            ("firewall", "Yönlendirme"),
            ("traffic", "Trafik"),
        ):
            row = Adw.ActionRow(title=title, subtitle="—")
            row.add_css_class("property")
            group.add(row)
            self.rows[key] = row
        box.append(group)

        self.results_group = Adw.PreferencesGroup(
            title="Son arama sonuçları",
            description="Her yöntem discord.com üzerinde gerçekten denendi.")
        self.results_group.set_visible(False)
        box.append(self.results_group)
        self._result_rows: list[Gtk.Widget] = []

        clamp = Adw.Clamp(maximum_size=680, child=box)
        scroller = Gtk.ScrolledWindow(child=clamp, vexpand=True)
        return scroller

    # -- Ayarlar sayfası ---------------------------------------------------
    def _page_settings(self) -> Gtk.Widget:
        page = Adw.PreferencesPage()

        general = Adw.PreferencesGroup(
            title="Genel",
            description="Servis sistem açılışında otomatik başlar.")
        self.row_enabled, _ = switch_row(
            "Koruma", "Kapatıldığında tüm kurallar geri alınır", True,
            lambda v: self._set_config(enabled=v))
        general.add(self.row_enabled)

        self.row_mode = combo_row(
            "Çalışma kipi", "Akıllı kip yalnızca engelli listesini yönlendirir",
            [label for _, label in MODE_LABELS], 0,
            lambda i: self._set_config(mode=MODE_LABELS[i][0]))
        general.add(self.row_mode)

        self.row_autoswitch, _ = switch_row(
            "Ağ değişince yeniden ara",
            "Yeni bir ağa bağlanıldığında yöntem arka planda saniyeler içinde bulunur",
            True, lambda v: self._set_config(auto_switch=v))
        general.add(self.row_autoswitch)

        self.row_discover, _ = switch_row(
            "Yeni engelli siteleri kendiliğinden bul",
            "Açtığınız bir site engelliyse sessizce sınanır ve listeye eklenir",
            True, lambda v: self._set_config(auto_discover=v))
        general.add(self.row_discover)

        self.row_interval = spin_row(
            "Düzenli denetim aralığı", "Saniye — 0 kapatır",
            1800, 0, 21600, 300,
            lambda v: self._set_config(recheck_interval=int(v)))
        general.add(self.row_interval)

        self.row_gui_autostart, _ = switch_row(
            "Oturum açılışında arayüzü başlat",
            "Servis zaten sistem açılışında başlar; bu yalnızca pencereyi açar",
            True, self._on_gui_autostart)
        general.add(self.row_gui_autostart)
        page.add(general)

        detection = Adw.PreferencesGroup(
            title="Operatör ve yöntem",
            description="Otomatik bırakıldığında ASN, bağlantı türü ve ağ adı "
                        "birlikte değerlendirilir.")
        self.row_isp = combo_row("Operatör", "", ["Otomatik saptansın"], 0,
                                 self._on_isp_changed)
        detection.add(self.row_isp)
        self.row_strategy = combo_row("Atlatma yöntemi", "", ["Otomatik seçilsin"], 0,
                                      self._on_strategy_changed)
        detection.add(self.row_strategy)
        page.add(detection)

        dns_group = Adw.PreferencesGroup(
            title="DNS",
            description="Sistemin tüm DNS trafiği şifreli olarak taşınır.")
        self.row_dns = combo_row("Sağlayıcı", "Yedekler otomatik devreye girer",
                                 [label for _, label in DNS_LABELS], 0,
                                 lambda i: self._set_config(
                                     dns_provider=DNS_LABELS[i][0]))
        dns_group.add(self.row_dns)
        self.row_dns_intercept, _ = switch_row(
            "DNS trafiğini yakala",
            "53 numaralı porta giden istekler yerel şifreli köprüye yönlendirilir",
            True, lambda v: self._set_config(dns_intercept=v))
        dns_group.add(self.row_dns_intercept)
        self.row_quic, _ = switch_row(
            "QUIC'i engelle",
            "Tarayıcılar UDP/443 yerine atlatma uygulanabilen TCP'ye döner",
            True, lambda v: self._set_config(block_quic=v))
        dns_group.add(self.row_quic)
        page.add(dns_group)

        advanced = Adw.PreferencesGroup(title="Gelişmiş")
        self.row_verbose, _ = switch_row(
            "Ayrıntılı günlük", "Sorun ararken açın", False,
            lambda v: self._set_config(verbose=v))
        advanced.add(self.row_verbose)
        advanced.add(button_row(
            "Servisi yeniden başlat",
            "Tüm kuralları yeniden kurar", "Yeniden başlat",
            self.restart_service))
        page.add(advanced)
        return page

    # -- Siteler sayfası ---------------------------------------------------
    def _page_domains(self) -> Gtk.Widget:
        page = Adw.PreferencesPage()

        add_group = Adw.PreferencesGroup(
            title="Kendi siteleriniz",
            description="Engellendiğini düşündüğünüz alan adlarını ekleyin. "
                        "Alt alan adları da kapsanır.")
        self.entry_domain = Adw.EntryRow(title="örnek.com")
        add_button = Gtk.Button(icon_name="list-add-symbolic",
                                valign=Gtk.Align.CENTER,
                                tooltip_text="Ekle")
        add_button.add_css_class("flat")
        add_button.connect("clicked", lambda _b: self._add_domain())
        self.entry_domain.add_suffix(add_button)
        self.entry_domain.connect("entry-activated", lambda _e: self._add_domain())
        add_group.add(self.entry_domain)
        self.custom_group = add_group
        page.add(add_group)
        self._custom_rows: list[Gtk.Widget] = []

        self.learned_group = Adw.PreferencesGroup(
            title="Otomatik öğrenilenler",
            description="Bağlantısı tekrar tekrar kesilen siteler buraya eklenir.")
        self.learned_group.set_visible(False)
        page.add(self.learned_group)
        self._learned_rows: list[Gtk.Widget] = []

        builtin = Adw.PreferencesGroup(
            title="Yerleşik liste",
            description="Discord ve Türkiye'de DPI ile engellendiği bilinen "
                        "diğer adresler zaten kapsanır.")
        from ..constants import DEFAULT_BLOCKED_DOMAINS
        expander = Adw.ExpanderRow(
            title=f"{len(DEFAULT_BLOCKED_DOMAINS)} alan adı",
            subtitle="Görmek için genişletin")
        for domain in DEFAULT_BLOCKED_DOMAINS:
            expander.add_row(Adw.ActionRow(title=domain))
        builtin.add(expander)
        page.add(builtin)
        return page

    # -- Günlük sayfası ----------------------------------------------------
    def _page_logs(self) -> Gtk.Widget:
        self.log_buffer = Gtk.TextBuffer()
        self.log_buffer.set_text(
            "Servis günlüğü burada görünür.\n"
            "Yöntem araması, ağ değişiklikleri ve test sonuçları buraya yazılır.")
        view = Gtk.TextView(buffer=self.log_buffer, editable=False,
                            monospace=True, cursor_visible=False,
                            wrap_mode=Gtk.WrapMode.WORD_CHAR,
                            top_margin=8, bottom_margin=8,
                            left_margin=8, right_margin=8)
        self.log_view = view
        scroller = Gtk.ScrolledWindow(child=view, vexpand=True)
        self.log_scroller = scroller
        return scroller

    # ------------------------------------------------------------------ #
    # veri akışı
    # ------------------------------------------------------------------ #
    def _bootstrap(self) -> None:
        self.client.call("strategies", self._on_strategies)
        self.client.call("isps", self._on_isps)
        self.client.call("config.get", self._on_config)
        self.client.call("status", self._on_status)
        self.client.call("logs", self._on_logs, since=0)

    def _tick(self) -> bool:
        self.client.call("status", self._on_status)
        if self.stack.get_visible_child_name() == "gunluk":
            self.client.call("logs", self._on_logs, since=self._log_since)
        return True

    def _on_strategies(self, response: dict) -> None:
        if not response.get("ok"):
            return
        self.strategy_list = response["data"]
        model = Gtk.StringList()
        model.append("Otomatik seçilsin")
        for strategy in self.strategy_list:
            model.append(strategy["label"])
        self._loading = True
        self.row_strategy.set_model(model)
        self._select_strategy(self.config.get("strategy", "auto"))
        self._loading = False

    def _on_isps(self, response: dict) -> None:
        if not response.get("ok"):
            return
        self.isp_list = response["data"]
        model = Gtk.StringList()
        model.append("Otomatik saptansın")
        for profile in self.isp_list:
            model.append(profile["label"])
        self._loading = True
        self.row_isp.set_model(model)
        self._select_isp(self.config.get("isp", "auto"))
        self._loading = False

    def _on_config(self, response: dict) -> None:
        if not response.get("ok"):
            return
        self.config = response["data"]
        self._loading = True
        self.row_enabled.set_active(bool(self.config.get("enabled", True)))
        self.row_autoswitch.set_active(bool(self.config.get("auto_switch", True)))
        self.row_discover.set_active(bool(self.config.get("auto_discover", True)))
        self.row_gui_autostart.set_active(bool(self.config.get("gui_autostart", True)))
        self.row_dns_intercept.set_active(bool(self.config.get("dns_intercept", True)))
        self.row_quic.set_active(bool(self.config.get("block_quic", True)))
        self.row_verbose.set_active(bool(self.config.get("verbose", False)))
        self.row_interval.set_value(float(self.config.get("recheck_interval", 1800)))
        mode = self.config.get("mode", "smart")
        self.row_mode.set_selected(
            next((i for i, (key, _) in enumerate(MODE_LABELS) if key == mode), 0))
        provider = self.config.get("dns_provider", "cloudflare")
        self.row_dns.set_selected(
            next((i for i, (key, _) in enumerate(DNS_LABELS) if key == provider), 0))
        self._select_isp(self.config.get("isp", "auto"))
        self._select_strategy(self.config.get("strategy", "auto"))
        self._refresh_domain_rows()
        self._loading = False

    def _select_isp(self, isp_id: str) -> None:
        if not self.isp_list:
            return
        index = 0
        for i, profile in enumerate(self.isp_list):
            if profile["id"] == isp_id:
                index = i + 1
                break
        self.row_isp.set_selected(index)

    def _select_strategy(self, name: str) -> None:
        if not self.strategy_list:
            return
        index = 0
        for i, strategy in enumerate(self.strategy_list):
            if strategy["name"] == name:
                index = i + 1
                break
        self.row_strategy.set_selected(index)

    def _on_isp_changed(self, index: int) -> None:
        if self._loading or not self.isp_list:
            return
        value = "auto" if index == 0 else self.isp_list[index - 1]["id"]
        self._set_config(isp=value)

    def _on_strategy_changed(self, index: int) -> None:
        if self._loading or not self.strategy_list:
            return
        value = "auto" if index == 0 else self.strategy_list[index - 1]["name"]
        self._set_config(strategy=value)

    def _on_gui_autostart(self, enabled: bool) -> None:
        if self._loading:
            return
        self._set_config(gui_autostart=enabled)
        self._write_autostart_file(enabled)

    def _write_autostart_file(self, enabled: bool) -> None:
        """Kullanıcı düzeyinde otomatik başlatma dosyasını yaz.

        Dosya adı sistem genelindeki girdiyle aynıdır; böylece kullanıcının
        seçimi sistem girdisini geçersiz kılar.
        """
        directory = os.path.join(GLib.get_user_config_dir(), "autostart")
        path = os.path.join(directory, f"{APP_ID}-autostart.desktop")
        content = (
            "[Desktop Entry]\n"
            "Type=Application\n"
            "Name=DPI Bypass\n"
            "Exec=dpi-bypass-gui\n"
            f"Icon={APP_ID}\n"
            "Terminal=false\n"
            "X-GNOME-Autostart-Delay=5\n"
            f"X-GNOME-Autostart-enabled={'true' if enabled else 'false'}\n"
            f"Hidden={'false' if enabled else 'true'}\n"
        )
        try:
            os.makedirs(directory, exist_ok=True)
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(content)
        except OSError as exc:
            self.toast(f"Otomatik başlatma ayarlanamadı: {exc}")

    def _set_config(self, **values) -> None:
        if self._loading:
            return
        self.config.update(values)
        self.client.call("config.set", self._on_config_set, values=values)

    def _on_config_set(self, response: dict) -> None:
        if not response.get("ok"):
            self.toast(f"Ayar kaydedilemedi: {response.get('error')}")
            return
        self.config = response["data"]["config"]
        if response["data"]["changed"]:
            self.toast("Ayarlar kaydedildi")

    # -- durum -------------------------------------------------------------
    def _on_status(self, response: dict) -> None:
        if not response.get("ok"):
            self._show_offline(response)
            return
        self.banner.hide_message()
        self.status = response["data"]
        data = self.status

        state = data["status"] if data.get("enabled", True) else "disabled"
        title, icon, css = STATUS_VIEW.get(state, STATUS_VIEW["starting"])
        busy = state in ("searching", "starting")
        self.status_spinner.set_visible(busy)
        self.status_spinner.set_spinning(busy)
        self.status_icon.set_visible(not busy)
        self.status_title.set_label(title)
        for name in ("dpi-ok", "dpi-fail", "dpi-off", "dpi-busy"):
            self.status_title.remove_css_class(name)
        self.status_title.add_css_class(css)

        strategy = data.get("strategy")
        if state == "active" and strategy:
            self.status_subtitle.set_label(
                f"{strategy['label']} yöntemi ile Discord ve diğer engelli "
                f"siteler açık.")
        elif state == "dns-only":
            self.status_subtitle.set_label(
                "Bu ağda DPI engeli görülmedi; şifreli DNS yeterli oldu.")
        elif state == "failed":
            self.status_subtitle.set_label(data.get("detail", ""))
        elif state == "disabled":
            self.status_subtitle.set_label("Tüm kurallar geri alındı.")
        else:
            self.status_subtitle.set_label(data.get("detail", ""))

        self.toggle_button.set_label(
            "Korumayı aç" if state == "disabled" else "Korumayı kapat")
        if state == "disabled":
            self.toggle_button.add_css_class("suggested-action")
            self.toggle_button.remove_css_class("destructive-action")
        else:
            self.toggle_button.remove_css_class("suggested-action")
            self.toggle_button.add_css_class("destructive-action")

        isp = data.get("isp", {})
        confidence = int(float(isp.get("confidence", 0)) * 100)
        self.rows["isp"].set_subtitle(
            f"{isp.get('label', '—')}"
            + (" (elle seçildi)" if isp.get("manual") else f" — %{confidence} güven")
        )
        link = data.get("link", {})
        network = data.get("network", {})
        detail = network.get("name", "—")
        if link.get("as_name"):
            detail += f" · AS{link.get('asn')} {link.get('as_name')}"
        self.rows["network"].set_subtitle(detail)

        if strategy:
            self.rows["strategy"].set_subtitle(
                f"{strategy['label']} ({strategy['name']})")
        else:
            self.rows["strategy"].set_subtitle(
                "atlatma gerekmiyor" if state == "dns-only" else "—")

        dns = data.get("dns", {})
        self.rows["dns"].set_subtitle(
            f"{dns.get('provider', '—')} · {dns.get('query', 0)} sorgu, "
            f"{dns.get('cache_hit', 0)} önbellek")

        firewall = data.get("firewall", {})
        self.rows["firewall"].set_subtitle(
            f"{firewall.get('backend', '—')} · {firewall.get('ips', 0)} IP · "
            f"kip: {firewall.get('mode', '—')}")

        proxy = data.get("proxy", {})
        self.rows["traffic"].set_subtitle(
            f"{proxy.get('connections', 0)} bağlantı, "
            f"{proxy.get('bypassed', 0)} atlatıldı · "
            f"çalışma süresi {self._fmt_uptime(data.get('uptime', 0))}")

        self._refresh_results(data.get("last_results", []))
        self._refresh_learned(data.get("learned_domains", []))

    def _show_offline(self, response: dict) -> None:
        title, icon, css = STATUS_VIEW["offline"]
        self.status_spinner.set_visible(False)
        self.status_icon.set_visible(True)
        self.status_title.set_label(title)
        self.status_subtitle.set_label(response.get("error", ""))
        if response.get("code") == "permission":
            self.banner.show_message(
                f"Denetim soketine erişemiyorsunuz. Kullanıcınızı '{SOCKET_GROUP}' "
                "grubuna ekleyip oturumu yeniden açın.",
                "Komutu kopyala",
                lambda: self._copy(
                    f"sudo usermod -aG {SOCKET_GROUP} $USER"))
        else:
            self.banner.show_message(
                "Arka plan servisi çalışmıyor.",
                "Servisi başlat", self.restart_service)

    def _refresh_results(self, results: list[dict]) -> None:
        for row in self._result_rows:
            self.results_group.remove(row)
        self._result_rows.clear()
        if not results:
            self.results_group.set_visible(False)
            return
        for result in results[-8:]:
            row = Adw.ActionRow(title=result["label"], subtitle=result["strategy"])
            if result["ok"]:
                label = Gtk.Label(label=f"✓ {result['latency_ms']} ms")
                label.add_css_class("dpi-ok")
            else:
                label = Gtk.Label(label=f"✕ {result['error']}", wrap=True,
                                  max_width_chars=28, xalign=1.0)
                label.add_css_class("dim-label")
            row.add_suffix(label)
            self.results_group.add(row)
            self._result_rows.append(row)
        self.results_group.set_visible(True)

    # -- alan adları -------------------------------------------------------
    def _refresh_domain_rows(self) -> None:
        for row in self._custom_rows:
            self.custom_group.remove(row)
        self._custom_rows.clear()
        for domain in self.config.get("extra_domains", []):
            row = Adw.ActionRow(title=domain)
            button = Gtk.Button(icon_name="user-trash-symbolic",
                                valign=Gtk.Align.CENTER, tooltip_text="Kaldır")
            button.add_css_class("flat")
            button.connect("clicked", lambda _b, d=domain: self._remove_domain(d))
            row.add_suffix(button)
            self.custom_group.add(row)
            self._custom_rows.append(row)

    def _refresh_learned(self, learned: list[str]) -> None:
        if [r.get_title() for r in self._learned_rows] == learned:
            return
        for row in self._learned_rows:
            self.learned_group.remove(row)
        self._learned_rows.clear()
        for domain in learned:
            row = Adw.ActionRow(title=domain, subtitle="otomatik eklendi")
            self.learned_group.add(row)
            self._learned_rows.append(row)
        self.learned_group.set_visible(bool(learned))

    def _add_domain(self) -> None:
        text = self.entry_domain.get_text().strip().lower().strip(".")
        if not text or "." not in text:
            self.toast("Geçerli bir alan adı yazın (örn. discord.com)")
            return
        domains = list(self.config.get("extra_domains", []))
        if text in domains:
            self.toast("Bu alan adı zaten listede")
            return
        domains.append(text)
        self.entry_domain.set_text("")
        self._set_config(extra_domains=domains)
        self.config["extra_domains"] = domains
        self._refresh_domain_rows()
        self.toast(f"{text} eklendi")

    def _remove_domain(self, domain: str) -> None:
        domains = [d for d in self.config.get("extra_domains", []) if d != domain]
        self._set_config(extra_domains=domains)
        self.config["extra_domains"] = domains
        self._refresh_domain_rows()

    # -- günlük ------------------------------------------------------------
    def _on_logs(self, response: dict) -> None:
        if not response.get("ok"):
            return
        entries = response["data"]
        if not entries:
            return
        self._log_since = entries[-1]["ts"]
        for entry in entries:
            stamp = time.strftime("%H:%M:%S", time.localtime(entry["ts"]))
            self._log_lines.append(f"{stamp}  {entry['level']:<7} {entry['msg']}")
        del self._log_lines[:-800]
        self.log_buffer.set_text("\n".join(self._log_lines))
        adjustment = self.log_scroller.get_vadjustment()
        GLib.idle_add(lambda: adjustment.set_value(
            adjustment.get_upper() - adjustment.get_page_size()))

    # ------------------------------------------------------------------ #
    # eylemler
    # ------------------------------------------------------------------ #
    def toggle_protection(self) -> None:
        enabled = not bool(self.status.get("enabled", True))
        self.client.call("enable" if enabled else "disable", self._on_action)
        self.toast("Koruma açılıyor…" if enabled else "Koruma kapatılıyor…")

    def do_search(self) -> None:
        self.client.call("search", self._on_action, reason="kullanıcı isteği")
        self.toast("Yöntem aranıyor…")

    def do_test(self) -> None:
        self.toast("discord.com test ediliyor…")
        self.client.call("test", self._on_test)

    def _on_test(self, response: dict) -> None:
        if not response.get("ok"):
            self.toast(f"Test başarısız: {response.get('error')}")
            return
        result = response["data"]
        if result["ok"]:
            self.toast(f"✓ {result['target']} erişilebilir "
                       f"({result['latency_ms']} ms, {result['label']})")
        else:
            self.toast(f"✕ {result['target']} açılmadı: {result['error']}")

    def _on_action(self, response: dict) -> None:
        if not response.get("ok"):
            self.toast(f"İşlem başarısız: {response.get('error')}")
        self.client.call("status", self._on_status)

    def forget_network(self) -> None:
        self.client.call("forget", self._on_action)
        self.toast("Bu ağ için kayıtlı yöntem silindi")

    def restart_service(self) -> None:
        try:
            Gio.Subprocess.new(
                ["pkexec", "systemctl", "restart", "dpi-bypass.service"],
                Gio.SubprocessFlags.NONE)
            self.toast("Servis yeniden başlatılıyor…")
        except GLib.Error as exc:
            message(self, "Servis yeniden başlatılamadı",
                    f"{exc.message}\n\nTerminalden şunu çalıştırabilirsiniz:\n"
                    "sudo systemctl restart dpi-bypass")

    def _copy(self, text: str) -> None:
        self.get_clipboard().set(text)
        self.toast("Komut panoya kopyalandı")

    def toast(self, text: str) -> None:
        self.toasts.add_toast(Adw.Toast(title=text, timeout=3))

    @staticmethod
    def _fmt_uptime(seconds: int) -> str:
        minutes, _ = divmod(int(seconds), 60)
        hours, minutes = divmod(minutes, 60)
        days, hours = divmod(hours, 24)
        if days:
            return f"{days} gün {hours} sa"
        if hours:
            return f"{hours} sa {minutes} dk"
        return f"{minutes} dk"

    def show_about(self) -> None:
        fields = dict(
            application_name=APP_NAME,
            application_icon=APP_ID,
            version=__version__,
            developer_name=AUTHOR,
            developers=[AUTHOR],
            copyright=f"© 2026 {AUTHOR}",
            website=WEBSITE,
            issue_url=f"{WEBSITE}/issues",
            license_type=Gtk.License.GPL_3_0,
            comments=(
                "Türkiye'deki DPI tabanlı engelleri kullanıcı alanında aşan, "
                "ağ değiştiğinde yöntemi kendiliğinden yeniden bulan bir "
                "GNOME uygulaması."
            ),
        )
        if HAS_ABOUT_DIALOG:
            dialog = Adw.AboutDialog(**fields)
            dialog.present(self)
        else:
            dialog = Adw.AboutWindow(transient_for=self, **fields)
            dialog.present()
