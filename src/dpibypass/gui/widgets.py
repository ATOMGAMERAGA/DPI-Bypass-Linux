"""libadwaita sürüm farklarını gizleyen küçük yardımcılar.

Debian 12 libadwaita 1.2 ile gelirken Fedora/Arch 1.5+ kullanır. Uygulama
her ikisinde de aynı görünsün diye yeni satır türleri yoksa eşdeğerleri
Adw.ActionRow ile kurulur.
"""

from __future__ import annotations

from typing import Callable, Iterable

from gi.repository import Adw, GLib, Gtk

HAS_SWITCH_ROW = hasattr(Adw, "SwitchRow")
HAS_SPIN_ROW = hasattr(Adw, "SpinRow")
HAS_TOOLBAR_VIEW = hasattr(Adw, "ToolbarView")
HAS_BANNER = hasattr(Adw, "Banner")
HAS_ABOUT_DIALOG = hasattr(Adw, "AboutDialog")
HAS_ALERT_DIALOG = hasattr(Adw, "AlertDialog")


def switch_row(title: str, subtitle: str = "", active: bool = False,
               on_change: Callable[[bool], None] | None = None):
    """Anahtarlı satır (Adw.SwitchRow ya da eşdeğeri)."""
    if HAS_SWITCH_ROW:
        row = Adw.SwitchRow(title=title, subtitle=subtitle, active=active)
        if on_change:
            row.connect("notify::active",
                        lambda r, _p: on_change(r.get_active()))
        return row, row

    row = Adw.ActionRow(title=title, subtitle=subtitle)
    switch = Gtk.Switch(active=active, valign=Gtk.Align.CENTER)
    if on_change:
        switch.connect("notify::active",
                       lambda s, _p: on_change(s.get_active()))
    row.add_suffix(switch)
    row.set_activatable_widget(switch)

    # Adw.SwitchRow ile aynı API'yi taklit et
    row.get_active = switch.get_active          # type: ignore[attr-defined]
    row.set_active = switch.set_active          # type: ignore[attr-defined]
    return row, switch


def combo_row(title: str, subtitle: str, items: Iterable[str], selected: int = 0,
              on_change: Callable[[int], None] | None = None) -> Adw.ComboRow:
    model = Gtk.StringList()
    for item in items:
        model.append(item)
    row = Adw.ComboRow(title=title, subtitle=subtitle, model=model)
    row.set_selected(max(0, selected))
    if on_change:
        row.connect("notify::selected",
                    lambda r, _p: on_change(r.get_selected()))
    return row


def spin_row(title: str, subtitle: str, value: float, lower: float, upper: float,
             step: float = 1.0, on_change: Callable[[float], None] | None = None):
    adjustment = Gtk.Adjustment(value=value, lower=lower, upper=upper,
                                step_increment=step, page_increment=step * 10)
    if HAS_SPIN_ROW:
        row = Adw.SpinRow(title=title, subtitle=subtitle, adjustment=adjustment)
        if on_change:
            row.connect("notify::value", lambda r, _p: on_change(r.get_value()))
        return row

    row = Adw.ActionRow(title=title, subtitle=subtitle)
    spin = Gtk.SpinButton(adjustment=adjustment, valign=Gtk.Align.CENTER)
    if on_change:
        spin.connect("value-changed", lambda s: on_change(s.get_value()))
    row.add_suffix(spin)
    row.set_activatable_widget(spin)
    row.get_value = spin.get_value              # type: ignore[attr-defined]
    row.set_value = spin.set_value              # type: ignore[attr-defined]
    return row


def button_row(title: str, subtitle: str, button_label: str,
               on_click: Callable[[], None],
               css: str = "") -> Adw.ActionRow:
    row = Adw.ActionRow(title=title, subtitle=subtitle)
    button = Gtk.Button(label=button_label, valign=Gtk.Align.CENTER)
    if css:
        button.add_css_class(css)
    button.connect("clicked", lambda _b: on_click())
    row.add_suffix(button)
    row.set_activatable_widget(button)
    return row


class Banner(Gtk.Box):
    """Adw.Banner yoksa da çalışan basit bir uyarı çubuğu."""

    def __init__(self) -> None:
        super().__init__(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        self.add_css_class("dpi-banner")
        self.set_visible(False)
        self._icon = Gtk.Image.new_from_icon_name("dialog-warning-symbolic")
        self._label = Gtk.Label(xalign=0.0, wrap=True, hexpand=True)
        self._button = Gtk.Button(valign=Gtk.Align.CENTER)
        self._button.set_visible(False)
        self._button.add_css_class("suggested-action")
        self.append(self._icon)
        self.append(self._label)
        self.append(self._button)
        self._handler = 0

    def show_message(self, text: str, button_label: str = "",
                     on_click: Callable[[], None] | None = None,
                     kind: str = "warning") -> None:
        self._label.set_text(text)
        self._icon.set_from_icon_name(
            "dialog-warning-symbolic" if kind == "warning" else "dialog-information-symbolic"
        )
        for css in ("dpi-banner-warning", "dpi-banner-info"):
            self.remove_css_class(css)
        self.add_css_class(f"dpi-banner-{kind}")
        if self._handler:
            self._button.disconnect(self._handler)
            self._handler = 0
        if button_label and on_click:
            self._button.set_label(button_label)
            self._handler = self._button.connect("clicked", lambda _b: on_click())
            self._button.set_visible(True)
        else:
            self._button.set_visible(False)
        self.set_visible(True)

    def hide_message(self) -> None:
        self.set_visible(False)


def toolbar_view(header: Gtk.Widget, content: Gtk.Widget,
                 bottom: Gtk.Widget | None = None) -> Gtk.Widget:
    if HAS_TOOLBAR_VIEW:
        view = Adw.ToolbarView()
        view.add_top_bar(header)
        view.set_content(content)
        if bottom is not None:
            view.add_bottom_bar(bottom)
        return view
    box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
    box.append(header)
    content.set_vexpand(True)
    box.append(content)
    if bottom is not None:
        box.append(bottom)
    return box


def message(parent: Gtk.Window, heading: str, body: str) -> None:
    if HAS_ALERT_DIALOG:
        dialog = Adw.AlertDialog(heading=heading, body=body)
        dialog.add_response("ok", "Tamam")
        dialog.present(parent)
        return
    dialog = Adw.MessageDialog(transient_for=parent, heading=heading, body=body)
    dialog.add_response("ok", "Tamam")
    dialog.present()


def idle(func: Callable, *args) -> None:
    GLib.idle_add(func, *args)
