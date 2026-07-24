"""GTK4 + libadwaita uygulaması."""

from __future__ import annotations

import os
import sys

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw, Gdk, Gio, GLib, Gtk  # noqa: E402

from ..version import APP_ID, APP_NAME, __version__  # noqa: E402
from .window import MainWindow  # noqa: E402

STYLE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "style.css")


class DpiBypassApp(Adw.Application):
    def __init__(self) -> None:
        super().__init__(application_id=APP_ID,
                         flags=Gio.ApplicationFlags.HANDLES_COMMAND_LINE)
        self.window: MainWindow | None = None
        self.add_main_option("version", 0, GLib.OptionFlags.NONE,
                             GLib.OptionArg.NONE, "Sürümü yazdır ve çık", None)

    def do_command_line(self, command_line: Gio.ApplicationCommandLine) -> int:
        options = command_line.get_options_dict()
        if options.contains("version"):
            command_line.print_literal(f"{APP_NAME} {__version__}\n")
            return 0
        self.activate()
        return 0

    def do_startup(self) -> None:
        Adw.Application.do_startup(self)
        self._load_css()
        self._load_icons()

        quit_action = Gio.SimpleAction.new("quit", None)
        quit_action.connect("activate", lambda *_: self.quit())
        self.add_action(quit_action)
        self.set_accels_for_action("app.quit", ["<Primary>q"])

    def do_activate(self) -> None:
        if self.window is None:
            self.window = MainWindow(self)
        self.window.present()

    def _load_css(self) -> None:
        display = Gdk.Display.get_default()
        if display is None:
            return
        provider = Gtk.CssProvider()
        try:
            provider.load_from_path(STYLE)
        except GLib.Error:
            return
        Gtk.StyleContext.add_provider_for_display(
            display, provider, Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION)

    @staticmethod
    def _load_icons() -> None:
        """Kaynak ağacından çalıştırıldığında simgeleri bul."""
        display = Gdk.Display.get_default()
        if display is None:
            return
        theme = Gtk.IconTheme.get_for_display(display)
        root = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "..", "..", "..", "data", "icons"))
        if os.path.isdir(root):
            theme.add_search_path(root)


def main(argv: list[str] | None = None) -> int:
    app = DpiBypassApp()
    return app.run(argv if argv is not None else sys.argv)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
