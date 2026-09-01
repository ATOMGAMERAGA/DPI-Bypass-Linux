"""Arayüz karar mantığı testleri (GTK olmadan, sahte 'gi' ile).

İki şey doğrulanır:

* Erişim hatası her zaman "gruba eklenmediniz" diye gösterilmez; gerçek
  sebebe göre farklı banner ve farklı düğme çıkar.
* Ping düşürme paneli yalnızca gerçekten ölçülmüş sonucu gösterir; kazanç
  doğrulanmadıysa "iyileştirme bulunamadı" der.
"""

from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))), "src"))

import gtkstub  # noqa: E402

gtkstub.install()

from dpibypass import session_access  # noqa: E402
from dpibypass.gui import window as window_module  # noqa: E402


class FakeBanner:
    def __init__(self) -> None:
        self.text = ""
        self.button = ""
        self.callback = None
        self.visible = False

    def show_message(self, text, button_label="", on_click=None,
                     kind="warning"):
        self.text = text
        self.button = button_label
        self.callback = on_click
        self.visible = True

    def hide_message(self):
        self.visible = False


class FakeRow:
    def __init__(self) -> None:
        self.subtitle = ""
        self.visible = True

    def set_subtitle(self, text): self.subtitle = text
    def set_visible(self, value): self.visible = bool(value)


def make_window() -> window_module.MainWindow:
    """__init__ çalıştırmadan yalnız test edilen alanları kuran pencere."""
    win = window_module.MainWindow.__new__(window_module.MainWindow)
    win.banner = FakeBanner()
    win.status_spinner = gtkstub.StubWidget()
    win.status_icon = gtkstub.StubWidget()
    win.status_title = gtkstub.StubWidget()
    win.status_subtitle = gtkstub.StubWidget()
    win.row_latency = gtkstub.StubWidget()
    win.row_latency_info = FakeRow()
    win.latency_detail_rows = {key: FakeRow()
                               for key, _title in
                               window_module.LATENCY_DETAIL_ROWS}
    win._loading = False
    win.status = {}
    win.toasts = gtkstub.StubWidget()
    return win


class TestAccessBanners(unittest.TestCase):
    """Aynı PermissionError farklı sebeplere göre farklı gösterilmeli."""

    def show(self, state: str, **overrides) -> FakeBanner:
        report = session_access.AccessReport(
            state=state, detail=f"detay-{state}", remedy=f"çözüm-{state}")
        for key, value in overrides.items():
            setattr(report, key, value)
        win = make_window()
        original = session_access.analyze
        session_access.analyze = lambda *args, **kwargs: report
        try:
            win._show_offline({"ok": False, "code": "permission",
                               "error": "erişim reddedildi"})
        finally:
            session_access.analyze = original
        return win.banner

    def test_stale_session_offers_a_restart_not_a_usermod_command(self):
        banner = self.show(session_access.STATE_STALE_SESSION,
                           sg_path="/usr/bin/sg")
        self.assertIn("yeniden başlat", banner.button.lower())
        self.assertNotIn("usermod", banner.text)

    def test_not_a_member_offers_repair_or_the_command(self):
        banner = self.show(session_access.STATE_NOT_MEMBER)
        self.assertTrue(banner.visible)
        self.assertIn("detay-not-a-member", banner.text)
        self.assertIn(banner.button, ("Erişimi onar", "Komutu kopyala"))

    def test_socket_permissions_is_reported_as_a_service_problem(self):
        banner = self.show(session_access.STATE_SOCKET_PERMISSIONS)
        self.assertIn("yeniden başlat", banner.button.lower())
        self.assertNotIn("grup", banner.text.lower())

    def test_missing_socket_is_reported_as_a_service_problem(self):
        banner = self.show(session_access.STATE_NO_SOCKET)
        self.assertIn("servis", banner.text.lower())
        self.assertEqual(banner.button, "Servisi başlat")

    def test_denied_with_correct_setup_does_not_blame_the_group(self):
        banner = self.show(session_access.STATE_DENIED)
        self.assertIn("detay-denied", banner.text)
        self.assertNotIn("usermod", banner.text)

    def test_every_state_produces_a_distinct_button(self):
        seen = {}
        for state in (session_access.STATE_STALE_SESSION,
                      session_access.STATE_NOT_MEMBER,
                      session_access.STATE_SOCKET_PERMISSIONS,
                      session_access.STATE_NO_SOCKET):
            seen[state] = self.show(state, sg_path="/usr/bin/sg").text
        self.assertEqual(len(set(seen.values())), len(seen))


class TestLatencyPanel(unittest.TestCase):
    def refresh(self, latency: dict):
        win = make_window()
        win._refresh_latency(latency)
        return win

    def test_verified_gain_shows_before_after_and_delta(self):
        win = self.refresh({
            "enabled": True, "active": True, "state": "active",
            "message": "Doğrulandı: median 24 → 19 ms",
            "applied": ["Wi-Fi güç tasarrufu kapatıldı", "fq_codel uygulandı"],
            "before": {"remote": {"median_ms": 24, "p95_ms": 38,
                                  "jitter_ms": 4.8, "packet_loss": 0}},
            "after": {"remote": {"median_ms": 19, "p95_ms": 27,
                                 "jitter_ms": 2.1, "packet_loss": 0}},
            "gain": {"median_ms": -5, "p95_ms": -11, "jitter_ms": -2.7},
            "candidates": [], "skipped": [],
        })
        rows = win.latency_detail_rows
        self.assertIn("24 ms median", rows["before"].subtitle)
        self.assertIn("38 ms p95", rows["before"].subtitle)
        self.assertIn("19 ms median", rows["after"].subtitle)
        self.assertIn("-5 ms median", rows["gain"].subtitle)
        self.assertIn("-11 ms p95", rows["gain"].subtitle)
        self.assertIn("fq_codel", rows["applied"].subtitle)
        self.assertTrue(rows["after"].visible)

    def test_no_gain_never_shows_an_after_or_a_gain(self):
        win = self.refresh({
            "enabled": True, "active": False, "state": "no-gain",
            "message": "Bu ağda doğrulanmış bir gecikme iyileştirmesi bulunamadı",
            "applied": [],
            "before": {"remote": {"median_ms": 24, "p95_ms": 38,
                                  "jitter_ms": 4.8, "packet_loss": 0}},
            "after": {"remote": {"median_ms": 19, "p95_ms": 27,
                                 "jitter_ms": 2.1, "packet_loss": 0}},
            "gain": {}, "candidates": [], "skipped": [],
        })
        rows = win.latency_detail_rows
        self.assertIn("bulunamadı", win.row_latency_info.subtitle)
        self.assertFalse(rows["after"].visible)
        self.assertFalse(rows["gain"].visible)
        self.assertFalse(rows["applied"].visible)

    def test_candidate_verdicts_are_listed(self):
        win = self.refresh({
            "enabled": True, "active": False, "state": "no-gain",
            "message": "kazanç yok", "applied": [],
            "candidates": [
                {"key": "wifi-power-save", "label": "Wi-Fi güç tasarrufu kapalı",
                 "verified": False},
                {"key": "qdisc-fq_codel", "label": "fq_codel kuyruk disiplini",
                 "verified": True},
            ],
            "skipped": ["cake adayı atlandı"],
        })
        text = win.latency_detail_rows["candidates"].subtitle
        self.assertIn("✕ Wi-Fi güç tasarrufu kapalı", text)
        self.assertIn("✓ fq_codel kuyruk disiplini", text)
        self.assertIn("cake", win.latency_detail_rows["skipped"].subtitle)

    def test_disabled_mode_hides_every_detail_row(self):
        win = self.refresh({"enabled": False, "active": False,
                            "state": "disabled", "message": "Kapalı"})
        self.assertEqual(win.row_latency_info.subtitle, "kapalı")
        for key in ("before", "after", "gain", "applied"):
            self.assertFalse(win.latency_detail_rows[key].visible, key)

    def test_running_benchmark_is_shown_as_in_progress(self):
        win = self.refresh({
            "enabled": True, "active": False, "state": "benchmarking",
            "message": "fq_codel kuyruk disiplini deneniyor…", "applied": [],
        })
        self.assertIn("deneniyor", win.row_latency_info.subtitle)

    def test_formatters_tolerate_missing_fields(self):
        self.assertEqual(window_module.MainWindow._fmt_remote({}), "")
        self.assertEqual(window_module.MainWindow._fmt_remote(
            {"median_ms": None}), "")
        self.assertEqual(window_module.MainWindow._fmt_gain({}), "")
        self.assertEqual(window_module.MainWindow._fmt_gain(
            {"median_ms": None, "p95_ms": -3}), "-3 ms p95")


if __name__ == "__main__":
    unittest.main(verbosity=2)
