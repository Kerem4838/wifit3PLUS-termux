"""The Jam All control lives only on the Scanner and routes through the app toggle."""
from contextlib import asynccontextmanager

import pytest
from textual.app import App
from textual.widgets import Button, Input

from wifit3.models import AccessPoint
from wifit3.persist.vault import Vault
from wifit3.ui.app import WifiteApp
from wifit3.ui.screens.filter import FilterBar
from wifit3.ui.screens.focus_v2 import FocusViewV2
from wifit3.ui.screens.probe_scanner import ProbeScannerView
from wifit3.ui.screens.scanner import ScannerView
from wifit3.wlan.sink import WlanSink


class _FakeIface:
    def __init__(self, supported):
        self.supported_channels = supported
        self.current_channel = supported[0] if supported else 1
        self.chipset = "test"
        self._is_hopping = True

    async def stop_hopping(self):
        self._is_hopping = False

    async def start_hopping(self, channels=None, interval=0.25):
        self._is_hopping = True


class _FakeArray:
    def __init__(self, aps, supported):
        self.access_points = {ap.bssid: ap for ap in aps}
        self._sink = WlanSink()
        self._sink.access_points = self.access_points
        self.clients = {}
        self.forged_macs = set()
        self.supported_channels = supported
        self.members = [_FakeIface(supported)] if supported else []

    def guessid(self, ap):
        return self._sink.guessid(ap)

    def get_access_points(self, include_eviltwin=True):
        return list(self.access_points.values())

    async def start_hopping(self, channels=None, interval=0.25, include_dfs_channels=True):
        pass

    @asynccontextmanager
    async def claim(self, iface):
        await iface.stop_hopping()
        try:
            yield iface
        finally:
            await iface.start_hopping()


class _ScannerHost(App):
    CSS = WifiteApp.CSS
    guessid = WifiteApp.guessid

    def __init__(self, array):
        super().__init__()
        self.array = array
        self.pbc_enabled = True
        self.target_ap = None
        self.vault = Vault()
        self.running = False
        self.toggle_calls: list = []

    @property
    def jam_all_running(self):
        return self.running

    def toggle_jam_all(self, log=None):
        self.toggle_calls.append(log)
        self.running = not self.running
        return self.running

    def persist_config(self):
        pass

    def on_mount(self):
        self.push_screen(ScannerView())


def _host():
    ap = AccessPoint(bssid="aa:bb:cc:00:00:01", ssid="Net", channel=1)
    return _ScannerHost(_FakeArray([ap], [1, 6, 11]))


def test_j_binding_is_scanner_scoped_only():
    assert any(b.key == "j" and b.action == "jam_all" for b in ScannerView.BINDINGS)
    assert all(b.key != "j" for b in WifiteApp.BINDINGS)
    assert all(b.action != "jam_all" for b in WifiteApp.BINDINGS)
    assert all(b.action != "jam_all" for b in ProbeScannerView.BINDINGS)
    assert all(b.action != "jam_all" for b in FocusViewV2.BINDINGS)


def test_jam_button_is_only_in_the_scanner_filter_bar():
    assert "filter-jam-all" in FilterBar.DEFAULT_CSS
    assert "filter-jam-all" in ScannerView.CSS
    assert "filter-jam-all" not in ProbeScannerView.CSS
    assert "filter-jam-all" not in FocusViewV2.CSS


@pytest.mark.asyncio
async def test_filter_bar_button_posts_toggle_and_tracks_state():
    app = _host()
    async with app.run_test() as pilot:
        await pilot.pause(0)
        scanner = app.screen
        assert isinstance(scanner, ScannerView)
        button = scanner.query_one("#filter-jam-all", Button)
        assert str(button.label) == "Jam All"
        assert button.variant == "primary"

        button.press()
        await pilot.pause()
        assert len(app.toggle_calls) == 1
        assert str(button.label) == "Stop Jam"
        assert button.variant == "error"

        button.press()
        await pilot.pause()
        assert len(app.toggle_calls) == 2
        assert str(button.label) == "Jam All"
        assert button.variant == "primary"


@pytest.mark.asyncio
async def test_j_hotkey_toggles_and_does_not_eat_filter_typing():
    app = _host()
    async with app.run_test() as pilot:
        await pilot.pause(0)
        scanner = app.screen
        await pilot.press("j")
        await pilot.pause()
        assert len(app.toggle_calls) == 1

        text = scanner.query_one("#filter-text", Input)
        text.focus()
        await pilot.press("j")
        await pilot.pause()
        assert len(app.toggle_calls) == 1
        assert text.value == "j"


@pytest.mark.asyncio
async def test_button_state_resyncs_on_resume():
    app = _host()
    async with app.run_test() as pilot:
        await pilot.pause(0)
        scanner = app.screen
        button = scanner.query_one("#filter-jam-all", Button)

        app.running = True
        await scanner.on_screen_resume()
        assert str(button.label) == "Stop Jam"
        assert button.variant == "error"

        app.running = False
        scanner._sync_jam_button()
        assert str(button.label) == "Jam All"
        assert button.variant == "primary"
