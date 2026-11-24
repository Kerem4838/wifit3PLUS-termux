"""UI tests for ProbeScannerView sorting, hover popup, Tier List, KnownApStore, and Vault Probes."""
import time
from pathlib import Path

import pytest
from textual.widgets import Button, DataTable, Input, Static, Tabs

from wifit3.models import AccessPoint, Client, IdSource, ProbeRecord, ProbedSsid
from wifit3.persist.config import Config
from wifit3.ui.app import WifiteApp
from wifit3.ui.screens.focus_v2 import FocusViewV2
from wifit3.ui.screens.focus_v2.clients_list import ClientWidget
from wifit3.ui.screens.probe_scanner import ProbeScannerView
from wifit3.ui.screens.vault_drawer import VaultDrawer
from wifit3.ui.screens.vault_probes import VaultProbesView
from wifit3.ui.vault.modals.nickname import NicknameModal
from wifit3.wlan.array import WlanArray
from wifit3.wlan.sink import WlanSink

from tests.ui.wait_until import wait_until


def _seed_array() -> WlanArray:
    sink = WlanSink()
    now = time.time()
    ap = AccessPoint(
        bssid="aa:bb:cc:dd:ee:ff",
        ssid="HomeNet",
        channel=6,
    )
    ap.identity.update(IdSource.WSC_BEACON, manufacturer="TP-Link", model_name="Archer C7")
    sink.access_points["aa:bb:cc:dd:ee:ff"] = ap

    real_mac = "18:7f:88:aa:bb:cc"
    sink.clients[real_mac] = Client(mac=real_mac, bssid="aa:bb:cc:dd:ee:ff", packets=7)
    rec1 = ProbeRecord(
        mac=real_mac,
        count=4,
        first_seen=now - 20,
        last_seen=now,
        last_channel=6,
        associated_bssid="aa:bb:cc:dd:ee:ff",
        signal_by_card={"wlan0": -48},
    )
    rec1.ssids["Starbucks"] = ProbedSsid(ssid="Starbucks", count=3, first_seen=now - 20, last_seen=now)
    rec1.ssids["HomeNet"] = ProbedSsid(ssid="HomeNet", count=2, first_seen=now - 15, last_seen=now)

    rec2 = ProbeRecord(
        mac="02:33:44:55:66:77",
        count=1,
        broadcast_count=1,
        first_seen=now - 50,
        last_seen=now - 50,
        last_channel=1,
        signal_by_card={"wlan0": -72},
    )
    sink.probes[rec1.mac] = rec1
    sink.probes[rec2.mac] = rec2
    return WlanArray(sink=sink)


class _ProbeTestApp(WifiteApp):
    CSS = WifiteApp.CSS + "\nVaultDrawer #vault-content { offset-y: 0; }"

    def __init__(self) -> None:
        super().__init__()
        self.copied: list[str] = []

    def copy_to_clipboard(self, text: str) -> None:
        self.copied.append(text)


@pytest.mark.asyncio
@pytest.mark.usefixtures("no_usb_devices")
async def test_probe_scanner_renders_sorts_filters_and_copies():
    app = _ProbeTestApp()
    app.array = _seed_array()

    async with app.run_test(size=(130, 40)) as pilot:
        await app.push_screen(app.probe_view)
        await pilot.pause()

        table = app.probe_view.query_one("#probe-table", DataTable)
        assert table.row_count == 2
        assert [r.key.value for r in table.ordered_rows] == ["18:7f:88:aa:bb:cc", "02:33:44:55:66:77"]

        detail = str(app.probe_view.query_one("#probe-detail", Static).content)
        assert "Starbucks" in detail
        assert "HomeNet" in detail

        # Toggle sort direction via 'o' and verify row order actually flips
        await pilot.press("o")
        await pilot.pause()
        assert [r.key.value for r in table.ordered_rows] == ["02:33:44:55:66:77", "18:7f:88:aa:bb:cc"]

        # Cycle back to descending and test header click sort on MAC
        await pilot.press("o")
        await pilot.pause()
        mac_col = table.columns["mac"]
        app.probe_view.post_message(DataTable.HeaderSelected(table, mac_col.key, 0, mac_col.label))
        await pilot.pause()
        assert [r.key.value for r in table.ordered_rows] == ["02:33:44:55:66:77", "18:7f:88:aa:bb:cc"]

        # Reset sort to last_seen desc via clicking last_seen header twice or once
        ls_col = table.columns["last_seen"]
        app.probe_view.post_message(DataTable.HeaderSelected(table, ls_col.key, 7, ls_col.label))
        await pilot.pause()
        assert [r.key.value for r in table.ordered_rows] == ["18:7f:88:aa:bb:cc", "02:33:44:55:66:77"]

        # Named-only filter hides the wildcard-only client
        await pilot.press("n")
        await pilot.pause()
        assert table.row_count == 1
        await pilot.press("n")
        await pilot.pause()
        assert table.row_count == 2

        # Copy probed SSIDs for selected client
        await pilot.press("c")
        assert set(app.copied[0].splitlines()) == {"Starbucks", "HomeNet"}

        # Text filter down to broadcast-only client
        flt = app.probe_view.query_one("#probe-filter", Input)
        flt.value = "66:77"
        await pilot.pause()
        assert table.row_count == 1


@pytest.mark.asyncio
@pytest.mark.usefixtures("no_usb_devices")
async def test_probe_scanner_mac_filter_and_split_view():
    app = _ProbeTestApp()
    app.array = _seed_array()

    async with app.run_test(size=(130, 40)) as pilot:
        await app.push_screen(app.probe_view)
        await pilot.pause()

        primary = app.probe_view.query_one("#probe-table", DataTable)
        random_pane = app.probe_view.query_one("#probe-random-pane")
        random_table = app.probe_view.query_one("#probe-random-table", DataTable)

        await pilot.press("m")
        await pilot.pause()
        assert primary.row_count == 1
        assert primary.ordered_rows[0].key.value == "18:7f:88:aa:bb:cc"

        await pilot.press("m")
        await pilot.pause()
        assert primary.row_count == 1
        assert primary.ordered_rows[0].key.value == "02:33:44:55:66:77"

        await pilot.press("m")
        await pilot.pause()
        assert primary.row_count == 2

        await pilot.press("g")
        await pilot.pause()
        assert random_pane.display is True
        assert primary.row_count == 1
        assert random_table.row_count == 1


@pytest.mark.asyncio
@pytest.mark.usefixtures("no_usb_devices")
async def test_scanner_button_opens_probe_view_and_returns():
    app = _ProbeTestApp()
    app.array = _seed_array()

    async with app.run_test(size=(130, 40)) as pilot:
        await app.push_screen(app.scanner_view)
        await pilot.pause()
        app.scanner_view.query_one("#filter-open-probes", Button).press()
        await pilot.pause()
        assert isinstance(app.screen, ProbeScannerView)

        await pilot.press("escape")
        await pilot.pause()
        assert app.screen is app.scanner_view


@pytest.mark.asyncio
@pytest.mark.usefixtures("no_usb_devices")
async def test_probe_scanner_jumps_to_associated_ap_and_tags_client():
    app = _ProbeTestApp()
    app.array = _seed_array()

    async with app.run_test(size=(130, 40)) as pilot:
        await app.push_screen(app.probe_view)
        await pilot.pause()

        await pilot.press("enter")
        await pilot.pause()

        assert isinstance(app.screen, FocusViewV2)
        assert app.target_ap is not None and app.target_ap.bssid == "aa:bb:cc:dd:ee:ff"
        assert app.tagged_client_mac == "18:7f:88:aa:bb:cc"
        widget = app.focus_view.query_one("#cl-187f88aabbcc", ClientWidget)
        assert widget.has_class("-tagged")


@pytest.mark.asyncio
@pytest.mark.usefixtures("no_usb_devices")
async def test_probe_scanner_and_tier_double_click_jump_to_focus():
    app = _ProbeTestApp()
    app.array = _seed_array()

    async with app.run_test(size=(130, 40)) as pilot:
        await app.push_screen(app.probe_view)
        await pilot.pause()

        # Single click on row 0 selects without leaving ProbeScannerView
        await pilot.click("#probe-table", offset=(2, 1), times=1)
        await pilot.pause()
        assert app.screen is app.probe_view

        # Clicking row 1 resets single-click history; then double-clicking row 0 (chain=2) jumps
        await pilot.click("#probe-table", offset=(2, 2), times=1)
        await pilot.pause()
        assert app.screen is app.probe_view

        await pilot.click("#probe-table", offset=(2, 1), times=2)
        await pilot.pause()
        assert isinstance(app.screen, FocusViewV2)
        assert app.target_ap is not None and app.target_ap.bssid == "aa:bb:cc:dd:ee:ff"
        assert app.tagged_client_mac == "18:7f:88:aa:bb:cc"

        # Return to ProbeScannerView, hover Tier List row 1 (HomeNet), and double-click it
        await pilot.press("escape")
        await pilot.pause()
        assert app.screen is app.probe_view

        await pilot.hover("#probe-tier-table", offset=(6, 2))
        await pilot.pause()
        await pilot.click("#probe-tier-table", offset=(6, 2), times=2)
        await pilot.pause()
        assert isinstance(app.screen, FocusViewV2)
        assert app.target_ap is not None and app.target_ap.bssid == "aa:bb:cc:dd:ee:ff"


@pytest.mark.asyncio
@pytest.mark.usefixtures("no_usb_devices")
async def test_vault_probes_double_click_focuses_ap():
    app = _ProbeTestApp()
    app.array = _seed_array()
    app.vault.sync_probes(app.array.probes, app.array.access_points)

    async with app.run_test(size=(130, 40)) as pilot:
        drawer = VaultDrawer(initial_section="probes")
        await app.push_screen(drawer)
        await wait_until(pilot, lambda: drawer.has_class("open"))

        # Verify rapid consecutive clicks (<0.6s) also trigger double-click jump
        await pilot.click("#vault-probes-table", offset=(4, 1), times=1)
        await pilot.click("#vault-probes-table", offset=(4, 1), times=1)
        await pilot.pause()
        assert isinstance(app.screen, FocusViewV2)
        assert app.target_ap is not None and app.target_ap.bssid == "aa:bb:cc:dd:ee:ff"
        assert app.tagged_client_mac == "18:7f:88:aa:bb:cc"


@pytest.mark.asyncio
@pytest.mark.usefixtures("no_usb_devices")
async def test_client_nickname_in_vault_probe_scanner_and_focus():
    app = _ProbeTestApp()
    app.array = _seed_array()
    app.vault.sync_probes(app.array.probes, app.array.access_points)
    mac = "18:7f:88:aa:bb:cc"

    async with app.run_test(size=(130, 40)) as pilot:
        drawer = VaultDrawer(initial_section="probes")
        await app.push_screen(drawer)
        await wait_until(pilot, lambda: drawer.has_class("open"))

        probes_view = drawer.query_one("#vault-probes", VaultProbesView)
        vault_table = probes_view.query_one("#vault-probes-table", DataTable)

        await pilot.press("n")
        await pilot.pause()
        assert isinstance(app.screen, NicknameModal)
        app.screen.query_one("#nickname", Input).value = "Kerem Phone"
        app.screen.query_one("#save", Button).press()
        await pilot.pause()

        assert "Kerem Phone" in str(vault_table.get_cell(mac, "client"))
        assert "Kerem Phone" in str(probes_view.query_one("#vault-probe-detail", Static).content)

        vfilter = probes_view.query_one("#vault-probe-filter", Input)
        vfilter.value = "Kerem"
        await pilot.pause()
        assert vault_table.row_count == 1
        vfilter.value = ""
        await pilot.pause()

        await pilot.press("escape")
        await wait_until(pilot, lambda: app.screen is not drawer)

        await app.push_screen(app.probe_view)
        await pilot.pause()
        probe_table = app.probe_view.query_one("#probe-table", DataTable)
        assert "Kerem Phone" in str(probe_table.get_cell(mac, "mac"))
        assert "Kerem Phone" in str(app.probe_view.query_one("#probe-detail", Static).content)
        hover = app.probe_view._build_hover_text("probe-table", mac, time.time())
        assert hover is not None and "Kerem Phone" in hover

        # Rename directly from ProbeScannerView and check FocusViewV2 shows the nickname
        await pilot.press("r")
        await pilot.pause()
        assert isinstance(app.screen, NicknameModal)
        app.screen.query_one("#nickname", Input).value = "MacBook Pro"
        app.screen.query_one("#save", Button).press()
        await pilot.pause()
        assert "MacBook Pro" in str(probe_table.get_cell(mac, "mac"))

        await pilot.click("#probe-table", offset=(2, 1), times=2)
        await pilot.pause()
        assert isinstance(app.screen, FocusViewV2)
        widget = app.focus_view.query_one("#cl-187f88aabbcc", ClientWidget)
        assert str(widget._mac_label.content) == "MacBook Pro"


@pytest.mark.asyncio
@pytest.mark.usefixtures("no_usb_devices")
async def test_vault_drawer_probes_tabs_delete_and_focus_ap():
    app = _ProbeTestApp()
    app.array = _seed_array()
    app.vault.sync_probes(app.array.probes, app.array.access_points)

    async with app.run_test(size=(130, 40)) as pilot:
        drawer = VaultDrawer(initial_section="probes")
        await app.push_screen(drawer)
        await wait_until(pilot, lambda: drawer.has_class("open"))

        probes_view = drawer.query_one("#vault-probes", VaultProbesView)
        assert probes_view.display is True
        table = probes_view.query_one("#vault-probes-table", DataTable)
        tabs = probes_view.query_one("#vault-probe-tabs", Tabs)
        assert table.row_count == 2

        tabs.active = "probe-tab-random"
        await pilot.pause()
        assert table.row_count == 1
        assert table.ordered_rows[0].key.value == "02:33:44:55:66:77"

        await pilot.press("d")
        await pilot.pause()
        await pilot.click("#yes")
        await pilot.pause()
        assert len(app.vault.all_probes()) == 1

        tabs.active = "probe-tab-real"
        await pilot.pause()
        assert table.row_count == 1
        probes_view.query_one("#vault-probe-focus-btn", Button).press()
        await pilot.pause()
        assert isinstance(app.screen, FocusViewV2)
        assert app.tagged_client_mac == "18:7f:88:aa:bb:cc"


@pytest.mark.asyncio
@pytest.mark.usefixtures("no_usb_devices")
async def test_tier_list_hover_popup_ssid_sort_and_known_aps_memory():
    app = _ProbeTestApp()
    app.array = _seed_array()
    # Add a random-MAC client also probing Starbucks so Tier List shows Real & Random counts
    rnd_mac = "06:11:22:33:44:55"
    rnd = ProbeRecord(mac=rnd_mac, count=5, first_seen=time.time(), last_seen=time.time())
    rnd.ssids["Starbucks"] = ProbedSsid(ssid="Starbucks", count=5, first_seen=time.time(), last_seen=time.time())
    app.array.probes[rnd_mac] = rnd
    app.vault.sync_known_aps(app.array.access_points)

    # Hidden AP with same BSSID recalls its saved SSID via KnownApStore
    hidden_ap = AccessPoint(bssid="aa:bb:cc:dd:ee:ff", ssid=None)
    assert app.guessid(hidden_ap) == "HomeNet"
    assert "Archer C7" in app.vault.known_ap_model("aa:bb:cc:dd:ee:ff")

    async with app.run_test(size=(130, 40)) as pilot:
        await app.push_screen(app.probe_view)
        await pilot.pause()

        tier_table = app.probe_view.query_one("#probe-tier-table", DataTable)
        assert tier_table.row_count == 2
        assert tier_table.ordered_rows[0].key.value == "Starbucks"
        starbucks_real = str(tier_table.get_cell("Starbucks", "real"))
        starbucks_rnd = str(tier_table.get_cell("Starbucks", "random"))
        assert "1 (3 req)" in starbucks_real
        assert "1 (5 req)" in starbucks_rnd
        homenet_found = str(tier_table.get_cell("HomeNet", "found"))
        assert "Archer C7" in homenet_found

        hover = app.probe_view._build_hover_text("probe-table", "18:7f:88:aa:bb:cc", time.time())
        assert hover is not None and "Starbucks" in hover and "HomeNet" in hover

        # Toggle to SSIDs view and sort by probes count
        await pilot.press("t")
        await pilot.pause()
        ssid_table = app.probe_view.query_one("#probe-ssid-table", DataTable)
        assert ssid_table.row_count == 2
        await pilot.press("s")
        await pilot.pause()
        assert ssid_table.ordered_rows[0].key.value == "Starbucks"

        await pilot.press("e")
        await pilot.pause()
        csv_files = list(Path(Config.captures_dir).glob("probes_export_*.csv"))
        assert len(csv_files) == 1
        assert "Starbucks" in csv_files[0].read_text(encoding="utf-8")
