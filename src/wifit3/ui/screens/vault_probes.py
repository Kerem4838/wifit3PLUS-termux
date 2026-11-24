"""Vault Probes section: browse, inspect, export, and delete persisted client probe history."""
from __future__ import annotations

import time
from typing import Dict, List, Optional

from rich.markup import escape
from rich.text import Text
from textual import on
from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.css.query import NoMatches
from textual.message import Message
from textual.widget import Widget
from textual.widgets import Button, DataTable, Input, Static, Tab, Tabs

from wifit3.persist.probe_store import PersistedProbe, export_probes_csv
from wifit3.ui.screens.probe_scanner import ProbeDataTable
from wifit3.ui.screens.vault_item import date_text
from wifit3.ui.screens.vault_table import matches_filter


class DeleteProbePressed(Message):
    """Emitted when the user requests deleting a saved probe record."""

    def __init__(self, mac: str) -> None:
        super().__init__()
        self.mac = mac


class ClearProbesPressed(Message):
    """Emitted when the user requests clearing all saved probe records."""


class FocusProbeApPressed(Message):
    """Emitted when the user requests jumping to the AP associated with a probe client."""

    def __init__(self, bssid: str, mac: str) -> None:
        super().__init__()
        self.bssid = bssid
        self.mac = mac


class NicknameProbePressed(Message):
    """Emitted when the user requests editing a saved probe client's nickname."""

    def __init__(self, mac: str) -> None:
        super().__init__()
        self.mac = mac


def _short_date(epoch: float) -> str:
    if epoch <= 0:
        return "—"
    return date_text(int(epoch))


def _ssids_preview(probe: PersistedProbe, max_len: int = 20) -> str:
    if not probe.ssids:
        return "—"
    ordered = sorted(probe.ssids.values(), key=lambda s: (-s.last_seen, s.ssid.lower()))
    joined = ", ".join(entry.ssid for entry in ordered)
    if len(joined) <= max_len:
        return joined
    return joined[: max_len - 1] + "…"


class VaultProbesView(Widget):
    """Two-pane browser for persisted Probe Request client profiles in Vault."""

    DEFAULT_CSS = """
    VaultProbesView {
        width: 100%;
        height: 1fr;
        layout: horizontal;
    }
    VaultProbesView #vault-probes-left {
        width: 54;
        height: 1fr;
        border: heavy $primary;
        border-title-color: $primary;
        border-title-style: bold;
    }
    VaultProbesView #vault-probe-filter-bar {
        height: auto;
        padding: 0 1;
        border: round $primary;
        border-title-color: $primary;
        border-title-style: bold;
    }
    VaultProbesView #vault-probe-filter {
        width: 1fr;
    }
    VaultProbesView #vault-probe-tabs {
        margin-bottom: 0;
    }
    VaultProbesView #vault-probes-table {
        width: 100%;
        height: 1fr;
    }
    VaultProbesView #vault-probes-right {
        width: 1fr;
        height: 1fr;
        border: heavy $primary;
        border-title-color: $primary;
        border-title-style: bold;
        padding: 0 1;
    }
    VaultProbesView #vault-probe-detail-scroll {
        height: 1fr;
    }
    VaultProbesView #vault-probe-actions {
        height: auto;
        padding-top: 1;
    }
    """

    def __init__(self, id: Optional[str] = None) -> None:
        super().__init__(id=id)
        self._probes_by_mac: Dict[str, PersistedProbe] = {}
        self._filter_text: str = ""
        self._current_tab: str = "probe-tab-all"
        self._selected_mac: Optional[str] = None

    def compose(self) -> ComposeResult:
        left = Vertical(id="vault-probes-left")
        left.border_title = "PROBED CLIENTS (0 Real / 0 Rnd)"
        with left:
            filter_bar = Horizontal(id="vault-probe-filter-bar")
            filter_bar.border_title = "[u]F[/u]ILTER"
            with filter_bar:
                yield Input(placeholder="MAC, vendor, SSID, or AP",
                            id="vault-probe-filter", compact=True)
            yield Tabs(
                Tab("ALL", id="probe-tab-all"),
                Tab("REAL MAC", id="probe-tab-real"),
                Tab("RANDOM MAC", id="probe-tab-random"),
                id="vault-probe-tabs",
            )
            yield ProbeDataTable(id="vault-probes-table", cursor_type="row")
        right = Vertical(id="vault-probes-right")
        right.border_title = "PROBE DETAILS"
        with right:
            with VerticalScroll(id="vault-probe-detail-scroll"):
                yield Static("", id="vault-probe-detail")
            with Horizontal(id="vault-probe-actions"):
                yield Button("Focus AP", id="vault-probe-focus-btn", variant="success", disabled=True)
                yield Button("Nickname", id="vault-probe-nick-btn")
                yield Button("Copy SSIDs", id="vault-probe-copy-btn", variant="primary")
                yield Button("Export CSV", id="vault-probe-export-btn")
                yield Button("Delete", id="vault-probe-delete-btn", variant="error")
                yield Button("Clear All", id="vault-probe-clear-btn")

    def on_mount(self) -> None:
        table = self.query_one("#vault-probes-table", DataTable)
        table.add_column("CLIENT", key="client", width=21)
        table.add_column("PROBES", key="ssids", width=18)
        table.add_column("LAST SEEN", key="seen", width=12)
        self.reload()

    def focus_filter(self) -> None:
        try:
            self.query_one("#vault-probe-filter", Input).focus()
        except NoMatches:
            pass

    def focus_table(self) -> None:
        try:
            self.query_one("#vault-probes-table", DataTable).focus()
        except NoMatches:
            pass

    def selected_mac(self) -> Optional[str]:
        try:
            table = self.query_one("#vault-probes-table", DataTable)
            if table.row_count == 0:
                return None
            return table.coordinate_to_cell_key(table.cursor_coordinate).row_key.value
        except Exception:
            return self._selected_mac

    def _filtered_probes(self) -> List[PersistedProbe]:
        all_items = self.app.vault.all_probes()
        self._probes_by_mac = {p.mac: p for p in all_items}
        filtered: List[PersistedProbe] = []
        for probe in all_items:
            if self._current_tab == "probe-tab-real" and probe.is_randomized:
                continue
            if self._current_tab == "probe-tab-random" and not probe.is_randomized:
                continue
            if self._filter_text:
                vendor_field = "Randomized MAC" if probe.is_randomized else probe.vendor
                ap_ssid = probe.associated_ssid or (
                    self.app.vault.known_ap_ssid(probe.associated_bssid) if probe.associated_bssid else None
                ) or ""
                ap_model = self.app.vault.known_ap_model(probe.associated_bssid) if probe.associated_bssid else ""
                fields = [
                    probe.mac,
                    probe.nickname,
                    vendor_field,
                    probe.associated_bssid or "",
                    ap_ssid,
                    ap_model,
                    *probe.ssids.keys(),
                ]
                if not matches_filter(self._filter_text, fields):
                    continue
            filtered.append(probe)
        return filtered

    def reload(self) -> None:
        """Reload persisted probe records into the table and detail pane."""
        if not self.is_attached:
            return
        try:
            left = self.query_one("#vault-probes-left", Vertical)
            table = self.query_one("#vault-probes-table", DataTable)
        except NoMatches:
            return

        items = self._filtered_probes()
        total = len(self._probes_by_mac)
        rnd_count = sum(1 for p in self._probes_by_mac.values() if p.is_randomized)
        real_count = total - rnd_count
        left.border_title = f"PROBED CLIENTS ({real_count} Real / {rnd_count} Rnd)"

        selected = self.selected_mac()
        cursor_row = table.cursor_row
        with table.prevent(DataTable.RowHighlighted):
            table.clear()
            for probe in items:
                prefix = "[green]●[/] " if probe.associated_bssid else ""
                if probe.nickname:
                    rnd_prefix = "[yellow]🎲 [/]" if probe.is_randomized else ""
                    mac_markup = f"{prefix}{rnd_prefix}[bold magenta]{escape(probe.nickname)}[/]"
                elif probe.is_randomized:
                    mac_markup = f"{prefix}[yellow]🎲 {escape(probe.mac)}[/]"
                else:
                    mac_markup = f"{prefix}{escape(probe.mac)}"
                table.add_row(
                    Text.from_markup(mac_markup, emoji=False),
                    Text(_ssids_preview(probe), style="cyan" if probe.ssids else "dim"),
                    Text(_short_date(probe.last_seen), justify="right"),
                    key=probe.mac,
                )
            if table.row_count > 0:
                if selected and selected in table.rows:
                    row = table.get_row_index(selected)
                else:
                    row = min(max(0, cursor_row), table.row_count - 1)
                table.move_cursor(row=row, scroll=False)
                self._selected_mac = table.coordinate_to_cell_key(table.cursor_coordinate).row_key.value
            else:
                self._selected_mac = None
        self._render_detail()

    def _render_detail(self) -> None:
        try:
            detail = self.query_one("#vault-probe-detail", Static)
        except NoMatches:
            return
        probe = self._probes_by_mac.get(self._selected_mac) if self._selected_mac else None
        try:
            self.query_one("#vault-probe-focus-btn", Button).disabled = not bool(
                probe and probe.associated_bssid
            )
            self.query_one("#vault-probe-nick-btn", Button).disabled = probe is None
        except NoMatches:
            pass

        if probe is None:
            detail.update("[dim]No saved probe clients match this view.[/]")
            return

        vendor_markup = (
            "[yellow]🎲 Randomized MAC[/]"
            if probe.is_randomized
            else escape(probe.vendor or "Unknown vendor")
        )

        if probe.associated_bssid:
            ap_ssid = probe.associated_ssid or self.app.vault.known_ap_ssid(probe.associated_bssid)
            ap_model = self.app.vault.known_ap_model(probe.associated_bssid)
            model_tail = f" · {escape(ap_model)}" if ap_model else ""
            if ap_ssid:
                assoc = f"[bold green]{escape(ap_ssid)}[/] [dim]({escape(probe.associated_bssid)}{model_tail})[/]"
            else:
                assoc = f"[bold green]{escape(probe.associated_bssid)}[/][dim]{model_tail}[/]"
        else:
            assoc = "[dim]None observed[/]"

        first_full = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(probe.first_seen)) if probe.first_seen else "—"
        last_full = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(probe.last_seen)) if probe.last_seen else "—"
        sig = f"{probe.last_signal} dBm" if probe.last_signal > -100 else "—"
        ch = str(probe.last_channel) if probe.last_channel else "—"

        lines = [f"[bold cyan]MAC:[/] {escape(probe.mac)}"]
        if probe.nickname:
            lines.append(f"[bold cyan]Nickname:[/] [bold magenta]{escape(probe.nickname)}[/]")
        lines.extend([
            f"[bold cyan]Vendor:[/] {vendor_markup}",
            f"[bold cyan]Associated AP:[/] {assoc}",
            f"[bold cyan]First Seen:[/] {first_full}",
            f"[bold cyan]Last Seen:[/] {last_full}",
            f"[bold cyan]Stats:[/] {probe.count} probes ({probe.broadcast_count} wildcard)  •  PWR: {sig}  •  CH: {ch}",
            "",
            f"[bold]Probed SSIDs ({len(probe.ssids)}):[/]",
        ])
        if probe.ssids:
            ordered = sorted(probe.ssids.values(), key=lambda s: (-s.last_seen, s.ssid.lower()))
            for entry in ordered:
                known = self.app.vault.known_ap_by_ssid(entry.ssid)
                ap_tag = (
                    f" [dim]→ {escape(known.bssid)}"
                    + (f" · {escape(known.model or known.vendor)}" if (known.model or known.vendor) else "")
                    + "[/]"
                    if known
                    else ""
                )
                lines.append(
                    f"  • [bold cyan]{escape(entry.ssid)}[/] "
                    f"[dim]({entry.count}x, {_short_date(entry.last_seen)})[/]{ap_tag}"
                )
        else:
            lines.append("  [dim]<wildcard / broadcast only>[/]")
        detail.update(Text.from_markup("\n".join(lines), emoji=False))

    @on(DataTable.RowHighlighted, "#vault-probes-table")
    def _on_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        if event.row_key is not None and event.row_key.value is not None:
            self._selected_mac = event.row_key.value
            self._render_detail()

    @on(ProbeDataTable.RowDoubleClicked)
    def _on_row_double_clicked(self, event: ProbeDataTable.RowDoubleClicked) -> None:
        if event.table_id != "vault-probes-table":
            return
        self._selected_mac = event.row_key
        self._emit_focus_ap()

    @on(Tabs.TabActivated, "#vault-probe-tabs")
    def _on_tab_activated(self, event: Tabs.TabActivated) -> None:
        if event.tab and event.tab.id and event.tab.id != self._current_tab:
            self._current_tab = event.tab.id
            self.reload()

    @on(Input.Changed, "#vault-probe-filter")
    def _on_filter_changed(self, event: Input.Changed) -> None:
        query = event.value.strip()
        if query != self._filter_text:
            self._filter_text = query
            self.reload()

    @on(Input.Submitted, "#vault-probe-filter")
    def _on_filter_submitted(self) -> None:
        self.focus_table()

    def _emit_focus_ap(self) -> None:
        mac = self.selected_mac()
        probe = self._probes_by_mac.get(mac) if mac else None
        if probe is None or not probe.associated_bssid:
            self.app.notify("Selected client has no associated AP", severity="warning")
            return
        self.post_message(FocusProbeApPressed(probe.associated_bssid, probe.mac))

    @on(Button.Pressed, "#vault-probe-focus-btn")
    def _on_focus_pressed(self, event: Button.Pressed) -> None:
        event.stop()
        self._emit_focus_ap()

    @on(Button.Pressed, "#vault-probe-nick-btn")
    def _on_nick_pressed(self, event: Button.Pressed) -> None:
        event.stop()
        mac = self.selected_mac()
        if not mac:
            self.app.notify("Select a probe client first", severity="warning")
            return
        self.post_message(NicknameProbePressed(mac))

    @on(Button.Pressed, "#vault-probe-copy-btn")
    def _on_copy_pressed(self, event: Button.Pressed) -> None:
        event.stop()
        probe = self._probes_by_mac.get(self._selected_mac) if self._selected_mac else None
        if probe is None or not probe.ssids:
            self.app.notify("No probed SSIDs to copy", severity="warning")
            return
        ordered = sorted(probe.ssids.values(), key=lambda s: (-s.last_seen, s.ssid.lower()))
        self.app.copy_to_clipboard("\n".join(entry.ssid for entry in ordered))
        self.app.notify(f"Copied {len(ordered)} SSID(s) for {probe.mac}")

    @on(Button.Pressed, "#vault-probe-export-btn")
    def _on_export_pressed(self, event: Button.Pressed) -> None:
        event.stop()
        probes = self.app.vault.all_probes()
        if not probes:
            self.app.notify("No probes to export", severity="warning")
            return
        try:
            out = export_probes_csv(probes)
        except OSError as exc:
            self.app.notify(f"Export failed: {exc}", severity="error")
            return
        self.app.notify(f"Exported {len(probes)} probe(s) to {out}")

    @on(Button.Pressed, "#vault-probe-delete-btn")
    def _on_delete_pressed(self, event: Button.Pressed) -> None:
        event.stop()
        mac = self.selected_mac()
        if not mac:
            self.app.notify("Select a probe client first", severity="warning")
            return
        self.post_message(DeleteProbePressed(mac))

    @on(Button.Pressed, "#vault-probe-clear-btn")
    def _on_clear_pressed(self, event: Button.Pressed) -> None:
        event.stop()
        if not self._probes_by_mac:
            self.app.notify("No saved probes to clear", severity="warning")
            return
        self.post_message(ClearProbesPressed())
