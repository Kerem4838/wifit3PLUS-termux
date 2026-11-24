"""Live passive 802.11 Probe Request scanner with sorting, hover popup, and Tier List."""
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Dict, List, Optional

from rich.markup import escape
from rich.text import Text
from textual import events, on
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.css.query import NoMatches
from textual.message import Message
from textual.screen import Screen
from textual.timer import Timer
from textual.widgets import Button, DataTable, Footer, Input, Label, Static

from wifit3.id.common import vendor_for_mac
from wifit3.models import AccessPoint, ProbeRecord
from wifit3.persist.config import Config
from wifit3.persist.probe_store import export_probes_csv
from wifit3.ui.screens.scanner import _ChannelBar, _ScannerHeader
from wifit3.ui.screens.vault_table import matches_filter
from wifit3.ui.vault.global_tracker import GlobalJobTracker
from wifit3.ui.vault.modals.nickname import NicknameModal

if TYPE_CHECKING:
    from wifit3.ui.app import WifiteApp

_CLIENT_SORT_COLS = ("last_seen", "signal", "count", "ssids", "mac", "vendor", "associated", "channel")
_CLIENT_NUMERIC_COLS = frozenset({"last_seen", "signal", "count", "ssids", "channel"})
_CLIENT_COL_LABELS = {
    "mac": "MAC",
    "vendor": "VENDOR",
    "ssids": "PROBES",
    "associated": "ASSOCIATED AP",
    "signal": "PWR",
    "channel": "CH",
    "count": "PKTS",
    "last_seen": "LAST SEEN",
}

_SSID_SORT_COLS = ("last_seen", "probes", "clients", "ssid", "live_ap")
_SSID_NUMERIC_COLS = frozenset({"last_seen", "probes", "clients"})
_SSID_COL_LABELS = {
    "ssid": "SSID",
    "clients": "CLIENTS",
    "probes": "PROBES",
    "live_ap": "FOUND AP / MODEL",
    "last_seen": "LAST SEEN",
    "sample_macs": "DEVICES",
}

_MAC_FILTERS = ("all", "real", "random")
_MAC_FILTER_LABELS = {"all": "MAC: All", "real": "MAC: Real", "random": "MAC: Random"}
_SSID_CELL_MAX = 40
_COL_KEYS = ("mac", "vendor", "ssids", "associated", "signal", "channel", "count", "last_seen")
_SSID_COL_KEYS = ("ssid", "clients", "probes", "live_ap", "last_seen", "sample_macs")
_TIER_COL_KEYS = ("rank", "ssid", "real", "random", "total", "found")


@dataclass(frozen=True, slots=True)
class _SsidTierEntry:
    ssid: str
    clients: List[ProbeRecord]
    real_clients: int
    real_reqs: int
    random_clients: int
    random_reqs: int
    total_reqs: int
    last_seen: float


def _format_age(epoch: float, now: float) -> str:
    if epoch <= 0:
        return "—"
    delta = max(0, int(now - epoch))
    if delta < 60:
        return f"{delta}s"
    if delta < 3600:
        return f"{delta // 60}m {delta % 60:02d}s"
    return f"{delta // 3600}h {(delta % 3600) // 60:02d}m"


def _vendor_text(record: ProbeRecord) -> str:
    if record.is_randomized:
        return "Randomized MAC"
    fp = record.fingerprint
    if fp is None:
        return ""
    emoji = fp.emoji.strip()
    return f"{emoji} {fp.label}".strip()


def _signal_text(rssi: int) -> Text:
    if rssi <= -100:
        return Text("—", style="dim", justify="right")
    color = "green" if rssi > -60 else ("yellow" if rssi > -75 else "red")
    return Text(f"{rssi} dBm", style=color, justify="right")


def _format_ssids_cell(record: ProbeRecord) -> Text:
    if not record.ssids:
        return Text("—", style="dim")
    ordered = sorted(record.ssids.values(), key=lambda s: (-s.last_seen, s.ssid.lower()))
    names = [entry.ssid for entry in ordered]
    joined = ", ".join(names)
    if len(joined) <= _SSID_CELL_MAX:
        return Text(joined, style="bold cyan")
    shown: List[str] = []
    used = 0
    for idx, name in enumerate(names):
        sep = 2 if shown else 0
        rem = len(names) - idx - 1
        reserve = len(f" (+{rem})") if rem > 0 else 0
        if used + sep + len(name) + reserve <= _SSID_CELL_MAX or not shown:
            shown.append(name)
            used += sep + len(name)
        else:
            break
    extra = len(names) - len(shown)
    text = ", ".join(shown)
    if len(text) > _SSID_CELL_MAX - (len(f" (+{extra})") if extra else 0):
        max_len = max(4, _SSID_CELL_MAX - (len(f" (+{extra})") if extra else 0) - 1)
        text = text[:max_len] + "…"
    out = Text(text, style="bold cyan")
    if extra > 0:
        out.append(f" (+{extra})", style="dim")
    return out


def _add_probe_columns(table: DataTable) -> None:
    table.add_column("MAC", key="mac", width=18)
    table.add_column("VENDOR", key="vendor", width=21)
    table.add_column("PROBES", key="ssids", width=_SSID_CELL_MAX + 2)
    table.add_column("ASSOCIATED AP", key="associated", width=30)
    table.add_column("PWR", key="signal", width=8)
    table.add_column("CH", key="channel", width=4)
    table.add_column("PKTS", key="count", width=6)
    table.add_column("LAST SEEN", key="last_seen", width=10)


def _add_ssid_columns(table: DataTable) -> None:
    table.add_column("SSID", key="ssid", width=30)
    table.add_column("CLIENTS", key="clients", width=8)
    table.add_column("PROBES", key="probes", width=8)
    table.add_column("FOUND AP / MODEL", key="live_ap", width=36)
    table.add_column("LAST SEEN", key="last_seen", width=10)
    table.add_column("DEVICES", key="sample_macs", width=28)


def _add_tier_columns(table: DataTable) -> None:
    table.add_column("#", key="rank", width=4)
    table.add_column("SSID", key="ssid", width=24)
    table.add_column("REAL", key="real", width=13)
    table.add_column("RANDOM", key="random", width=13)
    table.add_column("TOTAL", key="total", width=6)
    table.add_column("FOUND AP / MODEL", key="found", width=34)


class ProbeDataTable(DataTable):
    """DataTable subclass that posts RowDoubleClicked when a data row is double-clicked."""

    class RowDoubleClicked(Message):
        """Posted when a user double-clicks a table row."""

        def __init__(self, table_id: str, row_key: str) -> None:
            super().__init__()
            self.table_id = table_id
            self.row_key = row_key

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._last_click_key: Optional[str] = None
        self._last_click_time: float = 0.0

    async def _on_click(self, event: events.Click) -> None:
        row_idx = event.style.meta.get("row") if event.style else None
        row_key = (
            self.ordered_rows[row_idx].key.value
            if isinstance(row_idx, int) and 0 <= row_idx < len(self.ordered_rows)
            else None
        )
        await super()._on_click(event)
        if row_key is None:
            self._last_click_key = None
            self._last_click_time = 0.0
            return
        now = time.monotonic()
        is_double = event.chain >= 2 or (
            self._last_click_key == row_key and (now - self._last_click_time) <= 0.6
        )
        if is_double:
            self._last_click_key = None
            self._last_click_time = 0.0
            self.post_message(self.RowDoubleClicked(self.id or "", row_key))
            return
        self._last_click_key = row_key
        self._last_click_time = now


class ProbeScannerView(Screen):
    """Live Probe Request monitor with sorting, hover popup, and Most-Probed Tier List."""

    app: "WifiteApp"

    CSS = """
    ProbeScannerView {
        layers: base overlay;
    }
    ProbeScannerView #probe-filter-bar {
        height: auto;
        padding: 0 1;
        border: round $primary;
        border-title-color: $primary;
        border-title-style: bold;
        align-vertical: middle;
    }
    ProbeScannerView #probe-filter-label {
        margin-right: 1;
        color: $text-muted;
    }
    ProbeScannerView #probe-filter {
        width: 1fr;
        min-width: 14;
        margin-right: 1;
    }
    ProbeScannerView #probe-filter-bar Button {
        min-width: 0;
        width: auto;
        margin-right: 1;
    }
    ProbeScannerView #probe-summary {
        width: auto;
        color: $text-muted;
    }
    ProbeScannerView #probe-tables {
        width: 100%;
        height: 2fr;
    }
    ProbeScannerView .probe-pane {
        width: 100%;
        height: 1fr;
        border: round $primary;
        border-title-color: $primary;
        border-title-style: bold;
    }
    ProbeScannerView #probe-random-pane {
        display: none;
        border: round $warning;
        border-title-color: $warning;
    }
    ProbeScannerView #probe-ssid-pane {
        display: none;
        border: round $secondary;
        border-title-color: $secondary;
    }
    ProbeScannerView .probe-pane DataTable {
        width: 100%;
        height: 1fr;
    }
    ProbeScannerView #probe-bottom {
        width: 100%;
        height: 1fr;
        min-height: 9;
        max-height: 14;
    }
    ProbeScannerView #probe-tier-pane {
        width: 3fr;
        height: 100%;
        border: round $primary;
        border-title-color: $primary;
        border-title-style: bold;
    }
    ProbeScannerView #probe-tier-table {
        width: 100%;
        height: 1fr;
    }
    ProbeScannerView #probe-detail-pane {
        width: 2fr;
        height: 100%;
        border: round $primary;
        border-title-color: $primary;
        border-title-style: bold;
        padding: 0 1;
    }
    ProbeScannerView #probe-detail-scroll {
        height: 1fr;
    }
    ProbeScannerView #probe-detail {
        width: 100%;
    }
    ProbeScannerView #probe-hover-popup {
        layer: overlay;
        display: none;
        position: absolute;
        width: auto;
        max-width: 60;
        max-height: 18;
        border: round $accent;
        background: $panel;
        padding: 0 1;
    }
    """

    BINDINGS = [
        Binding("escape", "back", "Back", show=True),
        Binding("b", "back", "Back", show=False),
        Binding("f", "focus_filter", "Filter", show=True),
        Binding("/", "focus_filter", "Filter", show=False),
        Binding("m", "cycle_mac_filter", "MAC Filter", show=True),
        Binding("n", "toggle_named_only", "Named Only", show=True),
        Binding("g", "toggle_split", "Split Random", show=True),
        Binding("t", "toggle_view_mode", "View Mode", show=True),
        Binding("e", "export_csv", "Export CSV", show=True),
        Binding("s", "cycle_sort", "Sort Col", show=True),
        Binding("o", "toggle_sort_dir", "Sort Dir", show=True),
        Binding("enter", "jump_to_ap", "Focus AP", show=True, priority=True),
        Binding("r", "rename_client", "Rename", show=True),
        Binding("c", "copy_ssids", "Copy SSIDs", show=True),
        Binding("v", "open_vault_probes", "Vault", show=True),
        Binding("q", "app.quit", "Quit", show=True),
    ]

    def __init__(self) -> None:
        super().__init__()
        self._refresh_timer: Optional[Timer] = None
        self._filter_text: str = ""
        self._mac_filter: str = "all"
        self._named_only: bool = False
        self._split_random: bool = False
        self._view_mode: str = "clients"
        self._sort_column: str = "last_seen"
        self._sort_reverse: bool = True
        self._ssid_sort_column: str = "last_seen"
        self._ssid_sort_reverse: bool = True
        self._selected_mac: Optional[str] = None
        self._selected_ssid: Optional[str] = None
        self._detail_mode: str = "client"
        self._active_table_id: str = "probe-table"
        self._hover_key: Optional[tuple[str, str]] = None
        self._hover_height: int = 10
        self._row_caches: Dict[str, dict[str, tuple]] = {
            "probe-table": {},
            "probe-random-table": {},
            "probe-ssid-table": {},
            "probe-tier-table": {},
        }

    def compose(self) -> ComposeResult:
        yield _ScannerHeader()
        yield _ChannelBar()
        with Vertical():
            filter_bar = Horizontal(id="probe-filter-bar")
            filter_bar.border_title = "PROBE SCANNER"
            with filter_bar:
                yield Label("Filter:", id="probe-filter-label")
                yield Input(placeholder="MAC, vendor, SSID, or AP...", id="probe-filter", compact=True)
                yield Button("MAC: All", id="probe-mac-filter-btn", compact=True,
                             tooltip="Cycle MAC filter: All / Real / Random (m)")
                yield Button("Probes: All", id="probe-named-btn", compact=True,
                             tooltip="Show all clients or only clients with named SSID probes (n)")
                yield Button("Split: Off", id="probe-split-btn", compact=True,
                             tooltip="Split Real & Randomized MACs into separate tables (g)")
                yield Button("View: Clients", id="probe-view-btn", compact=True,
                             tooltip="Toggle Clients / SSIDs view (t)")
                yield Button("Export", id="probe-export-btn", compact=True,
                             tooltip="Export probes to CSV (e)")
                yield Label("", id="probe-summary")
            with Vertical(id="probe-tables"):
                primary = Vertical(id="probe-primary-pane", classes="probe-pane")
                primary.border_title = "PROBED CLIENTS (0)"
                with primary:
                    yield ProbeDataTable(id="probe-table", cursor_type="row")
                random_pane = Vertical(id="probe-random-pane", classes="probe-pane")
                random_pane.border_title = "RANDOMIZED MAC CLIENTS (0)"
                with random_pane:
                    yield ProbeDataTable(id="probe-random-table", cursor_type="row")
                ssid_pane = Vertical(id="probe-ssid-pane", classes="probe-pane")
                ssid_pane.border_title = "PROBED SSIDs (0)"
                with ssid_pane:
                    yield ProbeDataTable(id="probe-ssid-table", cursor_type="row")
            with Horizontal(id="probe-bottom"):
                tier_pane = Vertical(id="probe-tier-pane")
                tier_pane.border_title = "MOST PROBED SSIDs — TIER LIST"
                with tier_pane:
                    yield ProbeDataTable(id="probe-tier-table", cursor_type="row")
                detail_pane = Vertical(id="probe-detail-pane")
                detail_pane.border_title = "DETAILS"
                with detail_pane:
                    with VerticalScroll(id="probe-detail-scroll"):
                        yield Static("", id="probe-detail")
        yield Static("", id="probe-hover-popup")
        yield GlobalJobTracker()
        yield Footer()

    def on_mount(self) -> None:
        for table_id in ("probe-table", "probe-random-table"):
            _add_probe_columns(self.query_one(f"#{table_id}", DataTable))
        _add_ssid_columns(self.query_one("#probe-ssid-table", DataTable))
        _add_tier_columns(self.query_one("#probe-tier-table", DataTable))
        self.query_one("#probe-table", DataTable).focus()
        self._apply_sort_headers()
        self._refresh_timer = self.set_interval(0.5, self.refresh_table)
        self.refresh_table()

    def on_screen_resume(self) -> None:
        self._hide_hover_popup()
        self.refresh_table()
        try:
            focus_id = "probe-ssid-table" if self._view_mode == "ssids" else self._active_table_id
            self.query_one(f"#{focus_id}", DataTable).focus()
        except NoMatches:
            pass

    def _resolve_ap_info(self, bssid: Optional[str]) -> tuple[Optional[str], Optional[str], str]:
        if not bssid:
            return None, None, ""
        array = self.app.array
        ap = array.access_points.get(bssid) if array else None
        ssid = None
        if ap is not None and ap.ssid and ap.ssid != "<hidden>":
            ssid = ap.ssid
        else:
            ssid = (
                self.app.vault.ssid(bssid)
                or Config.decloaked_ssid(bssid)
                or self.app.vault.known_ap_ssid(bssid)
                or None
            )
        model = (ap.identity.summary if ap is not None else "") or self.app.vault.known_ap_model(bssid) or vendor_for_mac(bssid) or ""
        return bssid, ssid, model

    def _find_ap_for_ssid(self, ssid: str) -> tuple[Optional[AccessPoint], Optional[str], str]:
        array = self.app.array
        if array:
            live_ap = next((ap for ap in array.access_points.values() if ap.ssid == ssid), None)
            if live_ap is not None:
                model = live_ap.identity.summary or self.app.vault.known_ap_model(live_ap.bssid) or vendor_for_mac(live_ap.bssid) or ""
                return live_ap, live_ap.bssid, model
        known = self.app.vault.known_ap_by_ssid(ssid)
        if known is not None:
            return None, known.bssid, known.model or known.vendor or vendor_for_mac(known.bssid) or ""
        return None, None, ""

    def _matches_text(self, record: ProbeRecord) -> bool:
        if not self._filter_text:
            return True
        vendor = _vendor_text(record)
        nick = self.app.vault.probe_nickname(record.mac)
        assoc_bssid, assoc_ssid, assoc_model = self._resolve_ap_info(record.associated_bssid)
        fields = [
            record.mac,
            nick,
            vendor,
            assoc_bssid or "",
            assoc_ssid or "",
            assoc_model,
            *record.ssids.keys(),
        ]
        return matches_filter(self._filter_text, fields)

    def _matches_filters(self, record: ProbeRecord) -> bool:
        if self._mac_filter == "real" and record.is_randomized:
            return False
        if self._mac_filter == "random" and not record.is_randomized:
            return False
        if self._named_only and not record.ssids:
            return False
        return self._matches_text(record)

    def _client_sort_key(self, record: ProbeRecord):
        col = self._sort_column
        if col == "signal":
            return (record.signal, record.last_seen, record.mac)
        if col == "count":
            return (record.count, record.last_seen, record.mac)
        if col == "mac":
            nick = self.app.vault.probe_nickname(record.mac).lower()
            return (nick or record.mac, record.mac)
        if col == "vendor":
            return (_vendor_text(record).lower(), record.mac)
        if col == "ssids":
            return (len(record.ssids), record.last_seen, record.mac)
        if col == "associated":
            _, ssid, _ = self._resolve_ap_info(record.associated_bssid)
            return ((ssid or record.associated_bssid or "zzzz").lower(), record.mac)
        if col == "channel":
            return (record.last_channel, record.last_seen, record.mac)
        return (record.last_seen, record.count, record.mac)

    def _ssid_sort_key(self, entry: _SsidTierEntry):
        col = self._ssid_sort_column
        if col == "ssid":
            return entry.ssid.lower()
        if col == "clients":
            return (len(entry.clients), entry.total_reqs, entry.last_seen)
        if col == "probes":
            return (entry.total_reqs, len(entry.clients), entry.last_seen)
        if col == "live_ap":
            live_ap, saved_bssid, _ = self._find_ap_for_ssid(entry.ssid)
            rank = 2 if live_ap is not None else (1 if saved_bssid else 0)
            return (rank, entry.total_reqs, entry.ssid.lower())
        return (entry.last_seen, entry.total_reqs, entry.ssid.lower())

    def _apply_sort_headers(self) -> None:
        arrow = "▼" if self._sort_reverse else "▲"
        for table_id in ("probe-table", "probe-random-table"):
            try:
                table = self.query_one(f"#{table_id}", DataTable)
            except NoMatches:
                continue
            for key, base in _CLIENT_COL_LABELS.items():
                col = table.columns.get(key)
                if col is not None:
                    col.label = Text(f"{base} {arrow}" if key == self._sort_column else base)
            table.refresh()

        ssid_arrow = "▼" if self._ssid_sort_reverse else "▲"
        try:
            ssid_table = self.query_one("#probe-ssid-table", DataTable)
            for key, base in _SSID_COL_LABELS.items():
                col = ssid_table.columns.get(key)
                if col is not None:
                    col.label = Text(f"{base} {ssid_arrow}" if key == self._ssid_sort_column else base)
            ssid_table.refresh()
        except NoMatches:
            pass

    def _build_tiers(self, records: List[ProbeRecord], *, apply_filter: bool = True) -> List[_SsidTierEntry]:
        grouped: Dict[str, List[ProbeRecord]] = {}
        for rec in records:
            for ssid in rec.ssids:
                if apply_filter and self._filter_text and not matches_filter(
                    self._filter_text, [ssid, rec.mac, _vendor_text(rec)]
                ):
                    continue
                grouped.setdefault(ssid, []).append(rec)

        tiers: List[_SsidTierEntry] = []
        for ssid, clients in grouped.items():
            real_c = sum(1 for c in clients if not c.is_randomized)
            real_r = sum(c.ssids[ssid].count for c in clients if not c.is_randomized)
            rnd_c = len(clients) - real_c
            rnd_r = sum(c.ssids[ssid].count for c in clients if c.is_randomized)
            last_seen = max(c.ssids[ssid].last_seen for c in clients)
            tiers.append(_SsidTierEntry(
                ssid=ssid,
                clients=clients,
                real_clients=real_c,
                real_reqs=real_r,
                random_clients=rnd_c,
                random_reqs=rnd_r,
                total_reqs=real_r + rnd_r,
                last_seen=last_seen,
            ))
        tiers.sort(key=lambda e: (-e.total_reqs, -len(e.clients), -e.last_seen, e.ssid.lower()))
        return tiers

    def refresh_table(self) -> None:
        """Refresh the live Probe tables, Most-Probed Tier List, and details."""
        try:
            primary_pane = self.query_one("#probe-primary-pane", Vertical)
            random_pane = self.query_one("#probe-random-pane", Vertical)
            ssid_pane = self.query_one("#probe-ssid-pane", Vertical)
            primary_table = self.query_one("#probe-table", DataTable)
            random_table = self.query_one("#probe-random-table", DataTable)
            ssid_table = self.query_one("#probe-ssid-table", DataTable)
            tier_table = self.query_one("#probe-tier-table", DataTable)
            summary_label = self.query_one("#probe-summary", Label)
        except NoMatches:
            return

        array = self.app.array
        all_records = list(array.probes.values()) if array else []
        now = time.time()

        real_total = sum(1 for rec in all_records if not rec.is_randomized)
        random_total = len(all_records) - real_total
        unique_ssids = {ssid for rec in all_records for ssid in rec.ssids}
        associated_count = sum(1 for rec in all_records if rec.associated_bssid)
        active_col = self._ssid_sort_column if self._view_mode == "ssids" else self._sort_column
        active_rev = self._ssid_sort_reverse if self._view_mode == "ssids" else self._sort_reverse
        arrow = "▼" if active_rev else "▲"
        sort_label = (
            _SSID_COL_LABELS.get(active_col, active_col)
            if self._view_mode == "ssids"
            else _CLIENT_COL_LABELS.get(active_col, active_col)
        )
        cards_count = len(array.members) if array else 0
        cards_part = f"  Cards: [bold cyan]{cards_count}[/]" if cards_count > 1 else ""
        summary_label.update(
            f"Real: [bold cyan]{real_total}[/]  "
            f"Rnd: [bold yellow]{random_total}[/]  "
            f"SSIDs: [bold cyan]{len(unique_ssids)}[/]  "
            f"Assoc: [bold green]{associated_count}[/]"
            f"{cards_part}  "
            f"Sort: [bold]{sort_label} {arrow}[/]"
        )

        filtered = [r for r in all_records if self._matches_filters(r)]
        filtered.sort(key=self._client_sort_key, reverse=self._sort_reverse)

        if self._view_mode == "ssids":
            primary_pane.display = False
            random_pane.display = False
            ssid_pane.display = True
            ssid_entries = self._build_tiers(all_records)
            ssid_entries.sort(key=self._ssid_sort_key, reverse=self._ssid_sort_reverse)
            ssid_pane.border_title = f"PROBED SSIDs ({len(ssid_entries)})"
            self._sync_ssid_table(ssid_table, ssid_entries, now)
            self._selected_ssid = self._cursor_key(ssid_table)
        else:
            ssid_pane.display = False
            primary_pane.display = True
            if self._split_random:
                real_rows = [r for r in filtered if not r.is_randomized]
                random_rows = [r for r in filtered if r.is_randomized]
                primary_pane.border_title = f"REAL MAC CLIENTS ({len(real_rows)})"
                random_pane.border_title = f"RANDOMIZED MAC CLIENTS ({len(random_rows)})"
                random_pane.display = True
                self._sync_table(primary_table, "probe-table", real_rows, now)
                self._sync_table(random_table, "probe-random-table", random_rows, now)
            else:
                primary_pane.border_title = f"PROBED CLIENTS ({len(filtered)})"
                random_pane.display = False
                self._sync_table(primary_table, "probe-table", filtered, now)
            self._sync_selected_mac()

        tier_entries = self._build_tiers(all_records, apply_filter=False)
        self._sync_tier_table(tier_table, tier_entries)

        if self._view_mode == "ssids" or self._detail_mode == "ssid":
            self._render_ssid_detail(all_records, now)
        else:
            self._render_detail(now)

    def _sync_ssid_table(self, table: DataTable, entries: List[_SsidTierEntry], now: float) -> None:
        ordered = [e.ssid for e in entries]
        existing = [row.key.value for row in table.ordered_rows]
        if ordered == existing:
            for entry in entries:
                sig, cells = self._ssid_row_cells(entry, now)
                if self._row_caches["probe-ssid-table"].get(entry.ssid) == sig:
                    continue
                self._row_caches["probe-ssid-table"][entry.ssid] = sig
                for col_key, value in zip(_SSID_COL_KEYS, cells):
                    table.update_cell(entry.ssid, col_key, value, update_width=False)
            return

        current = self._cursor_key(table)
        cursor_row = table.cursor_row
        scroll_y = table.scroll_y
        new_cache: dict[str, tuple] = {}
        with table.prevent(DataTable.RowHighlighted):
            table.clear()
            for entry in entries:
                sig, cells = self._ssid_row_cells(entry, now)
                new_cache[entry.ssid] = sig
                table.add_row(*cells, key=entry.ssid)
            self._row_caches["probe-ssid-table"] = new_cache
            if table.row_count == 0:
                return
            target = current if (current and current in table.rows) else self._selected_ssid
            row = table.get_row_index(target) if (target and target in table.rows) else min(max(0, cursor_row), table.row_count - 1)
            table.move_cursor(row=row, scroll=False)
        table.scroll_to(y=scroll_y, animate=False, immediate=True)

    def _found_ap_cell(self, ssid: str) -> tuple[tuple, Text]:
        live_ap, bssid, model = self._find_ap_for_ssid(ssid)
        model_tail = f" · {model}" if model else ""
        if live_ap is not None and bssid:
            return (True, bssid, model), Text.from_markup(
                f"[bold green]● Live: {escape(bssid)}[/][dim]{escape(model_tail)}[/]", emoji=False
            )
        if bssid:
            return (False, bssid, model), Text.from_markup(
                f"[cyan]Saved: {escape(bssid)}[/][dim]{escape(model_tail)}[/]", emoji=False
            )
        return (False, None, ""), Text("—", style="dim")

    def _ssid_row_cells(self, entry: _SsidTierEntry, now: float) -> tuple[tuple, tuple]:
        found_sig, found_text = self._found_ap_cell(entry.ssid)
        age = _format_age(entry.last_seen, now)
        macs_sorted = sorted(entry.clients, key=lambda c: (-c.ssids[entry.ssid].last_seen, c.mac))
        sample = ", ".join(self.app.vault.probe_nickname(c.mac) or c.mac for c in macs_sorted[:2])
        if len(macs_sorted) > 2:
            sample += f" (+{len(macs_sorted) - 2})"
        sig = (len(entry.clients), entry.total_reqs, found_sig, age, sample)
        cells = (
            Text(entry.ssid, style="bold cyan"),
            Text(str(len(entry.clients)), justify="right"),
            Text(str(entry.total_reqs), justify="right"),
            found_text,
            Text(age, justify="right"),
            Text(sample, style="dim"),
        )
        return sig, cells

    def _sync_tier_table(self, table: DataTable, entries: List[_SsidTierEntry]) -> None:
        ordered = [e.ssid for e in entries]
        existing = [row.key.value for row in table.ordered_rows]
        if ordered == existing:
            for idx, entry in enumerate(entries, start=1):
                sig, cells = self._tier_row_cells(idx, entry)
                if self._row_caches["probe-tier-table"].get(entry.ssid) == sig:
                    continue
                self._row_caches["probe-tier-table"][entry.ssid] = sig
                for col_key, value in zip(_TIER_COL_KEYS, cells):
                    table.update_cell(entry.ssid, col_key, value, update_width=False)
            return

        current = self._cursor_key(table)
        cursor_row = table.cursor_row
        scroll_y = table.scroll_y
        new_cache: dict[str, tuple] = {}
        with table.prevent(DataTable.RowHighlighted):
            table.clear()
            for idx, entry in enumerate(entries, start=1):
                sig, cells = self._tier_row_cells(idx, entry)
                new_cache[entry.ssid] = sig
                table.add_row(*cells, key=entry.ssid)
            self._row_caches["probe-tier-table"] = new_cache
            if table.row_count == 0:
                return
            row = table.get_row_index(current) if (current and current in table.rows) else min(max(0, cursor_row), table.row_count - 1)
            table.move_cursor(row=row, scroll=False)
        table.scroll_to(y=scroll_y, animate=False, immediate=True)

    def _tier_row_cells(self, rank: int, entry: _SsidTierEntry) -> tuple[tuple, tuple]:
        found_sig, found_text = self._found_ap_cell(entry.ssid)
        real_str = f"{entry.real_clients} ({entry.real_reqs} req)" if entry.real_clients else "0"
        rnd_str = f"{entry.random_clients} ({entry.random_reqs} req)" if entry.random_clients else "0"
        sig = (rank, real_str, rnd_str, entry.total_reqs, found_sig)
        cells = (
            Text(f"#{rank}", style="bold" if rank <= 3 else "dim", justify="right"),
            Text(entry.ssid, style="bold cyan"),
            Text(real_str, style="cyan" if entry.real_clients else "dim", justify="right"),
            Text(rnd_str, style="yellow" if entry.random_clients else "dim", justify="right"),
            Text(str(entry.total_reqs), style="bold", justify="right"),
            found_text,
        )
        return sig, cells

    def _sync_table(
        self, table: DataTable, table_id: str, records: List[ProbeRecord], now: float
    ) -> None:
        ordered_macs = [r.mac for r in records]
        existing_macs = [row.key.value for row in table.ordered_rows]
        if ordered_macs == existing_macs:
            for record in records:
                self._update_row_cells(table, table_id, record, now)
        else:
            self._rebuild_rows(table, table_id, records, now)

    def _row_cells(self, record: ProbeRecord, now: float) -> tuple[tuple, tuple]:
        is_rnd = record.is_randomized
        nick = self.app.vault.probe_nickname(record.mac)
        vendor = _vendor_text(record)
        assoc_bssid, assoc_ssid, assoc_model = self._resolve_ap_info(record.associated_bssid)
        age = _format_age(record.last_seen, now)
        sig_val = record.signal
        ch = str(record.last_channel) if record.last_channel else "—"
        ssid_sig = tuple((s.ssid, s.count, int(s.last_seen)) for s in record.ssids.values())
        signature = (is_rnd, nick, vendor, ssid_sig, assoc_bssid, assoc_ssid, assoc_model, sig_val, ch, record.count, age)

        if nick:
            rnd_prefix = "[yellow]🎲 [/]" if is_rnd else ""
            mac_text = Text.from_markup(f"{rnd_prefix}[bold magenta]{escape(nick)}[/]", emoji=False)
        elif is_rnd:
            mac_text = Text.from_markup(f"[yellow]{escape(record.mac)}[/]", emoji=False)
        else:
            mac_text = Text(record.mac)
        if is_rnd:
            vendor_text = Text.from_markup("[yellow]🎲 Random MAC[/]", emoji=False)
        elif vendor:
            vendor_text = Text(vendor)
        else:
            vendor_text = Text("—", style="dim")

        model_tail = f" · {assoc_model}" if assoc_model else ""
        if assoc_bssid and assoc_ssid:
            assoc_text = Text.from_markup(
                f"[bold green]● {escape(assoc_ssid)}[/] [dim]({escape(assoc_bssid)}{escape(model_tail)})[/]",
                emoji=False,
            )
        elif assoc_bssid:
            assoc_text = Text.from_markup(
                f"[bold green]● {escape(assoc_bssid)}[/][dim]{escape(model_tail)}[/]",
                emoji=False,
            )
        else:
            assoc_text = Text("—", style="dim")

        cells = (
            mac_text,
            vendor_text,
            _format_ssids_cell(record),
            assoc_text,
            _signal_text(sig_val),
            Text(ch, justify="right"),
            Text(str(record.count), justify="right"),
            Text(age, justify="right"),
        )
        return signature, cells

    def _update_row_cells(
        self, table: DataTable, table_id: str, record: ProbeRecord, now: float
    ) -> None:
        cache = self._row_caches[table_id]
        signature, cells = self._row_cells(record, now)
        if cache.get(record.mac) == signature:
            return
        cache[record.mac] = signature
        for col_key, value in zip(_COL_KEYS, cells):
            table.update_cell(record.mac, col_key, value, update_width=False)

    def _rebuild_rows(
        self, table: DataTable, table_id: str, records: List[ProbeRecord], now: float
    ) -> None:
        current = self._cursor_key(table)
        cursor_row = table.cursor_row
        scroll_y = table.scroll_y
        new_cache: dict[str, tuple] = {}
        with table.prevent(DataTable.RowHighlighted):
            table.clear()
            for record in records:
                signature, cells = self._row_cells(record, now)
                new_cache[record.mac] = signature
                table.add_row(*cells, key=record.mac)
            self._row_caches[table_id] = new_cache
            if table.row_count == 0:
                return
            target = current if (current and current in table.rows) else self._selected_mac
            if target and target in table.rows:
                row = table.get_row_index(target)
            else:
                row = min(max(0, cursor_row), table.row_count - 1)
            table.move_cursor(row=row, scroll=False)
        table.scroll_to(y=scroll_y, animate=False, immediate=True)

    @staticmethod
    def _cursor_key(table: DataTable) -> Optional[str]:
        if table.row_count == 0:
            return None
        try:
            return table.coordinate_to_cell_key(table.cursor_coordinate).row_key.value
        except Exception:
            return None

    def _sync_selected_mac(self) -> None:
        array = self.app.array
        if not array:
            self._selected_mac = None
            return
        if not self._split_random and self._active_table_id == "probe-random-table":
            self._active_table_id = "probe-table"
        try:
            active_table = self.query_one(f"#{self._active_table_id}", DataTable)
        except NoMatches:
            self._selected_mac = None
            return
        mac = self._cursor_key(active_table)
        if mac is None and self._split_random:
            other_id = "probe-random-table" if self._active_table_id == "probe-table" else "probe-table"
            try:
                other_table = self.query_one(f"#{other_id}", DataTable)
            except NoMatches:
                other_table = None
            if other_table is not None:
                mac = self._cursor_key(other_table)
                if mac is not None:
                    self._active_table_id = other_id
        self._selected_mac = mac

    def _render_ssid_detail(self, all_records: List[ProbeRecord], now: float) -> None:
        try:
            detail = self.query_one("#probe-detail", Static)
        except NoMatches:
            return
        ssid = self._selected_ssid
        if not ssid:
            detail.update("[dim]No probed SSID selected yet...[/]")
            return
        clients = [rec for rec in all_records if ssid in rec.ssids]
        clients.sort(key=lambda c: (-c.ssids[ssid].last_seen, c.mac))
        live_ap, bssid, model = self._find_ap_for_ssid(ssid)
        model_tail = f" · {escape(model)}" if model else ""
        if live_ap is not None and bssid:
            ap_status = f"[bold green]● Live AP: {escape(bssid)}[/][dim]{model_tail}[/]"
        elif bssid:
            ap_status = f"[cyan]Saved AP: {escape(bssid)}[/][dim]{model_tail}[/]"
        else:
            ap_status = "[dim]AP not seen[/]"

        real_reqs = sum(c.ssids[ssid].count for c in clients if not c.is_randomized)
        rnd_reqs = sum(c.ssids[ssid].count for c in clients if c.is_randomized)
        lines = [
            f"[bold cyan]{escape(ssid)}[/]  |  {ap_status}",
            f"Real: [cyan]{sum(1 for c in clients if not c.is_randomized)} ({real_reqs} req)[/]  •  "
            f"Random: [yellow]{sum(1 for c in clients if c.is_randomized)} ({rnd_reqs} req)[/]",
        ]
        for rec in clients:
            entry = rec.ssids[ssid]
            nick = self.app.vault.probe_nickname(rec.mac)
            client_label = f"[bold magenta]{escape(nick)}[/] [dim]({escape(rec.mac)})[/]" if nick else f"[bold]{escape(rec.mac)}[/]"
            vendor = "🎲 Random MAC" if rec.is_randomized else (_vendor_text(rec) or "Unknown vendor")
            lines.append(
                f"  • {client_label} [dim]({escape(vendor)})[/] "
                f"— {entry.count}x, {_format_age(entry.last_seen, now)}"
            )
        detail.update(Text.from_markup("\n".join(lines), emoji=False))

    def _render_detail(self, now: float) -> None:
        try:
            detail = self.query_one("#probe-detail", Static)
        except NoMatches:
            return
        array = self.app.array
        record = array.probes.get(self._selected_mac) if (array and self._selected_mac) else None
        if record is None:
            detail.update("[dim]Waiting for 802.11 Probe Request frames from nearby clients...[/]")
            return

        if record.is_randomized:
            vendor_markup = "[yellow]🎲 Randomized MAC (Android/iOS/OS privacy)[/]"
        else:
            vendor_markup = f"[bold]{escape(_vendor_text(record) or 'Unknown vendor')}[/]"

        assoc_bssid, assoc_ssid, assoc_model = self._resolve_ap_info(record.associated_bssid)
        model_tail = f" · {escape(assoc_model)}" if assoc_model else ""
        if assoc_bssid and assoc_ssid:
            assoc_str = (
                f"[bold green]Connected to {escape(assoc_ssid)}[/] "
                f"[dim]({escape(assoc_bssid)}{model_tail}) — double-click or Enter to Focus & Tag[/]"
            )
        elif assoc_bssid:
            assoc_str = (
                f"[bold green]Connected to {escape(assoc_bssid)}[/][dim]{model_tail}[/] "
                "[dim]— double-click or Enter to Focus & Tag[/]"
            )
        else:
            assoc_str = "[dim]Not seen associated[/]"

        first_str = time.strftime("%H:%M:%S", time.localtime(record.first_seen)) if record.first_seen else "—"
        last_str = time.strftime("%H:%M:%S", time.localtime(record.last_seen)) if record.last_seen else "—"
        sig_str = f"{record.signal} dBm" if record.signal > -100 else "—"
        nick = self.app.vault.probe_nickname(record.mac)
        client_head = (
            f"[bold magenta]{escape(nick)}[/] [dim]({escape(record.mac)})[/]"
            if nick
            else f"[bold cyan]{escape(record.mac)}[/]"
        )
        lines = [
            f"{client_head}  {vendor_markup}  |  {assoc_str}",
            (
                f"Probes: [bold]{record.count}[/] "
                f"([dim]{record.broadcast_count} wildcard[/])  |  "
                f"PWR: [bold]{sig_str}[/]  CH: [bold]{record.last_channel or '—'}[/]  |  "
                f"First: {first_str}  Last: {last_str} ([cyan]{_format_age(record.last_seen, now)}[/])"
            ),
        ]
        if len(record.signal_by_card) > 1:
            antennas = ", ".join(
                f"{escape(card)} ({rssi} dBm)" for card, rssi in sorted(record.signal_by_card.items())
            )
            lines.append(f"[dim]Antennas:[/] {antennas}")
        if record.ssids:
            ordered = sorted(record.ssids.values(), key=lambda s: (-s.last_seen, s.ssid.lower()))
            lines.append("[bold]Probed SSIDs:[/]")
            for entry in ordered:
                lines.append(
                    f"  • [bold cyan]{escape(entry.ssid)}[/] "
                    f"[dim]({entry.count}x, {_format_age(entry.last_seen, now)} ago)[/]"
                )
        else:
            lines.append("[dim]Only wildcard / broadcast probe requests observed so far.[/]")
        detail.update(Text.from_markup("\n".join(lines), emoji=False))

    def _build_hover_text(self, table_id: str, row_key: str, now: float) -> Optional[str]:
        array = self.app.array
        if not array:
            return None
        if table_id in ("probe-table", "probe-random-table"):
            rec = array.probes.get(row_key)
            if rec is None:
                return None
            nick = self.app.vault.probe_nickname(rec.mac)
            vendor = "🎲 Random MAC" if rec.is_randomized else (_vendor_text(rec) or "Unknown vendor")
            head = (
                f"[bold magenta]{escape(nick)}[/] [dim]({escape(rec.mac)} · {escape(vendor)})[/]"
                if nick
                else f"[bold cyan]{escape(rec.mac)}[/] [dim]({escape(vendor)})[/]"
            )
            lines = [head]
            _, assoc_ssid, assoc_model = self._resolve_ap_info(rec.associated_bssid)
            if rec.associated_bssid:
                ap_name = assoc_ssid or rec.associated_bssid
                tail = f" · {assoc_model}" if assoc_model else ""
                lines.append(f"[green]AP:[/] {escape(ap_name)} [dim]{escape(tail)}[/]")
            if rec.ssids:
                ordered = sorted(rec.ssids.values(), key=lambda s: (-s.last_seen, s.ssid.lower()))
                lines.append(f"[bold]Probed SSIDs ({len(ordered)}):[/]")
                for entry in ordered[:12]:
                    lines.append(
                        f"  • [cyan]{escape(entry.ssid)}[/] [dim]({entry.count}x, {_format_age(entry.last_seen, now)})[/]"
                    )
                if len(ordered) > 12:
                    lines.append(f"  [dim](+{len(ordered) - 12} more)[/]")
            else:
                lines.append("[dim]<wildcard / broadcast only>[/]")
            return "\n".join(lines)

        all_records = list(array.probes.values())
        clients = [rec for rec in all_records if row_key in rec.ssids]
        if not clients:
            return None
        clients.sort(key=lambda c: (-c.ssids[row_key].last_seen, c.mac))
        live_ap, bssid, model = self._find_ap_for_ssid(row_key)
        lines = [f"[bold cyan]{escape(row_key)}[/] [dim]({len(clients)} device(s))[/]"]
        if bssid:
            tag = "Live AP" if live_ap else "Saved AP"
            tail = f" · {model}" if model else ""
            lines.append(f"[green]{tag}:[/] {escape(bssid)}{escape(tail)}")
        for rec in clients[:12]:
            nick = self.app.vault.probe_nickname(rec.mac)
            label = f"[bold magenta]{escape(nick)}[/] [dim]({escape(rec.mac)})[/]" if nick else escape(rec.mac)
            vendor = "🎲 Random" if rec.is_randomized else (_vendor_text(rec) or "Unknown")
            lines.append(f"  • {label} [dim]({escape(vendor)}, {rec.ssids[row_key].count}x)[/]")
        if len(clients) > 12:
            lines.append(f"  [dim](+{len(clients) - 12} more)[/]")
        return "\n".join(lines)

    def _hide_hover_popup(self) -> None:
        self._hover_key = None
        try:
            self.query_one("#probe-hover-popup", Static).display = False
        except NoMatches:
            pass

    @on(events.MouseMove)
    def _on_mouse_move(self, event: events.MouseMove) -> None:
        row_idx = event.style.meta.get("row") if event.style else None
        table = event.widget
        if not isinstance(table, DataTable) or table.id not in (
            "probe-table", "probe-random-table", "probe-ssid-table", "probe-tier-table",
        ) or not isinstance(row_idx, int) or row_idx < 0 or row_idx >= len(table.ordered_rows):
            self._hide_hover_popup()
            return

        row_key = table.ordered_rows[row_idx].key.value
        if row_key is None:
            self._hide_hover_popup()
            return

        key = (table.id, row_key)
        try:
            popup = self.query_one("#probe-hover-popup", Static)
        except NoMatches:
            return
        if key != self._hover_key or not popup.display:
            content = self._build_hover_text(table.id, row_key, time.time())
            if content is None:
                self._hide_hover_popup()
                return
            self._hover_key = key
            self._hover_height = min(18, content.count("\n") + 3)
            popup.update(Text.from_markup(content, emoji=False))
            popup.display = True

        popup_w = popup.outer_size.width or 48
        popup_h = popup.outer_size.height or self._hover_height
        if event.screen_x + 2 + popup_w <= self.size.width:
            x = event.screen_x + 2
        elif event.screen_x - popup_w - 1 >= 0:
            x = event.screen_x - popup_w - 1
        else:
            x = max(0, self.size.width - popup_w)
        if event.screen_y + 1 + popup_h <= self.size.height:
            y = event.screen_y + 1
        else:
            y = max(1, event.screen_y - popup_h)
        popup.styles.offset = (x, y)

    @on(events.Leave)
    def _on_leave(self) -> None:
        self._hide_hover_popup()

    @on(DataTable.HeaderSelected)
    def _on_header_selected(self, event: DataTable.HeaderSelected) -> None:
        col_key = event.column_key.value
        table_id = event.control.id
        if table_id in ("probe-table", "probe-random-table") and col_key in _CLIENT_SORT_COLS:
            if self._sort_column == col_key:
                self._sort_reverse = not self._sort_reverse
            else:
                self._sort_column = col_key
                self._sort_reverse = col_key in _CLIENT_NUMERIC_COLS
            self._apply_sort_headers()
            self.refresh_table()
        elif table_id == "probe-ssid-table" and col_key in _SSID_SORT_COLS:
            if self._ssid_sort_column == col_key:
                self._ssid_sort_reverse = not self._ssid_sort_reverse
            else:
                self._ssid_sort_column = col_key
                self._ssid_sort_reverse = col_key in _SSID_NUMERIC_COLS
            self._apply_sort_headers()
            self.refresh_table()

    @on(DataTable.RowHighlighted)
    def _on_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        if event.row_key is None or event.row_key.value is None:
            return
        tid = event.control.id
        if tid in ("probe-ssid-table", "probe-tier-table"):
            self._selected_ssid = event.row_key.value
            self._detail_mode = "ssid"
            array = self.app.array
            self._render_ssid_detail(list(array.probes.values()) if array else [], time.time())
        elif tid in ("probe-table", "probe-random-table"):
            self._active_table_id = tid
            self._selected_mac = event.row_key.value
            self._detail_mode = "client"
            self._render_detail(time.time())

    @on(ProbeDataTable.RowDoubleClicked)
    def _on_row_double_clicked(self, event: ProbeDataTable.RowDoubleClicked) -> None:
        if event.table_id not in (
            "probe-table", "probe-random-table", "probe-ssid-table", "probe-tier-table",
        ):
            return
        self._hide_hover_popup()
        if event.table_id in ("probe-ssid-table", "probe-tier-table"):
            self._selected_ssid = event.row_key
            self._detail_mode = "ssid"
        else:
            self._active_table_id = event.table_id
            self._selected_mac = event.row_key
            self._detail_mode = "client"
        table = self.query_one(f"#{event.table_id}", DataTable)
        if not table.has_focus:
            table.focus()
        self.action_jump_to_ap()

    @on(Input.Changed, "#probe-filter")
    def _on_filter_changed(self, event: Input.Changed) -> None:
        query = event.value.strip()
        if query != self._filter_text:
            self._filter_text = query
            self.refresh_table()

    @on(Input.Submitted, "#probe-filter")
    def _on_filter_submitted(self) -> None:
        focus_id = "probe-ssid-table" if self._view_mode == "ssids" else self._active_table_id
        self.query_one(f"#{focus_id}", DataTable).focus()

    @on(Button.Pressed, "#probe-mac-filter-btn")
    def _on_mac_filter_pressed(self, event: Button.Pressed) -> None:
        event.stop()
        self.action_cycle_mac_filter()

    @on(Button.Pressed, "#probe-named-btn")
    def _on_named_pressed(self, event: Button.Pressed) -> None:
        event.stop()
        self.action_toggle_named_only()

    @on(Button.Pressed, "#probe-split-btn")
    def _on_split_pressed(self, event: Button.Pressed) -> None:
        event.stop()
        self.action_toggle_split()

    @on(Button.Pressed, "#probe-view-btn")
    def _on_view_pressed(self, event: Button.Pressed) -> None:
        event.stop()
        self.action_toggle_view_mode()

    @on(Button.Pressed, "#probe-export-btn")
    def _on_export_pressed(self, event: Button.Pressed) -> None:
        event.stop()
        self.action_export_csv()

    def action_back(self) -> None:
        filter_input = self.query_one("#probe-filter", Input)
        if filter_input.has_focus:
            focus_id = "probe-ssid-table" if self._view_mode == "ssids" else self._active_table_id
            self.query_one(f"#{focus_id}", DataTable).focus()
            return
        self._hide_hover_popup()
        self.app.pop_screen()

    def action_focus_filter(self) -> None:
        self.query_one("#probe-filter", Input).focus()

    def action_cycle_mac_filter(self) -> None:
        idx = _MAC_FILTERS.index(self._mac_filter)
        self._mac_filter = _MAC_FILTERS[(idx + 1) % len(_MAC_FILTERS)]
        btn = self.query_one("#probe-mac-filter-btn", Button)
        btn.label = _MAC_FILTER_LABELS[self._mac_filter]
        btn.variant = "primary" if self._mac_filter != "all" else "default"
        self.refresh_table()

    def action_toggle_named_only(self) -> None:
        """Toggle filtering out clients that only sent wildcard/broadcast probes."""
        self._named_only = not self._named_only
        btn = self.query_one("#probe-named-btn", Button)
        btn.label = "Probes: Named" if self._named_only else "Probes: All"
        btn.variant = "primary" if self._named_only else "default"
        self.refresh_table()

    def action_toggle_split(self) -> None:
        self._split_random = not self._split_random
        btn = self.query_one("#probe-split-btn", Button)
        btn.label = "Split: On" if self._split_random else "Split: Off"
        btn.variant = "primary" if self._split_random else "default"
        if not self._split_random:
            self._active_table_id = "probe-table"
        self.refresh_table()

    def action_toggle_view_mode(self) -> None:
        """Toggle between Client-centric and SSID-centric probe views."""
        self._view_mode = "ssids" if self._view_mode == "clients" else "clients"
        self._detail_mode = "ssid" if self._view_mode == "ssids" else "client"
        btn = self.query_one("#probe-view-btn", Button)
        btn.label = "View: SSIDs" if self._view_mode == "ssids" else "View: Clients"
        btn.variant = "primary" if self._view_mode == "ssids" else "default"
        self._apply_sort_headers()
        self.refresh_table()

    def action_export_csv(self) -> None:
        """Export live probe records to a CSV file in captures_dir."""
        array = self.app.array
        records = list(array.probes.values()) if array else []
        if not records:
            self.notify("No probes to export", severity="warning")
            return
        try:
            out = export_probes_csv(
                records,
                ssid_lookup=lambda bssid: self._resolve_ap_info(bssid)[1],
                nickname_lookup=self.app.vault.probe_nickname,
            )
        except OSError as exc:
            self.notify(f"Export failed: {exc}", severity="error")
            return
        self.notify(f"Exported {len(records)} probe(s) to {out}")

    def action_cycle_sort(self) -> None:
        if self._view_mode == "ssids":
            idx = _SSID_SORT_COLS.index(self._ssid_sort_column)
            self._ssid_sort_column = _SSID_SORT_COLS[(idx + 1) % len(_SSID_SORT_COLS)]
            self._ssid_sort_reverse = self._ssid_sort_column in _SSID_NUMERIC_COLS
        else:
            idx = _CLIENT_SORT_COLS.index(self._sort_column)
            self._sort_column = _CLIENT_SORT_COLS[(idx + 1) % len(_CLIENT_SORT_COLS)]
            self._sort_reverse = self._sort_column in _CLIENT_NUMERIC_COLS
        self._apply_sort_headers()
        self.refresh_table()

    def action_toggle_sort_dir(self) -> None:
        if self._view_mode == "ssids":
            self._ssid_sort_reverse = not self._ssid_sort_reverse
        else:
            self._sort_reverse = not self._sort_reverse
        self._apply_sort_headers()
        self.refresh_table()

    def action_jump_to_ap(self) -> None:
        """Open FocusViewV2 on the selected client's associated AP or SSID's live AP."""
        if self.query_one("#probe-filter", Input).has_focus:
            focus_id = "probe-ssid-table" if self._view_mode == "ssids" else self._active_table_id
            self.query_one(f"#{focus_id}", DataTable).focus()
            return
        focused = self.app.focused
        use_ssid = (
            self._view_mode == "ssids"
            or (isinstance(focused, DataTable) and focused.id == "probe-tier-table")
            or self._detail_mode == "ssid"
        )
        if use_ssid:
            if not self._selected_ssid:
                self.notify("No SSID selected", severity="warning")
                return
            live_ap, _, _ = self._find_ap_for_ssid(self._selected_ssid)
            if live_ap is None:
                self.notify("Associated AP is not currently in range", severity="warning")
                return
            self.app.focus_ap(live_ap)
            return
        array = self.app.array
        record = array.probes.get(self._selected_mac) if (array and self._selected_mac) else None
        if record is None or not record.associated_bssid:
            self.notify("Selected client is not associated with any AP", severity="warning")
            return
        ap = array.access_points.get(record.associated_bssid)
        if ap is None:
            self.notify("Associated AP is not currently in range", severity="warning")
            return
        self.app.focus_ap(ap, tag_client_mac=record.mac)

    def action_rename_client(self) -> None:
        """Set or clear a persistent nickname for the selected probe client."""
        if self._view_mode == "ssids" or self._detail_mode == "ssid" or not self._selected_mac:
            self.notify("Select a client first", severity="warning")
            return
        mac = self._selected_mac
        current = self.app.vault.probe_nickname(mac)

        def _save(value: Optional[str]) -> None:
            if value is None:
                return
            array = self.app.array
            if array is not None:
                self.app.vault.sync_probes(array.probes, array.access_points)
            self.app.vault.set_probe_nickname(mac, value)
            self.refresh_table()
            self.notify("Client nickname saved" if value else "Client nickname cleared")

        self.app.push_screen(
            NicknameModal(None, current, title="Set Client Nickname", subtitle=mac),
            _save,
        )

    def action_copy_ssids(self) -> None:
        if self._view_mode == "ssids" or self._detail_mode == "ssid":
            if not self._selected_ssid:
                self.notify("No probed SSIDs to copy", severity="warning")
                return
            self.app.copy_to_clipboard(self._selected_ssid)
            self.notify(f"Copied SSID: {self._selected_ssid}")
            return
        array = self.app.array
        record = array.probes.get(self._selected_mac) if (array and self._selected_mac) else None
        if record is None or not record.ssids:
            self.notify("No probed SSIDs to copy", severity="warning")
            return
        ordered = sorted(record.ssids.values(), key=lambda s: (-s.last_seen, s.ssid.lower()))
        payload = "\n".join(entry.ssid for entry in ordered)
        self.app.copy_to_clipboard(payload)
        self.notify(f"Copied {len(ordered)} SSID(s) for {record.mac}")

    def action_open_vault_probes(self) -> None:
        self._hide_hover_popup()
        self.app.action_toggle_vault(section="probes")
