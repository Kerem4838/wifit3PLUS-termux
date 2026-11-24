"""Clients list: List of related client MAC addresses underneath the AP."""
from __future__ import annotations

from typing import Callable

from textual import events
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.message import Message
from textual.screen import ModalScreen
from textual.widgets import Button, Label, Tooltip

from wifit3.id import Fingerprint


_UNSET = object()


def _widget_id(mac: str) -> str:
    return "cl-" + mac.replace(":", "")


class ClientWidget(Horizontal):
    """A Client of the currently-focused target."""

    class DeauthRequested(Message):
        def __init__(self, mac: str) -> None:
            super().__init__()
            self.mac = mac

    class FingerprintClicked(Message):
        def __init__(self, mac: str, fingerprint: Fingerprint, offset: tuple[int, int]) -> None:
            super().__init__()
            self.mac = mac
            self.fingerprint = fingerprint
            self.offset = offset

    def __init__(self, client, *, tagged: bool = False, nickname: str = "", **kwargs) -> None:
        super().__init__(id=_widget_id(client.mac), classes="client-row", **kwargs)
        self._mac = client.mac
        self._fp = client.fingerprint
        self._power = client.signal
        self._packets = client.packets
        self._tagged = tagged
        self._nickname = nickname.strip()
        if tagged:
            self.add_class("-tagged")

    def compose(self) -> ComposeResult:
        fp_text = self._fp.emoji if self._fp else ("★" if self._tagged else "")
        self._fp_label = Label(fp_text, classes="cl-fp")
        self._mac_label = Label(self._nickname or self._mac, classes="cl-bssid")
        self._pwr_label = Label(str(self._power), classes="cl-pwr")
        self._pkts_label = Label(str(self._packets), classes="cl-pkts")
        if self._nickname:
            self._mac_label.tooltip = f"{self._nickname} ({self._mac})"
        if self._fp is not None:
            self._fp_label.tooltip = f"{self._fp.label} (Tagged)" if self._tagged else self._fp.label
            self._fp_label.add_class("fp-known")
            self._mac_label.add_class("fp-known")
        elif self._tagged:
            self._fp_label.tooltip = "Tagged from Probe Scanner"
        self._deauth = Button("✕", classes="cl-deauth", tooltip="Deauthenticate Client")
        yield self._fp_label
        yield self._mac_label
        yield self._pwr_label
        yield self._pkts_label
        yield self._deauth

    def set_nickname(self, nickname: str) -> None:
        """Update the displayed nickname (falling back to MAC when empty)."""
        clean = nickname.strip()
        if clean == self._nickname:
            return
        self._nickname = clean
        mac_label = getattr(self, "_mac_label", None)
        if mac_label is None:
            return
        mac_label.update(clean or self._mac, layout=False)
        mac_label.tooltip = f"{clean} ({self._mac})" if clean else None

    def set_tagged(self, tagged: bool) -> None:
        """Toggle the tagged highlight state on this client row."""
        if tagged == self._tagged:
            return
        self._tagged = tagged
        self.set_class(tagged, "-tagged")
        fp_label = getattr(self, "_fp_label", None)
        if fp_label is None:
            return
        if self._fp is None:
            fp_label.update("★" if tagged else "", layout=False)
            fp_label.tooltip = "Tagged from Probe Scanner" if tagged else None
        else:
            fp_label.tooltip = f"{self._fp.label} (Tagged)" if tagged else self._fp.label

    def update_stats(self, power: int, packets: int) -> None:
        """Repaint power/packets in place, only on a real change (a blind ``Label.update`` at 10 Hz
        wipes text selection and burns CPU)."""
        if power != self._power:
            self._power = power
            self._pwr_label.update(str(power), layout=False)      # fixed-width column
        if packets != self._packets:
            self._packets = packets
            self._pkts_label.update(str(packets), layout=False)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        event.stop()
        self.post_message(self.DeauthRequested(self._mac))

    def on_click(self, event: events.Click) -> None:
        if self._fp is not None and event.widget in (self._fp_label, self._mac_label):
            self.post_message(
                self.FingerprintClicked(self._mac, self._fp, (event.screen_x, event.screen_y)))

    # Keyboard a11y: the mac label is not focusable, so focusing the row's ✕ surfaces the
    # fingerprint as a tooltip at the button (Textual otherwise shows tooltips on hover only).
    def on_descendant_focus(self, _event: events.DescendantFocus) -> None:
        if self._fp is None:
            return
        try:
            tooltip = self.screen.query_one(Tooltip)
        except Exception:
            return
        tooltip.update(self._fp.label)
        tooltip.absolute_offset = self._deauth.region.offset
        tooltip.display = True

    def on_descendant_blur(self, _event: events.DescendantBlur) -> None:
        try:
            self.screen.query_one(Tooltip).display = False
        except Exception:
            pass


class FingerprintModal(ModalScreen[None]):
    """A small popup showing a Client's vendor information."""

    BINDINGS = [Binding("escape", "dismiss", "Close", show=False)]

    DEFAULT_CSS = """
    FingerprintModal { background: $background 0%; }
    FingerprintModal > #fp-box {
        width: auto; height: auto; border: round $primary; background: $panel; padding: 0 1;
    }
    """

    def __init__(self, mac: str, fp: Fingerprint, *, offset: tuple[int, int]) -> None:
        super().__init__()
        self._mac = mac
        self._fp = fp
        self._offset = offset

    def compose(self) -> ComposeResult:
        box = Vertical(
            Label(f"{self._fp.emoji} {self._fp.label}"),
            Label(f"[dim]OUI: {self._mac[:8]}[/dim]"),
            id="fp-box",
        )
        box.styles.offset = self._offset
        yield box

    def on_mount(self) -> None:
        # The box's real size isn't known until after layout, so a click near the screen edge
        # would place it partly off-screen; clamp once the size is known.
        self.call_after_refresh(self._keep_on_screen)

    def _keep_on_screen(self) -> None:
        box = self.query_one("#fp-box")
        max_x = max(0, self.size.width - box.outer_size.width)
        max_y = max(0, self.size.height - box.outer_size.height)
        x, y = self._offset
        box.styles.offset = (max(0, min(x, max_x)), max(0, min(y, max_y)))

    def on_click(self, event: events.Click) -> None:
        if event.widget is self:            # the transparent backdrop, not the box or its labels
            self.dismiss()


class ClientsList(Vertical):
    def __init__(
        self,
        clients,
        *,
        tagged_mac: str | None = None,
        nickname_lookup: Callable[[str], str] | None = None,
        **kwargs,
    ) -> None:
        super().__init__(**kwargs)
        self._clients = clients
        self._tagged_mac = tagged_mac.lower() if tagged_mac else None
        self._nickname_lookup = nickname_lookup
        self._rows: dict[str, ClientWidget] = {}
        self._deauth_enabled: bool | None = None
        self._last_snapshot: tuple | None = None

    def _nick_for(self, mac: str) -> str:
        return self._nickname_lookup(mac) if self._nickname_lookup is not None else ""

    def compose(self) -> ComposeResult:
        # Broadcast button pinned at the top; only the row list scrolls below it.
        yield Button("Deauth all", id="deauth-all", classes="bcast-btn",
                     tooltip="Deauthenticate all clients (Broadcast)")
        rows = []
        for c in self._clients:
            widget = ClientWidget(
                c,
                tagged=(c.mac.lower() == self._tagged_mac),
                nickname=self._nick_for(c.mac),
            )
            self._rows[c.mac] = widget
            rows.append(widget)
        yield VerticalScroll(*rows, id="client-rows")

    def on_mount(self) -> None:
        self._update_title()

    def _rows_host(self) -> VerticalScroll:
        """The scroll container the client rows live in (new rows mount here)."""
        return self.query_one("#client-rows", VerticalScroll)

    def sync(
        self,
        clients,
        tagged_mac: str | None | object = _UNSET,
        *,
        nickname_lookup: Callable[[str], str] | None | object = _UNSET,
    ) -> None:
        """Reconcile client row information to match ``clients``."""
        if tagged_mac is not _UNSET:
            self._tagged_mac = tagged_mac.lower() if isinstance(tagged_mac, str) and tagged_mac else None
        if nickname_lookup is not _UNSET:
            self._nickname_lookup = nickname_lookup
        clients = list(clients)
        nicks = {c.mac: self._nick_for(c.mac) for c in clients}
        snapshot = (
            self._tagged_mac,
            tuple((c.mac, c.signal, c.packets, c.fingerprint, nicks[c.mac]) for c in clients),
        )
        if snapshot == self._last_snapshot:
            return
        self._last_snapshot = snapshot
        current = {c.mac for c in clients}
        for mac in list(self._rows):
            if mac not in current:
                self._remove_row(mac)
        for c in clients:
            is_tagged = c.mac.lower() == self._tagged_mac
            nick = nicks[c.mac]
            row = self._rows.get(c.mac)
            if row is None:
                if self.query(f"#{_widget_id(c.mac)}"):
                    continue
                widget = ClientWidget(c, tagged=is_tagged, nickname=nick)
                self._rows[c.mac] = widget
                self._rows_host().mount(widget)
                if is_tagged:
                    widget.scroll_visible(animate=False)
            else:
                was_tagged = row._tagged
                row.update_stats(c.signal, c.packets)
                row.set_nickname(nick)
                row.set_tagged(is_tagged)
                if is_tagged and not was_tagged and row.is_attached:
                    row.scroll_visible(animate=False)
        self._update_title()

    def _remove_row(self, mac: str) -> None:
        row = self._rows.pop(mac, None)
        if row is not None:
            row.remove()

    def set_deauth_enabled(self, enabled: bool) -> None:
        """Enable/disable every deauth control (✕)."""
        if enabled == self._deauth_enabled:
            return
        self._deauth_enabled = enabled
        disabled = not enabled
        for btn in self.query(Button):
            btn.disabled = disabled

    def _update_title(self) -> None:
        title = f"CLIENTS ({len(self._rows)})"
        if self.border_title != title:
            self.border_title = title
