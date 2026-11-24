"""Probe Request observation models for wireless client stations."""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from functools import cached_property
from typing import TYPE_CHECKING, Dict, Optional

from wifit3.dot11.mac import is_randomized_mac

if TYPE_CHECKING:
    from wifit3.id import Fingerprint


@dataclass
class ProbedSsid:
    """Single SSID probed by a client station."""
    ssid: str
    count: int = 1
    first_seen: float = 0.0
    last_seen: float = 0.0


@dataclass
class ProbeRecord:
    """Aggregated Probe Request activity observed for a client MAC."""
    mac: str
    ssids: Dict[str, ProbedSsid] = field(default_factory=dict)
    count: int = 0
    broadcast_count: int = 0
    first_seen: float = 0.0
    last_seen: float = 0.0
    last_channel: int = 0
    associated_bssid: Optional[str] = None
    signal_by_card: Dict[str, int] = field(default_factory=dict)
    signal_history: Dict[str, deque[int]] = field(default_factory=dict, repr=False)

    @property
    def signal(self) -> int:
        """Strongest smoothed RSSI (dBm) across receiving cards; -100 if none yet."""
        return max(self.signal_by_card.values(), default=-100)

    @property
    def is_randomized(self) -> bool:
        """True if this client MAC uses locally-administered randomization."""
        return is_randomized_mac(self.mac)

    @cached_property
    def fingerprint(self) -> Optional[Fingerprint]:
        """OUI vendor fingerprint for this client MAC, cached on first read."""
        if self.is_randomized:
            return None
        from wifit3.id import fingerprint_client
        return fingerprint_client(self.mac)
