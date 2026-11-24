"""Persistent client Probe Request history stored alongside captures."""
from __future__ import annotations

import csv
import json
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Optional, Union

from wifit3.dot11.mac import is_randomized_mac
from wifit3.models import AccessPoint, ProbeRecord
from wifit3.persist.config import Config

logger = logging.getLogger(__name__)

PROBES_FILE_NAME = "probes.json"
_STORE_VERSION = 1


@dataclass
class PersistedProbeSsid:
    """Saved per-SSID probe statistics for a client."""
    ssid: str
    count: int
    first_seen: float
    last_seen: float

    def to_dict(self) -> dict:
        return {
            "ssid": self.ssid,
            "count": self.count,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
        }

    @classmethod
    def from_dict(cls, ssid: str, data: dict) -> Optional["PersistedProbeSsid"]:
        if not isinstance(data, dict):
            return None
        try:
            return cls(
                ssid=str(data.get("ssid", ssid)),
                count=max(0, int(data.get("count", 1))),
                first_seen=float(data.get("first_seen", 0.0)),
                last_seen=float(data.get("last_seen", 0.0)),
            )
        except (TypeError, ValueError):
            return None


@dataclass
class PersistedProbe:
    """Saved Probe Request profile for a single client MAC."""
    mac: str
    vendor: str = ""
    nickname: str = ""
    ssids: Dict[str, PersistedProbeSsid] = field(default_factory=dict)
    count: int = 0
    broadcast_count: int = 0
    first_seen: float = 0.0
    last_seen: float = 0.0
    last_channel: int = 0
    last_signal: int = -100
    associated_bssid: Optional[str] = None
    associated_ssid: Optional[str] = None

    @property
    def is_randomized(self) -> bool:
        """True if this client MAC uses locally-administered randomization."""
        return is_randomized_mac(self.mac)

    def to_dict(self) -> dict:
        return {
            "mac": self.mac,
            "vendor": self.vendor,
            "nickname": self.nickname,
            "count": self.count,
            "broadcast_count": self.broadcast_count,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "last_channel": self.last_channel,
            "last_signal": self.last_signal,
            "associated_bssid": self.associated_bssid,
            "associated_ssid": self.associated_ssid,
            "ssids": {ssid: entry.to_dict() for ssid, entry in self.ssids.items()},
        }

    @classmethod
    def from_dict(cls, mac: str, data: dict) -> Optional["PersistedProbe"]:
        if not isinstance(data, dict):
            return None
        ssids: Dict[str, PersistedProbeSsid] = {}
        raw_ssids = data.get("ssids", {})
        if isinstance(raw_ssids, dict):
            for ssid_key, raw_entry in raw_ssids.items():
                entry = PersistedProbeSsid.from_dict(str(ssid_key), raw_entry)
                if entry is not None and entry.ssid:
                    ssids[entry.ssid] = entry
        try:
            return cls(
                mac=str(data.get("mac", mac)).lower(),
                vendor=str(data.get("vendor") or ""),
                nickname=str(data.get("nickname") or "").strip(),
                ssids=ssids,
                count=max(0, int(data.get("count", 0))),
                broadcast_count=max(0, int(data.get("broadcast_count", 0))),
                first_seen=float(data.get("first_seen", 0.0)),
                last_seen=float(data.get("last_seen", 0.0)),
                last_channel=int(data.get("last_channel", 0)),
                last_signal=int(data.get("last_signal", -100)),
                associated_bssid=data.get("associated_bssid") or None,
                associated_ssid=data.get("associated_ssid") or None,
            )
        except (TypeError, ValueError):
            return None


class ProbeStore:
    """Loads, merges, and atomically writes client probe history to ``probes.json``."""

    def __init__(self) -> None:
        self._records: Dict[str, PersistedProbe] = {}
        self._loaded_path: Optional[Path] = None
        self._synced_live: Dict[str, tuple[float, int, int, Dict[str, int]]] = {}

    @property
    def path(self) -> Path:
        return Path(Config.captures_dir) / PROBES_FILE_NAME

    def load(self) -> Dict[str, PersistedProbe]:
        """Return persisted probes, reading from disk if ``captures_dir`` changed."""
        target = self.path
        if self._loaded_path != target:
            self._load_from(target)
        return self._records

    def reload(self) -> Dict[str, PersistedProbe]:
        """Force re-reading probes from disk."""
        self._loaded_path = None
        return self.load()

    def _load_from(self, target: Path) -> None:
        records: Dict[str, PersistedProbe] = {}
        if target.is_file():
            try:
                raw = json.loads(target.read_text(encoding="utf-8"))
            except (OSError, UnicodeError, json.JSONDecodeError) as exc:
                logger.warning("Failed to read %s: %s", target, exc)
                raw = None
            if isinstance(raw, dict):
                probes_obj = raw.get("probes", raw if "version" not in raw else {})
                if isinstance(probes_obj, dict):
                    for mac_key, item in probes_obj.items():
                        parsed = PersistedProbe.from_dict(str(mac_key), item)
                        if parsed is not None and parsed.mac:
                            records[parsed.mac] = parsed
                else:
                    logger.warning("Ignoring malformed probes section in %s", target)
            elif raw is not None:
                logger.warning("Ignoring malformed JSON root in %s", target)
        self._records = records
        self._loaded_path = target

    def all_probes(self) -> List[PersistedProbe]:
        """All persisted probe clients sorted newest-first."""
        records = self.load()
        return sorted(records.values(), key=lambda p: (p.last_seen, p.count, p.mac), reverse=True)

    def get(self, mac: str) -> Optional[PersistedProbe]:
        return self.load().get(mac.lower())

    def nickname(self, mac: str) -> str:
        """Return the saved nickname for ``mac``, or an empty string."""
        rec = self.get(mac)
        return rec.nickname if rec is not None else ""

    def set_nickname(self, mac: str, nickname: Optional[str]) -> bool:
        """Set or clear a client's saved nickname and persist the change."""
        records = self.load()
        mac_key = mac.lower()
        clean = (nickname or "").strip()
        existing = records.get(mac_key)
        if existing is not None:
            if existing.nickname == clean:
                return False
            existing.nickname = clean
        else:
            if not clean:
                return False
            records[mac_key] = PersistedProbe(mac=mac_key, nickname=clean)
        return self._write()

    def sync(
        self,
        live_probes: Dict[str, ProbeRecord],
        access_points: Dict[str, AccessPoint],
        ssid_lookup: Optional[Callable[[str], Optional[str]]] = None,
    ) -> bool:
        """Merge live session probes into disk history without double-counting."""
        records = self.load()
        dirty = False

        for mac, live in live_probes.items():
            mac_key = mac.lower()
            prev = self._synced_live.get(mac_key)
            if prev is not None and prev[0] == live.first_seen:
                _, prev_total, prev_bcast, prev_ssids = prev
            else:
                prev_total, prev_bcast, prev_ssids = 0, 0, {}

            delta_total = max(0, live.count - prev_total)
            delta_bcast = max(0, live.broadcast_count - prev_bcast)
            ssid_deltas = {
                ssid: max(0, entry.count - prev_ssids.get(ssid, 0))
                for ssid, entry in live.ssids.items()
            }

            if mac_key not in records:
                if prev is not None and delta_total == 0 and not any(ssid_deltas.values()):
                    continue
                records[mac_key] = PersistedProbe(
                    mac=mac_key,
                    first_seen=live.first_seen,
                    last_seen=live.last_seen,
                    last_channel=live.last_channel,
                    last_signal=live.signal,
                )
                dirty = True

            persisted = records[mac_key]
            if delta_total > 0:
                persisted.count += delta_total
                dirty = True
            if delta_bcast > 0:
                persisted.broadcast_count += delta_bcast
                dirty = True

            for ssid, entry in live.ssids.items():
                delta_ssid = ssid_deltas.get(ssid, 0)
                existing = persisted.ssids.get(ssid)
                if existing is None:
                    persisted.ssids[ssid] = PersistedProbeSsid(
                        ssid=ssid,
                        count=delta_ssid or entry.count,
                        first_seen=entry.first_seen,
                        last_seen=entry.last_seen,
                    )
                    dirty = True
                else:
                    if delta_ssid > 0:
                        existing.count += delta_ssid
                        dirty = True
                    if entry.first_seen and (existing.first_seen == 0.0 or entry.first_seen < existing.first_seen):
                        existing.first_seen = entry.first_seen
                        dirty = True
                    if entry.last_seen > existing.last_seen:
                        existing.last_seen = entry.last_seen
                        dirty = True

            if live.first_seen and (persisted.first_seen == 0.0 or live.first_seen < persisted.first_seen):
                persisted.first_seen = live.first_seen
                dirty = True
            if live.last_seen > persisted.last_seen:
                persisted.last_seen = live.last_seen
                persisted.last_channel = live.last_channel
                persisted.last_signal = live.signal
                dirty = True

            if live.is_randomized:
                vendor = "Randomized MAC"
            else:
                fp = live.fingerprint
                vendor = fp.label if fp is not None else ""
            if vendor and persisted.vendor != vendor:
                persisted.vendor = vendor
                dirty = True

            if live.associated_bssid and persisted.associated_bssid != live.associated_bssid:
                persisted.associated_bssid = live.associated_bssid
                dirty = True

            bssid = persisted.associated_bssid
            if bssid:
                resolved_ssid = self._resolve_ap_ssid(bssid, access_points, ssid_lookup)
                if resolved_ssid and persisted.associated_ssid != resolved_ssid:
                    persisted.associated_ssid = resolved_ssid
                    dirty = True

            self._synced_live[mac_key] = (
                live.first_seen,
                live.count,
                live.broadcast_count,
                {ssid: entry.count for ssid, entry in live.ssids.items()},
            )

        if not dirty:
            return False
        return self._write()

    @staticmethod
    def _resolve_ap_ssid(
        bssid: str,
        access_points: Dict[str, AccessPoint],
        ssid_lookup: Optional[Callable[[str], Optional[str]]],
    ) -> Optional[str]:
        ap = access_points.get(bssid)
        if ap is not None and ap.ssid and ap.ssid != "<hidden>":
            return ap.ssid
        if ssid_lookup is not None:
            found = ssid_lookup(bssid)
            if found and found != "<hidden>":
                return found
        return None

    def delete(self, mac: str) -> bool:
        """Remove a single client probe record and persist the change."""
        records = self.load()
        removed = records.pop(mac.lower(), None)
        if removed is None:
            return False
        self._write()
        return True

    def clear(self) -> None:
        """Delete all saved client probe records."""
        records = self.load()
        if not records and not self.path.exists():
            return
        records.clear()
        self._write()

    def _write(self) -> bool:
        target = self.path
        payload = {
            "version": _STORE_VERSION,
            "probes": {mac: rec.to_dict() for mac, rec in sorted(self._records.items())},
        }
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            temporary = target.with_name(target.name + ".tmp")
            temporary.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
                                 encoding="utf-8")
            temporary.replace(target)
        except OSError as exc:
            logger.warning("Failed to write %s: %s", target, exc)
            return False
        self._loaded_path = target
        return True


def export_probes_csv(
    probes: Iterable[Union[ProbeRecord, PersistedProbe]],
    destination: Optional[Path] = None,
    *,
    ssid_lookup: Optional[Callable[[str], Optional[str]]] = None,
    nickname_lookup: Optional[Callable[[str], str]] = None,
) -> Path:
    """Export live or persisted client probe records to a UTF-8 CSV file."""
    target = destination or (Path(Config.captures_dir) / f"probes_export_{int(time.time())}.csv")
    target.parent.mkdir(parents=True, exist_ok=True)
    rows = sorted(probes, key=lambda p: (p.last_seen, p.count, p.mac), reverse=True)
    with target.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow([
            "mac", "nickname", "is_randomized", "vendor", "ssids",
            "associated_bssid", "associated_ssid",
            "signal_dbm", "channel", "count", "broadcast_count",
            "first_seen", "last_seen",
        ])
        for rec in rows:
            if isinstance(rec, PersistedProbe):
                nickname = rec.nickname
                vendor = "Randomized MAC" if rec.is_randomized else rec.vendor
                signal_dbm = rec.last_signal
                assoc_ssid = rec.associated_ssid
            else:
                nickname = nickname_lookup(rec.mac) if nickname_lookup is not None else ""
                if rec.is_randomized:
                    vendor = "Randomized MAC"
                else:
                    fp = rec.fingerprint
                    vendor = fp.label if fp is not None else ""
                signal_dbm = rec.signal
                assoc_ssid = (
                    ssid_lookup(rec.associated_bssid)
                    if (rec.associated_bssid and ssid_lookup is not None)
                    else None
                )
            ssids_str = "; ".join(
                entry.ssid for entry in sorted(rec.ssids.values(), key=lambda s: (-s.last_seen, s.ssid.lower()))
            )
            writer.writerow([
                rec.mac,
                nickname,
                rec.is_randomized,
                vendor,
                ssids_str,
                rec.associated_bssid or "",
                assoc_ssid or "",
                signal_dbm,
                rec.last_channel,
                rec.count,
                rec.broadcast_count,
                rec.first_seen,
                rec.last_seen,
            ])
    return target
