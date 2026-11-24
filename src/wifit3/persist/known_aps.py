"""Persistent BSSID -> SSID and vendor/model memory across scan sessions."""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Optional

from wifit3.id.common import vendor_for_mac
from wifit3.models import AccessPoint
from wifit3.persist.config import Config

logger = logging.getLogger(__name__)

KNOWN_APS_FILE_NAME = "known_aps.json"
_STORE_VERSION = 1


@dataclass
class KnownAp:
    """Persisted AP name and vendor/model metadata keyed by BSSID."""
    bssid: str
    ssid: Optional[str] = None
    vendor: str = ""
    model: str = ""
    last_seen: float = 0.0

    def to_dict(self) -> dict:
        return {
            "bssid": self.bssid,
            "ssid": self.ssid,
            "vendor": self.vendor,
            "model": self.model,
            "last_seen": self.last_seen,
        }

    @classmethod
    def from_dict(cls, bssid: str, data: dict) -> Optional["KnownAp"]:
        if not isinstance(data, dict):
            return None
        try:
            raw_ssid = data.get("ssid")
            ssid = raw_ssid if isinstance(raw_ssid, str) and raw_ssid and raw_ssid != "<hidden>" else None
            return cls(
                bssid=str(data.get("bssid", bssid)).lower(),
                ssid=ssid,
                vendor=str(data.get("vendor") or ""),
                model=str(data.get("model") or ""),
                last_seen=float(data.get("last_seen", 0.0)),
            )
        except (TypeError, ValueError):
            return None


class KnownApStore:
    """Loads, merges, and atomically writes known AP names/models to ``known_aps.json``."""

    def __init__(self) -> None:
        self._records: Dict[str, KnownAp] = {}
        self._loaded_path: Optional[Path] = None

    @property
    def path(self) -> Path:
        return Path(Config.captures_dir) / KNOWN_APS_FILE_NAME

    def load(self) -> Dict[str, KnownAp]:
        """Return persisted AP metadata, reading from disk if ``captures_dir`` changed."""
        target = self.path
        if self._loaded_path != target:
            self._load_from(target)
        return self._records

    def reload(self) -> Dict[str, KnownAp]:
        """Force re-reading known AP metadata from disk."""
        self._loaded_path = None
        return self.load()

    def _load_from(self, target: Path) -> None:
        records: Dict[str, KnownAp] = {}
        if target.is_file():
            try:
                raw = json.loads(target.read_text(encoding="utf-8"))
            except (OSError, UnicodeError, json.JSONDecodeError) as exc:
                logger.warning("Failed to read %s: %s", target, exc)
                raw = None
            if isinstance(raw, dict):
                aps_obj = raw.get("aps", raw if "version" not in raw else {})
                if isinstance(aps_obj, dict):
                    for bssid_key, item in aps_obj.items():
                        parsed = KnownAp.from_dict(str(bssid_key), item)
                        if parsed is not None and parsed.bssid:
                            records[parsed.bssid] = parsed
                else:
                    logger.warning("Ignoring malformed aps section in %s", target)
            elif raw is not None:
                logger.warning("Ignoring malformed JSON root in %s", target)
        self._records = records
        self._loaded_path = target

    def sync(self, access_points: Dict[str, AccessPoint]) -> bool:
        """Merge discovered AP SSIDs and OUI/WSC models into persistent storage."""
        records = self.load()
        dirty = False

        for bssid, ap in access_points.items():
            key = bssid.lower()
            real_ssid = ap.ssid if (ap.ssid and ap.ssid != "<hidden>") else None
            vendor = vendor_for_mac(key) or ""
            model = ap.identity.summary or vendor
            if not real_ssid and not model:
                continue

            existing = records.get(key)
            if existing is None:
                records[key] = KnownAp(
                    bssid=key,
                    ssid=real_ssid,
                    vendor=vendor,
                    model=model,
                    last_seen=ap.last_seen,
                )
                dirty = True
                continue

            if real_ssid and existing.ssid != real_ssid:
                existing.ssid = real_ssid
                dirty = True
            if vendor and existing.vendor != vendor:
                existing.vendor = vendor
                dirty = True
            if model and len(model) >= len(existing.model) and existing.model != model:
                existing.model = model
                dirty = True
            if ap.last_seen > existing.last_seen:
                existing.last_seen = ap.last_seen
                dirty = True

        if not dirty:
            return False
        return self._write()

    def get(self, bssid: str) -> Optional[KnownAp]:
        return self.load().get(bssid.lower())

    def ssid(self, bssid: str) -> Optional[str]:
        rec = self.get(bssid)
        return rec.ssid if rec is not None else None

    def model(self, bssid: str) -> str:
        rec = self.get(bssid)
        if rec is not None and (rec.model or rec.vendor):
            return rec.model or rec.vendor
        return vendor_for_mac(bssid) or ""

    def find_by_ssid(self, ssid: str) -> Optional[KnownAp]:
        """Return the most recently seen KnownAp matching ``ssid``."""
        if not ssid:
            return None
        matches = [rec for rec in self.load().values() if rec.ssid == ssid]
        if not matches:
            return None
        return max(matches, key=lambda rec: rec.last_seen)

    def _write(self) -> bool:
        target = self.path
        payload = {
            "version": _STORE_VERSION,
            "aps": {bssid: rec.to_dict() for bssid, rec in sorted(self._records.items())},
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
