"""Tests for ProbeStore persistence and Vault probe integration."""
from pathlib import Path
import csv

from wifit3.models import AccessPoint, ProbeRecord, ProbedSsid
from wifit3.persist.config import Config
from wifit3.persist.probe_store import PROBES_FILE_NAME, ProbeStore, export_probes_csv
from wifit3.persist.vault import Vault


def _live_record(mac: str, ssid: str, count: int, now: float, bssid: str | None = None) -> ProbeRecord:
    rec = ProbeRecord(
        mac=mac,
        count=count,
        broadcast_count=1,
        first_seen=now - 10,
        last_seen=now,
        last_channel=6,
        associated_bssid=bssid,
        signal_by_card={"wlan0": -55},
    )
    rec.ssids[ssid] = ProbedSsid(ssid=ssid, count=count - 1, first_seen=now - 10, last_seen=now)
    return rec


def test_probe_store_persists_merges_without_double_counting():
    store = ProbeStore()
    live = {"00:0c:29:11:22:33": _live_record("00:0c:29:11:22:33", "HomeNet", 4, 1000.0, "aa:bb:cc:dd:ee:ff")}
    aps = {"aa:bb:cc:dd:ee:ff": AccessPoint(bssid="aa:bb:cc:dd:ee:ff", ssid="OfficeAP")}

    assert store.sync(live, aps) is True
    assert store.sync(live, aps) is False

    # Same session increments only by delta
    live["00:0c:29:11:22:33"].count = 6
    live["00:0c:29:11:22:33"].ssids["HomeNet"].count = 5
    live["00:0c:29:11:22:33"].last_seen = 1010.0
    assert store.sync(live, aps) is True

    reloaded = ProbeStore().all_probes()
    assert len(reloaded) == 1
    saved = reloaded[0]
    assert saved.count == 6
    assert saved.broadcast_count == 1
    assert saved.ssids["HomeNet"].count == 5
    assert saved.associated_bssid == "aa:bb:cc:dd:ee:ff"
    assert saved.associated_ssid == "OfficeAP"

    # New session merges onto persisted totals
    new_session_live = {"00:0c:29:11:22:33": _live_record("00:0c:29:11:22:33", "HomeNet", 3, 2000.0)}
    second_store = ProbeStore()
    assert second_store.sync(new_session_live, {}) is True
    merged = second_store.get("00:0c:29:11:22:33")
    assert merged is not None
    assert merged.count == 9
    assert merged.ssids["HomeNet"].count == 7


def test_probe_store_delete_clear_and_corrupt_json():
    probes_file = Path(Config.captures_dir) / PROBES_FILE_NAME
    probes_file.write_text("{corrupt json", encoding="utf-8")
    store = ProbeStore()
    assert store.all_probes() == []

    live = {"11:22:33:44:55:66": _live_record("11:22:33:44:55:66", "Cafe", 2, 1000.0)}
    assert store.sync(live, {}) is True
    assert store.delete("11:22:33:44:55:66") is True
    assert store.all_probes() == []

    # Same unchanged live record does not reappear immediately after deletion
    assert store.sync(live, {}) is False
    assert store.all_probes() == []

    # New probe traffic re-records the client
    live["11:22:33:44:55:66"].count = 3
    assert store.sync(live, {}) is True
    assert len(store.all_probes()) == 1

    store.clear()
    assert store.all_probes() == []


def test_vault_probe_methods_and_notifications():
    vault = Vault()
    events = []
    vault.subscribe(lambda bssid: events.append(bssid))

    live = {"11:22:33:44:55:66": _live_record("11:22:33:44:55:66", "CoffeeShop", 3, 1500.0, "aa:bb:cc:dd:ee:ff")}
    vault.save_wpa_psk("SavedAP", "aa:bb:cc:dd:ee:ff", "secret123", manual=True)
    events.clear()

    assert vault.sync_probes(live, {}) is True
    probes = vault.all_probes()
    assert len(probes) == 1
    assert probes[0].associated_ssid == "SavedAP"
    assert vault.delete_probe("11:22:33:44:55:66") is True
    assert events == [None]
    assert vault.all_probes() == []


def test_export_probes_csv_writes_expected_columns(tmp_path):
    rec = _live_record("02:aa:bb:cc:dd:ee", "CafeWiFi", 3, 1200.0, "aa:bb:cc:dd:ee:ff")
    out = export_probes_csv(
        [rec],
        destination=tmp_path / "out.csv",
        ssid_lookup=lambda bssid: "CafeAP" if bssid == "aa:bb:cc:dd:ee:ff" else None,
    )
    assert out.is_file()
    with out.open(encoding="utf-8", newline="") as f:
        rows = list(csv.DictReader(f))
    assert len(rows) == 1
    assert rows[0]["mac"] == "02:aa:bb:cc:dd:ee"
    assert rows[0]["is_randomized"] == "True"
    assert rows[0]["vendor"] == "Randomized MAC"
    assert rows[0]["ssids"] == "CafeWiFi"
    assert rows[0]["associated_ssid"] == "CafeAP"


def test_probe_store_client_nicknames_persist_and_export(tmp_path):
    store = ProbeStore()
    mac = "18:7f:88:aa:bb:cc"
    live = {mac: _live_record(mac, "HomeNet", 3, 1200.0)}
    assert store.sync(live, {}) is True
    assert store.nickname(mac) == ""

    assert store.set_nickname(mac.upper(), "  Kerem Phone  ") is True
    assert store.set_nickname(mac, "Kerem Phone") is False
    assert ProbeStore().nickname(mac) == "Kerem Phone"

    # Setting a nickname before live sync preserves it once the client is seen
    pre_mac = "aa:11:22:33:44:55"
    assert store.set_nickname(pre_mac, "Guest Tablet") is True
    assert store.sync({pre_mac: _live_record(pre_mac, "GuestNet", 2, 1300.0)}, {}) is True
    reloaded = ProbeStore()
    assert reloaded.nickname(pre_mac) == "Guest Tablet"

    out = export_probes_csv(reloaded.all_probes(), destination=tmp_path / "nick.csv")
    with out.open(encoding="utf-8", newline="") as f:
        rows = {row["mac"]: row for row in csv.DictReader(f)}
    assert rows[mac]["nickname"] == "Kerem Phone"
    assert rows[pre_mac]["nickname"] == "Guest Tablet"

    assert reloaded.set_nickname(mac, "") is True
    assert ProbeStore().nickname(mac) == ""

    vault = Vault()
    events = []
    vault.subscribe(lambda bssid: events.append(bssid))
    assert vault.set_probe_nickname(mac, "Office Laptop") is True
    assert events == [None]
    assert vault.probe_nickname(mac) == "Office Laptop"
