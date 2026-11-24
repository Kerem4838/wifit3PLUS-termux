"""Tests for KnownApStore persistent BSSID -> SSID and AP model memory."""
from pathlib import Path

from wifit3.models import AccessPoint, IdSource
from wifit3.persist.config import Config
from wifit3.persist.known_aps import KNOWN_APS_FILE_NAME, KnownApStore
from wifit3.persist.vault import Vault


def test_known_ap_store_persists_ssid_and_model_across_restarts():
    store = KnownApStore()
    ap = AccessPoint(bssid="18:7f:88:aa:bb:cc", ssid="OfficeNet", last_seen=1200.0)
    ap.identity.update(IdSource.WSC_BEACON, manufacturer="TP-Link", model_name="Archer AX10")

    assert store.sync({"18:7f:88:aa:bb:cc": ap}) is True
    assert store.sync({"18:7f:88:aa:bb:cc": ap}) is False

    reloaded = KnownApStore()
    assert reloaded.ssid("18:7f:88:aa:bb:cc") == "OfficeNet"
    assert "Archer AX10" in reloaded.model("18:7f:88:aa:bb:cc")
    found = reloaded.find_by_ssid("OfficeNet")
    assert found is not None and found.bssid == "18:7f:88:aa:bb:cc"

    # Hidden beacon later does not overwrite saved SSID
    hidden_ap = AccessPoint(bssid="18:7f:88:aa:bb:cc", ssid=None, last_seen=1500.0)
    assert reloaded.sync({"18:7f:88:aa:bb:cc": hidden_ap}) is True
    assert reloaded.ssid("18:7f:88:aa:bb:cc") == "OfficeNet"


def test_known_ap_store_handles_corrupt_json_and_vault_lookup():
    path = Path(Config.captures_dir) / KNOWN_APS_FILE_NAME
    path.write_text("{broken", encoding="utf-8")
    store = KnownApStore()
    assert store.load() == {}

    vault = Vault()
    ap = AccessPoint(bssid="00:0c:29:11:22:33", ssid="LabNet", last_seen=2000.0)
    assert vault.sync_known_aps({"00:0c:29:11:22:33": ap}) is True
    assert vault.known_ap_ssid("00:0c:29:11:22:33") == "LabNet"
    assert vault.known_ap_by_ssid("LabNet") is not None
    assert vault.known_ap_model("00:0c:29:11:22:33") != ""
