"""Unit tests for Probe Request tracking in WlanSink and WlanArray."""
from wifit3.dot11.mac import is_randomized_mac
from wifit3.models import ProbeRecord
from wifit3.wlan.array import WlanArray
from wifit3.wlan.sink import WlanSink

from tests.frames import pkt


def _probe(source="12:22:33:44:55:66", ssid=None, rssi=-52, bssid="ff:ff:ff:ff:ff:ff"):
    return pkt({
        "type": "probe_req",
        "type_id": 0,
        "subtype_id": 4,
        "bssid": bssid,
        "source": source,
        "dest": "ff:ff:ff:ff:ff:ff",
        "rssi": rssi,
        "ssid": ssid,
    })


def test_broadcast_and_directed_probe_tracking():
    sink = WlanSink()

    sink.update(_probe(ssid=None, rssi=-60), "wlan0", channel_hint=6)
    sink.update(_probe(ssid="CafeWiFi", rssi=-50), "wlan0", channel_hint=11)
    sink.update(_probe(ssid="CafeWiFi", rssi=-40), "wlan0", channel_hint=11)

    assert sink.probed_ssids == {"CafeWiFi"}
    rec = sink.probes["12:22:33:44:55:66"]
    assert rec.count == 3
    assert rec.broadcast_count == 1
    assert rec.last_channel == 11
    assert rec.signal == -50
    assert rec.ssids["CafeWiFi"].count == 2
    assert rec.first_seen <= rec.last_seen


def test_probe_ignores_own_macs_and_group_macs():
    sink = WlanSink()
    sink.register_own_mac("02:aa:bb:cc:dd:ee")

    sink.update(_probe(source="02:aa:bb:cc:dd:ee", ssid="MyOwnProbe"), "wlan0")
    sink.update(_probe(source="01:00:5e:00:00:01", ssid="Multicast"), "wlan0")

    assert "02:aa:bb:cc:dd:ee" not in sink.probes
    assert "01:00:5e:00:00:01" not in sink.probes


def test_probe_links_associated_ap_in_either_order():
    sink = WlanSink()
    bssid = "aa:bb:cc:dd:ee:ff"

    # Probe arrives before data frame
    sink.update(_probe(source="10:20:30:40:50:60", ssid="HomeNet"), "wlan0")
    assert sink.probes["10:20:30:40:50:60"].associated_bssid is None

    sink.update(pkt({
        "type": "data",
        "bssid": bssid,
        "source": "10:20:30:40:50:60",
        "dest": bssid,
        "to_ds": True,
        "from_ds": False,
        "rssi": -45,
    }), "wlan0")
    assert sink.probes["10:20:30:40:50:60"].associated_bssid == bssid

    # Data frame arrives before probe
    sink.update(pkt({
        "type": "data",
        "bssid": bssid,
        "source": "aa:11:22:33:44:55",
        "dest": bssid,
        "to_ds": True,
        "from_ds": False,
        "rssi": -48,
    }), "wlan0")
    sink.update(_probe(source="aa:11:22:33:44:55", ssid="OfficeNet"), "wlan0")
    assert sink.probes["aa:11:22:33:44:55"].associated_bssid == bssid


def test_wlan_array_exposes_sink_probes():
    sink = WlanSink()
    array = WlanArray(sink=sink)
    sink.update(_probe(ssid="AirportFree"), "wlan0")
    assert array.probes is sink.probes
    assert "12:22:33:44:55:66" in array.probes


def test_randomized_mac_detection_and_fingerprint_skip():
    assert is_randomized_mac("02:aa:bb:cc:dd:ee") is True
    assert is_randomized_mac("16:11:22:33:44:55") is True
    assert is_randomized_mac("18:7f:88:aa:bb:cc") is False
    assert is_randomized_mac("00:0c:29:11:22:33") is False
    assert is_randomized_mac("03:00:00:00:00:01") is False

    rnd = ProbeRecord(mac="02:aa:bb:cc:dd:ee")
    real = ProbeRecord(mac="18:7f:88:aa:bb:cc")
    assert rnd.is_randomized is True
    assert rnd.fingerprint is None
    assert real.is_randomized is False
    assert real.fingerprint is not None and real.fingerprint.label == "Ring device"


def test_multicard_probe_updates_per_card_signal():
    from types import SimpleNamespace

    sink = WlanSink()
    array = WlanArray(sink=sink, window=5.0)
    iface0 = SimpleNamespace(name="wlan0", current_channel=6)
    iface1 = SimpleNamespace(name="wlan1", current_channel=6)
    array._dedupe.add_source("wlan0")
    array._dedupe.add_source("wlan1")

    raw_frame = b"\x40\x00\x00\x00" + b"\xff" * 6 + b"\x18\x7f\x88\xaa\xbb\xcc" + b"\xff" * 6 + b"\x00\x00"
    p0 = pkt({
        "type": "probe_req", "type_id": 0, "subtype_id": 4,
        "bssid": "ff:ff:ff:ff:ff:ff", "source": "18:7f:88:aa:bb:cc",
        "dest": "ff:ff:ff:ff:ff:ff", "rssi": -68, "ssid": "CoffeeNet", "raw": raw_frame,
    })
    p1 = pkt({
        "type": "probe_req", "type_id": 0, "subtype_id": 4,
        "bssid": "ff:ff:ff:ff:ff:ff", "source": "18:7f:88:aa:bb:cc",
        "dest": "ff:ff:ff:ff:ff:ff", "rssi": -42, "ssid": "CoffeeNet", "raw": raw_frame,
    })

    array._ingest(iface0, p0)
    array._ingest(iface1, p1)

    rec = array.probes["18:7f:88:aa:bb:cc"]
    assert rec.count == 1
    assert rec.signal_by_card == {"wlan0": -68, "wlan1": -42}
    assert rec.signal == -42


def test_assoc_request_records_probed_ssid():
    sink = WlanSink()
    bssid = "aa:bb:cc:dd:ee:ff"
    sink.update(pkt({
        "type": "assoc_req",
        "type_id": 0,
        "subtype_id": 0,
        "bssid": bssid,
        "source": "18:7f:88:aa:bb:cc",
        "dest": bssid,
        "rssi": -49,
        "ssid": "TargetHomeWiFi",
    }), "wlan0", channel_hint=11)

    assert "TargetHomeWiFi" in sink.probed_ssids
    rec = sink.probes["18:7f:88:aa:bb:cc"]
    assert "TargetHomeWiFi" in rec.ssids
    assert rec.associated_bssid == bssid
    assert rec.last_channel == 11
