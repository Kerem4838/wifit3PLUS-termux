"""The global sweep jams every known AP and client on channels the card can tune."""
import asyncio
from types import SimpleNamespace

import pytest

from wifit3.campaigns.campaign import Campaign
from wifit3.campaigns.jam_all import BROADCAST_BURST, CLIENT_ROUNDS, JamAllCampaign
from wifit3.chips.driver import FakeMacSupport
from wifit3.dot11.mac import mac_to_str
from wifit3.models import AccessPoint, Client
from wifit3.persist.config import Config
from wifit3.wlan.array import WlanArray

_AP1 = "aa:bb:cc:00:00:01"
_AP2 = "aa:bb:cc:00:00:02"
_AP3 = "aa:bb:cc:00:00:03"
_SILENCED = "aa:bb:cc:00:00:04"
_FORGED_AP = "aa:bb:cc:00:00:05"
_OFF_BAND = "aa:bb:cc:00:00:06"
_CLIENT1 = "11:22:33:44:55:01"
_CLIENT2 = "11:22:33:44:55:02"
_FORGED_CLIENT = "11:22:33:44:55:03"
_BROADCAST = "ff:ff:ff:ff:ff:ff"


class _FakeIface:
    def __init__(self, channels):
        self.supported_channels = list(channels)
        self.current_channel = channels[0]
        self.driver = SimpleNamespace(FAKE_MAC=FakeMacSupport.NONE)
        self.name = "wlan0"
        self.description = "test card"
        self.chipset = "test"
        self.on_tx = None
        self.frames: list[bytes] = []
        self.channel_calls: list[int] = []
        self.hopping = False
        self.stop_hops = 0
        self.start_hops: list = []

    def register_rx_callback(self, cb):
        pass

    def register_disconnect_callback(self, cb):
        pass

    async def set_channel(self, channel, scan=False):
        self.current_channel = channel
        self.channel_calls.append(channel)
        return True

    async def send_no_wait(self, frame):
        self.frames.append(frame)
        return True

    async def start_hopping(self, channels=None, interval=0.5):
        self.hopping = True
        self.start_hops.append(channels)

    async def stop_hopping(self):
        self.hopping = False
        self.stop_hops += 1


def _pool(channels=(1, 6, 11)):
    iface = _FakeIface(channels)
    array = WlanArray()
    array.attach(iface)
    return array, iface


def _ap(bssid, channel):
    return AccessPoint(bssid=bssid, channel=channel, ssid=bssid)


def _count(frames, a1=None, a2=None):
    return sum(1 for frame in frames
               if (a1 is None or mac_to_str(frame[4:10]) == a1)
               and (a2 is None or mac_to_str(frame[10:16]) == a2))


@pytest.fixture(autouse=True)
def _clear_silenced():
    Config.silenced_bssids = []
    yield
    Config.silenced_bssids = []


async def test_sweep_broadcasts_every_ap_and_deauths_every_client_both_ways():
    array, iface = _pool()
    await array.start_hopping(channels=[1, 6, 11], interval=0.25)
    for ap in (_ap(_AP1, 1), _ap(_AP2, 6), _ap(_AP3, 11),
               _ap(_SILENCED, 1), _ap(_FORGED_AP, 6), _ap(_OFF_BAND, 149)):
        array.access_points[ap.bssid] = ap
    array.clients.update({
        _CLIENT1: Client(mac=_CLIENT1, bssid=_AP1),
        _CLIENT2: Client(mac=_CLIENT2, bssid=_AP2),
        _FORGED_CLIENT: Client(mac=_FORGED_CLIENT, bssid=_AP1),
        "11:22:33:44:55:04": Client(mac="11:22:33:44:55:04", bssid=_SILENCED),
        "11:22:33:44:55:05": Client(mac="11:22:33:44:55:05", bssid=_OFF_BAND),
    })
    Config.silenced_bssids = [_SILENCED]
    array.forged_macs.update({_FORGED_AP, _FORGED_CLIENT})

    camp = JamAllCampaign(array)
    original_sweep = camp._sweep

    async def one_sweep(tx):
        result = await original_sweep(tx)
        camp.stopped = True
        return result

    camp._sweep = one_sweep
    await camp._loop()

    for bssid in (_AP1, _AP2, _AP3):
        assert _count(iface.frames, _BROADCAST, bssid) == BROADCAST_BURST
    for bssid in (_SILENCED, _FORGED_AP, _OFF_BAND):
        assert _count(iface.frames, _BROADCAST, bssid) == 0
    for client in (_CLIENT1, _CLIENT2):
        ap = _AP1 if client == _CLIENT1 else _AP2
        assert _count(iface.frames, client, ap) == CLIENT_ROUNDS
        assert _count(iface.frames, ap, client) == CLIENT_ROUNDS
    assert _count(iface.frames, _FORGED_CLIENT, _AP1) == 0
    assert _count(iface.frames, _AP1, _FORGED_CLIENT) == 0
    assert all(frame[-2:] == b"\x07\x00" for frame in iface.frames)

    assert camp.frames_sent == 3 * BROADCAST_BURST + 4 * CLIENT_ROUNDS
    assert camp.channels_swept == [1, 6, 11]
    assert iface.current_channel == 1
    assert iface.hopping is True
    assert array._hopping is True


async def test_stop_between_frames_keeps_the_partial_burst_and_restores_radio():
    array, iface = _pool()
    await array.start_hopping(channels=[1, 6], interval=0.25)
    array.access_points[_AP1] = _ap(_AP1, 1)
    array.clients[_CLIENT1] = Client(mac=_CLIENT1, bssid=_AP1)

    camp = JamAllCampaign(array)
    original_send = iface.send_no_wait

    async def stop_after_two(frame):
        await original_send(frame)
        if len(iface.frames) == 2:
            camp.stopped = True

    iface.send_no_wait = stop_after_two
    await camp._loop()

    assert len(iface.frames) == 2
    assert camp.frames_sent == 2
    assert iface.current_channel == 1
    assert iface.hopping is True
    assert array._hopping is True


async def test_no_target_ap_leaves_channel_and_hopping_alone():
    array, iface = _pool()
    await array.start_hopping(channels=[1, 6], interval=0.25)
    logs: list[str] = []
    camp = JamAllCampaign(array, log=logs.append)

    await camp._loop()

    assert iface.frames == []
    assert iface.channel_calls == []
    assert iface.current_channel == 1
    assert iface.hopping is True
    assert any("no target AP" in line for line in logs)


async def test_run_then_request_stop_releases_the_radio_mutex():
    array, iface = _pool()
    await array.start_hopping(channels=[1, 6], interval=0.25)
    array.access_points[_AP1] = _ap(_AP1, 6)
    logs: list[str] = []
    camp = JamAllCampaign(array, log=logs.append)

    assert camp.run() is True
    assert Campaign.active is camp
    await asyncio.sleep(0)
    camp.request_stop()
    await camp.stop()

    assert Campaign.active is None
    assert camp.done is True
    assert iface.current_channel == 1
    assert iface.hopping is True
    assert any("Jam All stopped" in line for line in logs)


async def test_a_second_campaign_cannot_claim_the_radio_while_sweeping():
    array, _ = _pool()
    await array.start_hopping(channels=[1], interval=0.25)
    array.access_points[_AP1] = _ap(_AP1, 1)
    first = JamAllCampaign(array)
    assert first.run() is True
    second = JamAllCampaign(array)
    try:
        assert second.run() is False
        assert Campaign.active is first
    finally:
        first.request_stop()
        await first.stop()


def _two_card_pool():
    card_24 = _FakeIface([1, 6, 11])
    card_5 = _FakeIface([36, 40])
    array = WlanArray()
    array.attach(card_24)
    array.attach(card_5)
    return array, card_24, card_5


async def _one_sweep(camp):
    original = camp._sweep

    async def stop_after(tx):
        result = await original(tx)
        camp.stopped = True
        return result

    camp._sweep = stop_after


async def test_two_cards_leave_the_unclaimed_card_hopping():
    array, card_24, card_5 = _two_card_pool()
    array.prefer(card_24)
    await array.start_hopping(channels=[1, 6, 11, 36, 40], interval=0.25)
    for bssid, channel in ((_AP1, 1), (_AP3, 6), (_OFF_BAND, 36)):
        array.access_points[bssid] = _ap(bssid, channel)

    camp = JamAllCampaign(array)
    await _one_sweep(camp)
    await camp._loop()

    assert _count(card_24.frames, _BROADCAST, _AP1) == BROADCAST_BURST
    assert _count(card_24.frames, _BROADCAST, _AP3) == BROADCAST_BURST
    assert card_5.frames == []
    assert card_5.hopping is True
    assert card_24.current_channel == 1
    assert card_24.hopping is True


async def test_pinned_card_without_targets_falls_back_to_a_card_that_has_them():
    array, card_24, card_5 = _two_card_pool()
    array.prefer(card_5)
    await array.start_hopping(channels=[1, 6, 11, 36, 40], interval=0.25)
    array.access_points[_AP1] = _ap(_AP1, 1)
    array.access_points[_AP3] = _ap(_AP3, 6)

    camp = JamAllCampaign(array)
    await _one_sweep(camp)
    await camp._loop()

    assert _count(card_24.frames, _BROADCAST, _AP1) == BROADCAST_BURST
    assert _count(card_24.frames, _BROADCAST, _AP3) == BROADCAST_BURST
    assert card_5.frames == []
