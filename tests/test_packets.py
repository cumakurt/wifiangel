import unittest

from wifi.packets import (
    check_wps,
    get_channel,
    get_security_info,
    get_signal,
    get_ssid,
    parse_client_observation,
    parse_network_observation,
)


class FakeCap:
    def __init__(self, privacy):
        self.privacy = privacy


class FakeLayer:
    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)


class FakeElt:
    def __init__(self, elt_id, info, payload=None, length=None):
        self.ID = elt_id
        self.info = info
        if length is None and isinstance(info, (bytes, bytearray)):
            self.len = len(info)
        elif length is None and isinstance(info, str):
            self.len = len(info)
        else:
            self.len = length if length is not None else 0
        self.payload = payload


class FakePacket:
    def __init__(self, layers, frame_type=None):
        self.layers = layers
        self.type = frame_type

    def haslayer(self, name):
        return name in self.layers

    def getlayer(self, name):
        return self.layers.get(name)


def linked_elts(*elts):
    for current, nxt in zip(elts, elts[1:]):
        current.payload = nxt
    return elts[0]


def rsn_info(akm_type):
    return (
        b"\x01\x00"  # version
        b"\x00\x0f\xac\x04"  # group cipher CCMP
        b"\x01\x00"
        b"\x00\x0f\xac\x04"  # pairwise cipher CCMP
        b"\x01\x00"
        + bytes([0x00, 0x0F, 0xAC, akm_type])
    )


class PacketParsingTests(unittest.TestCase):
    def test_open_network_observation(self):
        dot11 = FakeLayer(addr3="aa:bb:cc:dd:ee:ff")
        beacon = FakeLayer(cap=FakeCap(privacy=False))
        first_elt = linked_elts(
            FakeElt(0, b"Guest"),
            FakeElt(3, bytes([6])),
        )
        beacon.payload = first_elt
        packet = FakePacket(
            {
                "Dot11": dot11,
                "Dot11Beacon": beacon,
            }
        )

        observation = parse_network_observation(packet)

        self.assertEqual(observation.bssid, "aa:bb:cc:dd:ee:ff")
        self.assertEqual(observation.ssid, "Guest")
        self.assertEqual(observation.channel, 6)
        self.assertEqual(observation.security, ("OPEN",))

    def test_wpa3_rsn_detection_uses_akm_suite(self):
        beacon = FakeLayer(cap=FakeCap(privacy=True))
        first_elt = linked_elts(
            FakeElt(0, b"Secure"),
            FakeElt(48, rsn_info(8)),
        )
        beacon.payload = first_elt
        packet = FakePacket({"Dot11Beacon": beacon})

        self.assertEqual(get_security_info(packet), ["WPA2", "WPA3"])

    def test_wps_vendor_element_detection(self):
        packet = FakePacket({"Dot11Elt": FakeElt(221, b"\x00P\xf2\x04abc")})

        self.assertTrue(check_wps(packet))

    def test_client_observation(self):
        dot11 = FakeLayer(
            addr1="11:22:33:44:55:66",
            addr2="22:33:44:55:66:77",
            addr3="aa:bb:cc:dd:ee:ff",
        )
        packet = FakePacket({"Dot11": dot11}, frame_type=2)

        observation = parse_client_observation(packet)

        self.assertEqual(observation.bssid, "aa:bb:cc:dd:ee:ff")
        self.assertEqual(observation.src, "22:33:44:55:66:77")
        self.assertEqual(observation.dst, "11:22:33:44:55:66")

    def test_ssid_respects_ie_length_field(self):
        """Long trailing buffer must not be treated as part of the SSID."""
        dot11 = FakeLayer(addr3="aa:bb:cc:dd:ee:ff")
        beacon = FakeLayer(cap=FakeCap(privacy=False))
        first_elt = linked_elts(
            FakeElt(0, b"Good" + b"\x00" * 20, length=4),
            FakeElt(3, bytes([6])),
        )
        beacon.payload = first_elt
        packet = FakePacket({"Dot11": dot11, "Dot11Beacon": beacon})
        self.assertEqual(get_ssid(packet), "Good")

    def test_ssid_utf8(self):
        dot11 = FakeLayer(addr3="aa:bb:cc:dd:ee:ff")
        beacon = FakeLayer(cap=FakeCap(privacy=False))
        first_elt = linked_elts(FakeElt(0, "caf\u00e9".encode()), FakeElt(3, bytes([1])))
        beacon.payload = first_elt
        packet = FakePacket(
            {"Dot11": dot11, "Dot11Beacon": beacon}
        )
        self.assertEqual(get_ssid(packet), "caf\u00e9")

    def test_ssid_invalid_utf8_shown_hidden(self):
        raw = b"\xff\xfe\x01\x02_ok"
        elt = FakeElt(0, raw)
        packet = FakePacket({"Dot11Elt": elt})
        self.assertEqual(get_ssid(packet), "<Hidden Network>")

    def test_ssid_newlines_collapsed_single_line(self):
        elt = FakeElt(0, b"a\nb\rc")
        packet = FakePacket({"Dot11Elt": elt})
        self.assertEqual(get_ssid(packet), "a b c")

    def test_ssid_raw_ie_bytes_finds_ssid_before_rates(self):
        from scapy.layers.dot11 import Dot11Beacon, Dot11Elt

        inner = Dot11Beacon() / Dot11Elt(ID=0, info=b"HomeWiFi") / Dot11Elt(
            ID=1, info=b"\x82\x84\x8b\x96\x0c\x12\x18"
        )

        class MiniPkt:
            def getlayer(self, name, idx=0, **kwargs):
                if name == "Dot11Beacon":
                    return inner
                return None

            def haslayer(self, name):
                return name == "Dot11Beacon"

        self.assertEqual(get_ssid(MiniPkt()), "HomeWiFi")

    def test_security_wpa2_from_raw_rsn_ie(self):
        from scapy.layers.dot11 import Dot11Beacon, Dot11Elt

        inner = (
            Dot11Beacon(cap=0)
            / Dot11Elt(ID=0, info=b"net")
            / Dot11Elt(ID=48, info=rsn_info(2))
        )

        class MiniPkt:
            def getlayer(self, name, **kwargs):
                if name == "Dot11Beacon":
                    return inner
                return None

            def haslayer(self, name):
                return name == "Dot11Beacon"

        self.assertIn("WPA2", get_security_info(MiniPkt()))

    def test_get_signal_prefers_radiotap(self):
        pkt = FakePacket({"RadioTap": FakeLayer(dBm_AntSignal=-52)})
        self.assertEqual(get_signal(pkt), -52)

    def test_get_channel_from_radiotap_frequency(self):
        beacon = FakeLayer(cap=FakeCap(privacy=False))
        beacon.payload = linked_elts(FakeElt(0, b"x"), FakeElt(3, bytes([0])))
        pkt = FakePacket({"Dot11Beacon": beacon, "RadioTap": FakeLayer(ChannelFrequency=5180)})
        self.assertEqual(get_channel(pkt), 36)

    def test_parse_skips_all_zero_bssid(self):
        dot11 = FakeLayer(addr3="00:00:00:00:00:00")
        beacon = FakeLayer(cap=FakeCap(privacy=False))
        first_elt = linked_elts(FakeElt(0, b"x"), FakeElt(3, bytes([1])))
        beacon.payload = first_elt
        packet = FakePacket(
            {"Dot11": dot11, "Dot11Beacon": beacon}
        )
        self.assertIsNone(parse_network_observation(packet))


if __name__ == "__main__":
    unittest.main()
