import unittest

from wifi.packets import (
    check_wps,
    get_security_info,
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
    def __init__(self, elt_id, info, payload=None):
        self.ID = elt_id
        self.info = info
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
        packet = FakePacket(
            {
                "Dot11": dot11,
                "Dot11Beacon": beacon,
                "Dot11Elt": first_elt,
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
        packet = FakePacket({"Dot11Beacon": beacon, "Dot11Elt": first_elt})

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


if __name__ == "__main__":
    unittest.main()
