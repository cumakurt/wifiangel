import unittest

from adapters.system_tools.speed import (
    DOWNLOAD_TEST_BYTES,
    build_speed_recommendations,
    bytes_to_mbytes_per_second,
    curl_download_command,
    curl_upload_command,
    download_speed_rating,
    estimate_upload_mbytes_per_second,
    fallback_upload_mbytes_per_second,
    mbytes_to_mbits,
    parse_ping_stats,
    ping_command,
    speed_gauge_blocks,
    upload_speed_rating,
)


class SpeedHelperTests(unittest.TestCase):
    def test_speed_calculations(self):
        self.assertEqual(bytes_to_mbytes_per_second(1024 * 1024, 2), 0.5)
        self.assertEqual(bytes_to_mbytes_per_second(1024, 0), 0)
        self.assertEqual(mbytes_to_mbits(2.5), 20)

    def test_upload_estimate_and_fallback(self):
        self.assertEqual(estimate_upload_mbytes_per_second(1024 * 1024, 2), 1.25)
        self.assertEqual(fallback_upload_mbytes_per_second(10), 3)
        self.assertEqual(fallback_upload_mbytes_per_second(0), 1.5)

    def test_parse_ping_stats(self):
        output = "rtt min/avg/max/mdev = 12.345/23.456/34.567/0.123 ms\n"

        stats = parse_ping_stats(output)

        self.assertIsNotNone(stats)
        self.assertEqual(stats.raw, "12.345/23.456/34.567/0.123")
        self.assertEqual(stats.average_ms, 23.456)
        self.assertEqual(stats.deviation_ms, 0.123)

    def test_parse_ping_stats_returns_none_for_invalid_output(self):
        self.assertIsNone(parse_ping_stats("no packets received"))
        self.assertIsNone(parse_ping_stats("rtt min/avg/max/mdev = bad/output ms"))

    def test_gauge_blocks_are_bounded(self):
        self.assertEqual(speed_gauge_blocks(-1, 100), 0)
        self.assertEqual(speed_gauge_blocks(50, 100), 5)
        self.assertEqual(speed_gauge_blocks(500, 100), 10)

    def test_ratings(self):
        self.assertEqual(download_speed_rating(4), "[red]Very Slow[/]")
        self.assertEqual(download_speed_rating(75), "[green]Good[/]")
        self.assertEqual(upload_speed_rating(0.5), "[red]Very Slow[/]")
        self.assertEqual(upload_speed_rating(60), "[bold green]Excellent[/]")

    def test_recommendations(self):
        recommendations = build_speed_recommendations(5, 2, 150)

        self.assertEqual(len(recommendations), 3)

    def test_command_builders(self):
        self.assertEqual(
            ping_command(count=1, timeout_seconds=2),
            ["ping", "-c", "1", "-W", "2", "8.8.8.8"],
        )
        self.assertEqual(ping_command(count=5, quiet=True), ["ping", "-c", "5", "-q", "8.8.8.8"])
        self.assertIn(str(DOWNLOAD_TEST_BYTES), curl_download_command()[-1])
        self.assertEqual(curl_upload_command("/tmp/test.dat")[-2], "file=@/tmp/test.dat")


if __name__ == "__main__":
    unittest.main()
