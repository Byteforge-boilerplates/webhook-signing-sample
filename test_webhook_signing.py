import json
import unittest

import webhook_signing as ws


BODY = json.dumps({"type": "usage.updated", "data": {"bytes": 1024}}).encode()
SECRET = ws.generate_secret()
NOW = 1_700_000_000


class SignVerifyTests(unittest.TestCase):
    def test_valid_signature_verifies(self):
        header = ws.sign(SECRET, BODY, NOW)
        self.assertTrue(ws.verify(header, BODY, [SECRET], now=NOW))

    def test_changed_body_fails(self):
        header = ws.sign(SECRET, BODY, NOW)
        self.assertFalse(ws.verify(header, BODY + b" ", [SECRET], now=NOW))

    def test_wrong_secret_fails(self):
        header = ws.sign(SECRET, BODY, NOW)
        self.assertFalse(ws.verify(header, BODY, [ws.generate_secret()], now=NOW))

    def test_stale_timestamp_fails(self):
        header = ws.sign(SECRET, BODY, NOW)
        self.assertFalse(ws.verify(header, BODY, [SECRET], now=NOW + 301))
        self.assertTrue(ws.verify(header, BODY, [SECRET], now=NOW + 300))

    def test_future_timestamp_outside_tolerance_fails(self):
        header = ws.sign(SECRET, BODY, NOW)
        self.assertFalse(ws.verify(header, BODY, [SECRET], now=NOW - 301))

    def test_overlap_window_accepts_old_secret(self):
        old = ws.generate_secret()
        header = ws.sign(old, BODY, NOW)
        self.assertTrue(ws.verify(header, BODY, [SECRET, old], now=NOW))

    def test_malformed_header_fails(self):
        for header in ("", "t=abc,v1=ff", "v1=deadbeef", "t=1700000000"):
            self.assertFalse(ws.verify(header, BODY, [SECRET], now=NOW), header)


class HelperTests(unittest.TestCase):
    def test_secret_format(self):
        self.assertTrue(SECRET.startswith("whsec_"))
        self.assertEqual(len(SECRET), len("whsec_") + 32)

    def test_prefix_is_short_and_safe(self):
        self.assertEqual(ws.secret_prefix(SECRET), SECRET[:10])

    def test_delivery_headers_carry_signature_and_event_id(self):
        headers = ws.delivery_headers(SECRET, event_id="evt_1", raw_body=BODY, timestamp=NOW, test=True)
        self.assertEqual(headers[ws.EVENT_ID_HEADER], "evt_1")
        self.assertEqual(headers["X-Example-Test"], "true")
        self.assertTrue(ws.verify(headers[ws.SIGNATURE_HEADER], BODY, [SECRET], now=NOW))


if __name__ == "__main__":
    unittest.main()
