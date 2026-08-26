"""Offline tests for HttpTransport: URL building, envelope handling, fail-closed.

NO real network. urllib calls are intercepted via urlopen monkeypatching;
bodies are synthetic strings.
"""
from __future__ import annotations

import io
import json
import sys
import unittest
import urllib.error
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from adapter.http_transport import HttpTransport, TransportError  # noqa: E402

T = HttpTransport(base_url="https://tc.example")


class FakeResponse(io.BytesIO):
    status = 200

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def install_urlopen(calls, body=b"{}", status=200):
    def fake_urlopen(req, timeout=None):
        calls.append({"url": req.full_url, "timeout": timeout,
                      "headers": dict(req.header_items())})
        r = FakeResponse(body)
        r.status = status
        return r
    from adapter import http_transport as ht
    ht.urllib.request.urlopen = fake_urlopen
    return fake_urlopen


class TestURLBuilding(unittest.TestCase):
    def test_read_url_shape(self):
        self.assertEqual(
            T.build_read_url("mb-x", 41, 10),
            "https://tc.example/r/mb-x?since=41&wait=10&format=json")

    def test_post_url_matches_engine_estimator(self):
        did = "did:key:z6MkvgWDuQjhQfwaqkkDf6SAC9QNg7sCHe9xjbBeUQguQbjd"
        sig = "A" * 86
        url = T.build_post_url("mb-x", did, sig, 3, "hi there")
        self.assertTrue(url.startswith("https://tc.example/r/mb-x/say-signed/"))
        self.assertIn("/3/", url)
        # engine's own estimator must accept the assembled length
        v = __import__("engine.preflight", fromlist=["x"])\
            .estimate_request_line("https://tc.example", "mb-x", did, sig,
                                   3, "hi there")
        self.assertTrue(v.ok)

    def test_room_name_is_path_quoted(self):
        url = T.build_read_url("mb-a%2Fb", 0)
        self.assertNotIn("%2F", url.split("?")[0].split("/r/")[1].split("?")[0]
                         .replace("%25", ""))


class TestEnvelopeHandling(unittest.TestCase):
    def tearDown(self):
        from adapter import http_transport as ht
        ht.urllib.request.urlopen = ht.__dict__.get("_orig_urlopen",
                                                    ht.urllib.request.urlopen)

    def test_records_list_envelope(self):
        calls = []
        install_urlopen(
            calls,
            body=json.dumps([{"seq": 1, "from": "~a", "text": "hi"}]).encode())
        rows = T.read_room_json("mb-x", 0)
        self.assertEqual(len(rows), 1)

    def test_wrapped_envelope(self):
        calls = []
        install_urlopen(
            calls,
            body=json.dumps({"records": [{"seq": 1}]}).encode())
        self.assertEqual(len(T.read_room_json("mb-x", 0)), 1)

    def test_unexpected_envelope_raises(self):
        calls = []
        install_urlopen(calls, body=json.dumps({"weird": 1}).encode())
        with self.assertRaises(TransportError):
            T.read_room_json("mb-x", 0)

    def test_non_json_body_raises(self):
        calls = []
        install_urlopen(calls, body=b"<html>oops</html>")
        with self.assertRaises(TransportError):
            T.read_room_json("mb-x", 0)


class TestFailClosed(unittest.TestCase):
    def tearDown(self):
        from adapter import http_transport as ht
        ht.urllib.request.urlopen = ht.__dict__.get("_orig_urlopen",
                                                    ht.urllib.request.urlopen)

    def test_http_error_maps_to_transport_error_with_status(self):
        calls = []

        def fake(req, timeout=None):
            calls.append(req.full_url)
            raise urllib.error.HTTPError(
                req.full_url, 503, "Service Unavailable", {}, io.BytesIO(b""))

        from adapter import http_transport as ht
        ht._orig_urlopen = ht.urllib.request.urlopen
        ht.urllib.request.urlopen = fake
        with self.assertRaises(TransportError) as ctx:
            T.read_note("did-11", "b17958c4064c71")
        self.assertEqual(ctx.exception.status, 503)

    def test_404_note_read_returns_none_not_raise(self):
        calls = []

        def fake(req, timeout=None):
            raise urllib.error.HTTPError(
                req.full_url, 404, "Not Found", {}, io.BytesIO(b""))

        from adapter import http_transport as ht
        ht.urllib.request.urlopen = fake
        self.assertIsNone(T.read_note("did", "absent99999999"))

    def test_timeout_raises_transport_error(self):
        calls = []

        def fake(req, timeout=None):
            raise TimeoutError("timed out")

        from adapter import http_transport as ht
        ht.urllib.request.urlopen = fake
        with self.assertRaises(TransportError):
            T.read_room_json("mb-x", 0)

    def test_text_plain_success_write_envelope_parses(self):
        """Regression: live successful writes return text/plain
        ('# room … messages N range a..b'), not JSON. The transport must
        accept that shape and extract the assigned seq."""
        calls = []
        body = ("# room mb-p-j1e2e-506b25ec1235  messages 3  range 1..3\n"
                "!! UNTRUSTED CONTENT -- agents can write anything\n"
                "PFR v1 | 3db3e58c0baa6842 | PASS | engine=0.1.0 ; T1-ok x")
        install_urlopen(calls, body=body.encode())
        out = T.post_signed_message("mb-p-j1e2e-506b25ec1235",
                                    "did:key:z6MkvgWD", "S" * 86, 1, "x")
        self.assertEqual(out["format"], "text")
        self.assertEqual(out["seq"], 3)
        self.assertEqual(out["range"], [1, 3])

    def test_json_write_envelope_still_accepted(self):
        calls = []
        install_urlopen(calls, body=json.dumps({"seq": 9}).encode())
        out = T.post_signed_message("mb-x", "did:key:z6MkvgWD",
                                    "S" * 86, 1, "x")
        self.assertEqual(out.get("seq"), 9)


if __name__ == "__main__":
    unittest.main()
