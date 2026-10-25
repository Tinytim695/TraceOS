from __future__ import annotations

import io
import json
import unittest
from pathlib import Path
from unittest import mock

import sys

ROOT = Path(__file__).resolve().parents[1]
LIB = ROOT / "config/includes.chroot/usr/local/lib/traceos"
sys.path.insert(0, str(LIB))
import ai_client


class AiClientTests(unittest.TestCase):
    def test_endpoint_must_be_https_without_credentials(self):
        with self.assertRaises(ai_client.AiError):
            ai_client.validate_https_endpoint("http://example.com/v1")
        with self.assertRaises(ai_client.AiError):
            ai_client.validate_https_endpoint("https://user:secret@example.com/v1")
        self.assertEqual(ai_client.validate_https_endpoint("https://example.com/v1/"), "https://example.com/v1")

    def test_session_store_masks_and_never_writes_a_file(self):
        store = ai_client.SessionStore()
        store.put("openai", "sk-test-secret-value")
        self.assertEqual(store.masked("openai"), "sk-…ue")
        store.delete("openai")
        self.assertEqual(store.get("openai"), "")

    def test_provider_error_redacts_the_key(self):
        secret = "sk-live-test-key"

        class Boom(Exception):
            pass

        def fail(*_args, **_kwargs):
            raise ai_client.urllib.error.URLError(secret)

        with mock.patch.object(ai_client.urllib.request, "urlopen", fail):
            with self.assertRaises(ai_client.AiError) as caught:
                ai_client.complete("openai", "gpt-4o-mini", secret, "hello")
        self.assertNotIn(secret, str(caught.exception))
        self.assertIn("[redacted]", str(caught.exception))

    def test_openai_request_is_one_explicit_post(self):
        body = io.BytesIO(json.dumps({"choices": [{"message": {"content": "pong"}}]}).encode())
        body.status = 200

        class Response:
            def read(self):
                return body.getvalue()

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

        seen = {}

        def opener(request, timeout=0):
            seen["url"] = request.full_url
            seen["timeout"] = timeout
            seen["auth"] = request.get_header("Authorization")
            return Response()

        with mock.patch.object(ai_client.urllib.request, "urlopen", opener):
            self.assertEqual(ai_client.complete("openai", "gpt-4o-mini", "sk-test", "ping", timeout=5), "pong")
        self.assertEqual(seen["url"], "https://api.openai.com/v1/chat/completions")
        self.assertEqual(seen["timeout"], 5)
        self.assertEqual(seen["auth"], "Bearer sk-test")


if __name__ == "__main__":
    unittest.main()
