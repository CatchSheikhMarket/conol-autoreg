import json
import os
import queue
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "upstream"))

with tempfile.TemporaryDirectory() as import_dir:
    with patch.dict(os.environ, {
        "ENI_POOL_DIR": import_dir,
        "ENI_POOL_FILE": str(Path(import_dir) / "pool.jsonl"),
    }):
        import conol_gateway as gateway


class GatewayStatsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.pool_dir = Path(self.tmp.name)
        self.pool_file = self.pool_dir / "pool.jsonl"
        self.rows = [
            {
                "name": "account-%d" % index,
                "email": "account-%d@example.invalid" % index,
                "status": "live",
                "token_expires": time.time() + 3600,
                "session_token": "fixture-cookie-%d" % index,
            }
            for index in range(3)
        ]
        self.pool_file.write_text(
            "".join(json.dumps(row) + "\n" for row in self.rows), encoding="utf-8"
        )
        self.pool = gateway.Pool(self.pool_file, self.pool_dir)

    def stream(self, create_error=None, cookie_missing=False, answer=None):
        events = queue.Queue()
        with patch.object(gateway, "POOL", self.pool):
            with patch.object(gateway, "create_session") as create:
                with patch.object(gateway, "read_answer") as read:
                    if create_error is not None:
                        create.side_effect = create_error
                    else:
                        create.return_value = {"sessionId": "fixture-session"}
                    read.return_value = {"answer": answer or "", "status": "stopped"}
                    if cookie_missing:
                        with patch.object(gateway, "cookie_for", return_value=None):
                            gateway._stream_completion(
                                "glm-5.3", [{"role": "user", "content": "ping"}],
                                [], None, 3, events,
                            )
                    else:
                        gateway._stream_completion(
                            "glm-5.3", [{"role": "user", "content": "ping"}],
                            [], None, 3, events,
                        )
                    create_count = create.call_count
                    read_count = read.call_count
        output = []
        while not events.empty():
            output.append(events.get_nowait())
        return output, create_count, read_count

    def assert_error_stream(self, output, status):
        self.assertEqual(len(output), 2)
        self.assertEqual(output[0]["_status"], status)
        self.assertIn("error", output[0])
        self.assertIsNone(output[1])

    def test_reload_preserves_all_stats(self):
        self.pool.stats.update({
            "requests": 12, "answered": 4, "empty": 2, "errors": 3,
            "rate_limited": 1, "too_long": 2,
        })
        before = self.pool.stats.copy()
        self.assertEqual(self.pool.reload(), 3)
        self.assertEqual(self.pool.stats, {**before, "reloads": before["reloads"] + 1})

    def test_reload_preserves_account_failure_and_request_history(self):
        account = self.pool.next()
        for _ in range(gateway.FAIL_LIMIT):
            self.pool.report_hard_fail(account["name"])
        before = {key: account[key] for key in ("fails", "requests", "dead")}
        self.pool.reload()
        reloaded = next(row for row in self.pool.accounts if row["name"] == account["name"])
        self.assertEqual({key: reloaded[key] for key in before}, before)
        self.assertTrue(reloaded["dead"])
        self.assertEqual(self.pool.snapshot()["usable"], 2)

    def test_stream_session_http_error_counts_every_attempt(self):
        output, created, read = self.stream(gateway.ConolError("HTTP 503 unavailable"))
        self.assert_error_stream(output, 502)
        self.assertEqual((created, read), (3, 0))
        self.assertEqual(self.pool.stats["requests"], 3)
        self.assertEqual(self.pool.stats["errors"], 3)
        self.assertEqual(self.pool.snapshot()["failing"], 0)
        self.assertEqual(self.pool.snapshot()["usable"], 3)

    def test_stream_session_transport_error_counts_every_attempt(self):
        output, created, read = self.stream(TimeoutError("fixture timeout"))
        self.assert_error_stream(output, 502)
        self.assertEqual((created, read), (3, 0))
        self.assertEqual(self.pool.stats["requests"], 3)
        self.assertEqual(self.pool.stats["errors"], 3)
        self.assertEqual(self.pool.snapshot()["failing"], 0)

    def test_stream_auth_error_counts_once_and_marks_accounts_failing(self):
        output, created, read = self.stream(gateway.ConolError("HTTP 401 unauthenticated"))
        self.assert_error_stream(output, 502)
        self.assertEqual((created, read), (3, 0))
        self.assertEqual(self.pool.stats["errors"], 3)
        self.assertTrue(all(account["fails"] == 1 for account in self.pool.accounts))
        self.assertEqual(self.pool.snapshot()["dead"], 0)

    def test_stream_missing_cookie_counts_without_creating_session(self):
        output, created, read = self.stream(cookie_missing=True)
        self.assert_error_stream(output, 502)
        self.assertEqual((created, read), (0, 0))
        self.assertEqual(self.pool.stats["requests"], 3)
        self.assertEqual(self.pool.stats["errors"], 3)
        self.assertEqual(self.pool.snapshot()["failing"], 3)

    def test_stream_rate_limit_counts_separately_without_rotation(self):
        output, created, read = self.stream(gateway.ConolError("HTTP 429 rate limited"))
        self.assert_error_stream(output, 429)
        self.assertEqual((created, read), (1, 0))
        self.assertEqual(self.pool.stats["requests"], 1)
        self.assertEqual(self.pool.stats["rate_limited"], 1)
        self.assertEqual(self.pool.stats["errors"], 0)
        self.assertEqual(self.pool.snapshot()["failing"], 0)

    def test_stream_success_counts_answer_and_survives_reload(self):
        output, created, read = self.stream(answer="pong")
        self.assertEqual((created, read), (1, 1))
        self.assertEqual(output[1], {"content": "pong"})
        self.assertEqual(output[2], {"finish": "stop"})
        self.assertIsNone(output[3])
        self.assertEqual(self.pool.stats["answered"], 1)
        self.assertEqual(self.pool.stats["errors"], 0)
        self.pool.reload()
        self.assertEqual(self.pool.stats["requests"], 1)
        self.assertEqual(self.pool.stats["answered"], 1)
        self.assertEqual(self.pool.stats["errors"], 0)


if __name__ == "__main__":
    unittest.main()
