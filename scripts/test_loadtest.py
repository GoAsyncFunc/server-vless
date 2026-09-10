import argparse
import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import loadtest


class LoadTest(unittest.TestCase):
    def args(self, directory):
        ca = Path(directory) / "ca.pem"
        ca.write_text("test")
        return argparse.Namespace(socks="127.0.0.1:25443", url="https://test.invalid/payload",
                                  target_ip="172.20.0.6", ca=str(ca), sha256="a" * 64,
                                  size=1024, concurrency=1, duration=1, warmup=0,
                                  timeout=1, rate_kib=1024, node_pid=None,
                                  label="unit", output=str(Path(directory) / "result.json"))

    def test_validation(self):
        with tempfile.TemporaryDirectory() as directory:
            args = self.args(directory)
            loadtest.validate(args)
            for field, value in [("target_ip", "8.8.8.8"), ("socks", "0.0.0.0:1234"),
                                 ("duration", 301), ("concurrency", 9), ("size", 0),
                                 ("sha256", "bad"), ("url", "http://test.invalid")]:
                changed = argparse.Namespace(**vars(args))
                setattr(changed, field, value)
                with self.assertRaises(ValueError):
                    loadtest.validate(changed)

    def test_percentile(self):
        self.assertIsNone(loadtest.percentile([], .95))
        self.assertEqual(loadtest.percentile([3, 1, 2], .5), 2)
        self.assertEqual(loadtest.percentile(list(range(100)), .95), 94)

    def test_success_and_payload_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            args = self.args(directory)
            args.size = 4
            args.sha256 = hashlib.sha256(b'test').hexdigest()
            fake = Path(directory) / 'curl'
            fake.write_text('#!/usr/bin/env python3\nimport sys,time\nfrom pathlib import Path\np=Path(sys.argv[sys.argv.index("-o")+1]);p.write_bytes(b"test")\ntime.sleep(.1)\nprint("0.1 0.01")\n')
            fake.chmod(0o700)
            with patch.dict(os.environ, {'PATH': directory + os.pathsep + os.environ['PATH']}):
                self.assertEqual(loadtest.run(args), 0)
            report = json.loads(Path(args.output).read_text())
            self.assertGreater(report['successes'], 0)
            self.assertEqual(report['successes'], report['requests'])
            self.assertFalse(list(Path(directory).glob('payload-*')))

    def test_failure_writes_report(self):
        with tempfile.TemporaryDirectory() as directory:
            args = self.args(directory)
            args.warmup = 1
            with patch("loadtest.subprocess.Popen", side_effect=OSError("sensitive URL")):
                self.assertEqual(loadtest.run(args), 1)
            report = Path(args.output).read_text()
            self.assertIn("OSError", report)
            self.assertNotIn("sensitive", report)


if __name__ == "__main__":
    unittest.main()
