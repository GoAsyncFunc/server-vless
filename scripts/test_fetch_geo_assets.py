import hashlib
import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "build" / "package" / "fetch-geo-assets.sh"
GEOIP = b"geoip fixture bytes\n"
GEOSITE = b"geosite fixture bytes\n"

# Stands in for curl: honours "-o FILE URL", serves the fixtures by basename
# and fails the first $FAKE_FAILURES calls, counting them in $FAKE_STATE.
FAKE_CURL = """#!/bin/sh
out=""
url=""
while [ $# -gt 0 ]; do
  case "$1" in
    -o) out="$2"; shift 2 ;;
    --connect-timeout|--max-time) shift 2 ;;
    -*) shift ;;
    *) url="$1"; shift ;;
  esac
done
count=0
if [ -f "$FAKE_STATE" ]; then count=$(cat "$FAKE_STATE"); fi
count=$((count + 1))
echo "$count" > "$FAKE_STATE"
if [ "$count" -le "${FAKE_FAILURES:-0}" ]; then
  printf 'partial' > "$out"
  exit 22
fi
case "$url" in
  */geoip.dat) cp "$FAKE_FIXTURES/geoip.dat" "$out" ;;
  */geosite.dat) cp "$FAKE_FIXTURES/geosite.dat" "$out" ;;
  *) exit 22 ;;
esac
"""


def sha256(data):
    return hashlib.sha256(data).hexdigest()


class FetchGeoAssets(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: subprocess.run(["rm", "-rf", str(self.tmp)], check=False))
        bin_dir = self.tmp / "bin"
        bin_dir.mkdir()
        (bin_dir / "curl").write_text(FAKE_CURL)
        (bin_dir / "curl").chmod(0o755)
        # The retry pause is real in the script; the tests do not need it.
        (bin_dir / "sleep").write_text("#!/bin/sh\nexit 0\n")
        (bin_dir / "sleep").chmod(0o755)
        fixtures = self.tmp / "fixtures"
        fixtures.mkdir()
        (fixtures / "geoip.dat").write_bytes(GEOIP)
        (fixtures / "geosite.dat").write_bytes(GEOSITE)
        self.dest = self.tmp / "dest"
        self.env = dict(os.environ, PATH=f"{bin_dir}:{os.environ.get('PATH', '')}",
                        FAKE_STATE=str(self.tmp / "calls"), FAKE_FIXTURES=str(fixtures))

    def script(self, geoip_sha=sha256(GEOIP), geosite_sha=sha256(GEOSITE)):
        # Only the pins change; the download, verify and move logic under test
        # is the shipped script's own.
        text = SCRIPT.read_text()
        text = re.sub(r'^GEOIP_SHA256=".*"$', f'GEOIP_SHA256="{geoip_sha}"', text, flags=re.M)
        text = re.sub(r'^GEOSITE_SHA256=".*"$', f'GEOSITE_SHA256="{geosite_sha}"', text, flags=re.M)
        path = self.tmp / "fetch-geo-assets.sh"
        path.write_text(text)
        return path

    def run_script(self, script, failures=0):
        env = dict(self.env, FAKE_FAILURES=str(failures))
        return subprocess.run(["sh", str(script), str(self.dest)], env=env,
                              capture_output=True, text=True, check=False)

    def calls(self):
        return int(Path(self.env["FAKE_STATE"]).read_text())

    def assertNoPartialFiles(self):
        self.assertEqual([], sorted(p.name for p in self.dest.glob("*.part")))

    def test_downloads_verify_and_move_into_place(self):
        result = self.run_script(self.script())
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual(GEOIP, (self.dest / "geoip.dat").read_bytes())
        self.assertEqual(GEOSITE, (self.dest / "geosite.dat").read_bytes())
        self.assertEqual(2, result.stdout.count(" ok"))
        self.assertNoPartialFiles()

    def test_retries_transient_download_failures(self):
        result = self.run_script(self.script(), failures=2)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual(4, self.calls())
        self.assertIn("retrying (2/3)", result.stderr)
        self.assertEqual(GEOIP, (self.dest / "geoip.dat").read_bytes())
        self.assertNoPartialFiles()

    def test_gives_up_after_three_attempts_and_leaves_nothing_behind(self):
        result = self.run_script(self.script(), failures=10)
        self.assertEqual(1, result.returncode)
        self.assertEqual(3, self.calls())
        self.assertIn("download failed after 3 attempts", result.stderr)
        self.assertFalse((self.dest / "geoip.dat").exists())
        self.assertNoPartialFiles()

    def test_rejects_a_checksum_mismatch_and_removes_the_file(self):
        result = self.run_script(self.script(geoip_sha=sha256(b"something else")))
        self.assertEqual(1, result.returncode)
        self.assertIn("geoip.dat: sha256 mismatch", result.stderr)
        self.assertFalse((self.dest / "geoip.dat").exists())
        self.assertFalse((self.dest / "geosite.dat").exists())
        self.assertNoPartialFiles()


if __name__ == "__main__":
    unittest.main()
