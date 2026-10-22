import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.publish_results import prepare_release_assets


class PublishResultsTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.workspace = Path(self.temp_dir.name)
        self.output = self.workspace / "output"
        self.output.mkdir()
        self.previous_cwd = Path.cwd()
        os.chdir(self.workspace)
        self.addCleanup(os.chdir, self.previous_cwd)

    def _write(self, relative_path, content=b"data"):
        path = self.output / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        return path

    def test_prepares_only_canonical_public_assets_and_checksums(self):
        self._write("custom/user_result.txt", b"Demo,http://example.com\n")
        self._write("custom/user_result.m3u", b"#EXTM3U\n")
        self._write("ipv4/result.txt", b"IPv4,http://example.com\n")
        self._write("epg/epg.gz", b"gzip-data")
        self._write("log/log.log", b"private log")
        self._write("data/channel_results.db", b"private database")

        destination = self.workspace / "release-assets"
        manifest = prepare_release_assets(
            final_file="output/custom/user_result.txt",
            destination=destination,
            generated_at="2026-09-08T00:00:00+00:00",
            repository="owner/repository",
            source_sha="abc123",
            workflow_run_id="42",
        )

        self.assertEqual(
            {path.name for path in destination.iterdir()},
            {
                "result.txt",
                "result.m3u",
                "ipv4.txt",
                "epg.gz",
                "direct-ruleset.yaml",
                "direct-ruleset.json",
                "manifest.json",
                "SHA256SUMS.txt",
            },
        )
        self.assertEqual(manifest["repository"], "owner/repository")
        self.assertEqual(manifest["generated_at"], "2026-09-08T00:00:00+00:00")
        manifest_file = json.loads((destination / "manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest_file, manifest)
        result_digest = hashlib.sha256((destination / "result.txt").read_bytes()).hexdigest()
        checksums = (destination / "SHA256SUMS.txt").read_text(encoding="utf-8")
        self.assertIn(f"{result_digest}  result.txt", checksums)
        self.assertNotIn("log.log", checksums)
        self.assertNotIn("channel_results.db", checksums)

    def test_exports_matching_direct_rules_from_public_playlist_urls(self):
        self._write(
            "result.txt",
            b"Demo,http://viewer:secret@TV.Example:8080/live/token.m3u8\n"
            b"Multicast,udp://@239.0.0.1:1234\n"
            b"Malformed,http://[invalid\n",
        )
        self._write(
            "result.m3u",
            b'#EXTM3U x-tvg-url="https://epg.example/epg.xml"\n'
            b'#EXTINF:-1 tvg-logo="https://images.example/logo.png",Demo\n'
            b"https://tv.example/duplicate.m3u8\n",
        )
        self._write("ipv6/result.m3u", b"#EXTM3U\nhttps://[2001:db8::1]:443/live\n")
        self._write("log/log.log", b"http://private.example/hidden\n")
        destination = self.workspace / "release-assets"

        manifest = prepare_release_assets("output/result.txt", destination)

        rule_set = json.loads((destination / "direct-ruleset.json").read_text(encoding="utf-8"))
        rule = rule_set["rules"][0]
        self.assertEqual(rule_set["version"], 1)
        self.assertEqual(rule["domain"], ["epg.example", "images.example", "tv.example"])
        self.assertEqual(rule["ip_cidr"], ["239.0.0.1/32", "2001:db8::1/128"])
        self.assertIn("52tb.xyz", rule["domain_suffix"])
        self.assertIn("freetv.top", rule["domain_suffix"])
        payload = (destination / "direct-ruleset.yaml").read_text(encoding="utf-8")
        self.assertIn("  - IP-CIDR,239.0.0.1/32\n", payload)
        self.assertIn("  - IP-CIDR6,2001:db8::1/128\n", payload)
        self.assertIn("  - DOMAIN,tv.example\n", payload)
        self.assertIn("  - DOMAIN-SUFFIX,52tb.xyz\n", payload)
        self.assertNotIn("secret", payload)
        self.assertNotIn("token", payload)
        self.assertNotIn("private.example", payload)
        self.assertEqual(payload.count("DOMAIN,tv.example\n"), 1)
        for name in ("direct-ruleset.yaml", "direct-ruleset.json"):
            asset = next(asset for asset in manifest["assets"] if asset["name"] == name)
            self.assertEqual(asset["sha256"], hashlib.sha256((destination / name).read_bytes()).hexdigest())

    def test_rejects_final_file_outside_output_directory(self):
        secret = self.workspace / "secret.txt"
        secret.write_text("secret", encoding="utf-8")

        with self.assertRaisesRegex(ValueError, "must be inside"):
            prepare_release_assets(
                final_file=secret,
                destination=self.workspace / "release-assets",
            )

    def test_rejects_empty_or_oversized_final_file(self):
        final_file = self._write("result.txt", b"")
        with self.assertRaisesRegex(ValueError, "is empty"):
            prepare_release_assets(
                final_file=final_file,
                destination=self.workspace / "empty-assets",
            )

        final_file.write_bytes(b"too large")
        with patch("scripts.publish_results.MAX_RELEASE_ASSET_BYTES", 1):
            with self.assertRaisesRegex(ValueError, "exceeds"):
                prepare_release_assets(
                    final_file=final_file,
                    destination=self.workspace / "large-assets",
                )


class PublishWorkflowTests(unittest.TestCase):
    def test_manual_workflow_publishes_release_without_git_push(self):
        workflow = Path(".github/workflows/main.yml").read_text(encoding="utf-8")

        self.assertIn("workflow_dispatch:", workflow)
        self.assertNotIn("schedule:", workflow)
        self.assertNotIn("git push", workflow)
        self.assertNotIn("git commit", workflow)
        self.assertIn("contents: write", workflow)
        self.assertIn("playlist-latest", workflow)
        self.assertIn("scripts/publish_results.py", workflow)

    def test_generated_output_is_ignored_by_git(self):
        ignore_patterns = Path(".gitignore").read_text(encoding="utf-8").splitlines()

        self.assertIn("/output/", ignore_patterns)
