import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("caddy_updater", Path(__file__).with_name("update_caddy.py"))
d = importlib.util.module_from_spec(spec)
spec.loader.exec_module(d)


class FakeUpdater(d.Updater):
    def __init__(self, root, change=None):
        super().__init__(root, root / "build")
        self.active = True
        self.started = []
        self.change = change
        self.stop_failure = False
        self.binary.parent.mkdir(parents=True)
        self.binary.write_bytes(b"original")
        self.config.parent.mkdir(parents=True)
        self.config.write_bytes(b"configuration")
        self.data.mkdir(parents=True)
        (self.data / "certificate").write_bytes(b"preserved certificate")
        self.receipts.mkdir(mode=0o700)
        self.stage = self.receipts / "update-test"
        self.stage.mkdir()
        self.candidate = self.stage / "candidate"
        self.candidate.write_bytes(b"candidate")
        self.build.mkdir()
        for name in d.BUILD_FILES:
            (self.build / name).write_text(name)
        self.routing = {"apps": {}}
        self.routes = {"origin:example": {"status": 200, "certificate": "original"}}

    def configuration(self):
        return {"config": d.manifest(self.config)}

    def stop(self):
        if self.stop_failure:
            raise RuntimeError("Stop unconfirmed")
        self.active = False

    def healthy(self, configuration, routes=None):
        d.require(self.active, "Inactive")
        if self.binary.read_bytes() == b"candidate":
            raise RuntimeError("Candidate unhealthy")
        return 123, self.routes

    def run(self, command, **kwargs):
        if command[:2] == ["systemctl", "start"]:
            self.active = True
            self.started.append(self.binary.read_bytes())
            if self.binary.read_bytes() == b"candidate" and self.change:
                self.change(self)
        return ""

    def replace(self, source):
        self.binary.write_bytes(source.read_bytes())

    def adapted(self, binary=None):
        return self.routing


class UpdaterTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.addCleanup(self.temporary.cleanup)

    def failure(self, change=None):
        updater = FakeUpdater(self.root, change)
        with patch.object(d.time, "sleep"):
            with self.assertRaises(RuntimeError):
                updater.activate(updater.candidate, updater.routing, updater.routes, updater.configuration())
        return updater

    def test_unchanged_failure_rolls_back_only_binary(self):
        updater = self.failure()
        self.assertTrue(updater.active)
        self.assertEqual(updater.binary.read_bytes(), b"original")
        self.assertFalse(updater.pending.exists())
        self.assertEqual(updater.transaction["status"], "rolled_back_binary_only_state_unchanged")
        self.assertTrue((updater.stage / "state.before/certificate").is_file())

    def test_changed_certificate_is_never_restored(self):
        updater = self.failure(lambda u: (u.data / "certificate").write_bytes(b"renewed"))
        self.assertFalse(updater.active)
        self.assertEqual((updater.data / "certificate").read_bytes(), b"renewed")
        self.assertTrue(updater.pending.exists())
        self.assertNotIn(b"original", updater.started)

    def test_added_storage_is_preserved_and_blocks_rollback(self):
        updater = self.failure(lambda u: (u.data / "new").write_bytes(b"new ACME account"))
        self.assertFalse(updater.active)
        self.assertEqual((updater.data / "new").read_bytes(), b"new ACME account")
        self.assertTrue(updater.pending.exists())

    def test_deleted_storage_blocks_rollback(self):
        updater = self.failure(lambda u: (u.data / "certificate").unlink())
        self.assertFalse(updater.active)
        self.assertFalse((updater.data / "certificate").exists())

    def test_operator_configuration_edit_is_preserved(self):
        updater = self.failure(lambda u: u.config.write_bytes(b"operator edit"))
        self.assertFalse(updater.active)
        self.assertEqual(updater.config.read_bytes(), b"operator edit")

    def test_candidate_binary_edit_blocks_rollback(self):
        updater = self.failure(lambda u: u.binary.write_bytes(b"operator binary"))
        self.assertFalse(updater.active)
        self.assertEqual(updater.binary.read_bytes(), b"operator binary")

    def test_binary_permissions_edit_blocks_rollback(self):
        updater = self.failure(lambda u: u.binary.chmod(0o700))
        self.assertFalse(updater.active)
        self.assertEqual(updater.binary.stat().st_mode & 0o777, 0o700)

    def test_previous_receipt_edit_blocks_rollback(self):
        updater = self.failure(lambda u: (u.stage / "binary.before").write_bytes(b"operator"))
        self.assertFalse(updater.active)
        self.assertTrue(updater.pending.exists())

    def test_unconfirmed_stop_never_snapshots_or_switches(self):
        updater = FakeUpdater(self.root)
        updater.stop_failure = True
        with self.assertRaises(RuntimeError):
            updater.activate(updater.candidate, updater.routing, updater.routes, updater.configuration())
        self.assertEqual(updater.binary.read_bytes(), b"original")
        self.assertFalse((updater.stage / "state.before").exists())
        self.assertTrue(updater.pending.exists())
        self.assertEqual(updater.transaction["status"], "manual_recovery_required_stop_unconfirmed")

    def test_capture_failure_restarts_original(self):
        updater = FakeUpdater(self.root)
        with patch.object(d, "snapshot", side_effect=RuntimeError("Capture failed")):
            with self.assertRaises(RuntimeError):
                updater.activate(updater.candidate, updater.routing, updater.routes, updater.configuration())
        self.assertTrue(updater.active)
        self.assertEqual(updater.binary.read_bytes(), b"original")
        self.assertFalse(updater.pending.exists())

    def test_unhealthy_rollback_is_stopped_and_keeps_marker(self):
        updater = FakeUpdater(self.root)
        original = updater.healthy

        def healthy(*args):
            if updater.started:
                raise RuntimeError("Restart never healthy")
            return original(*args)

        with patch.object(updater, "healthy", side_effect=healthy), patch.object(d.time, "sleep"):
            with self.assertRaises(RuntimeError):
                updater.activate(updater.candidate, updater.routing, updater.routes, updater.configuration())
        self.assertFalse(updater.active)
        self.assertTrue(updater.pending.exists())
        self.assertEqual(updater.binary.read_bytes(), b"original")

    def test_rollback_waits_for_readiness(self):
        updater = FakeUpdater(self.root)
        original = updater.healthy
        checks = []

        def healthy(*args):
            if updater.started and updater.binary.read_bytes() == b"original":
                checks.append(True)
                if len(checks) == 1:
                    raise RuntimeError("Still starting")
            return original(*args)

        with patch.object(updater, "healthy", side_effect=healthy), patch.object(d.time, "sleep"):
            with self.assertRaises(RuntimeError):
                updater.activate(updater.candidate, updater.routing, updater.routes, updater.configuration())
        self.assertEqual(len(checks), 2)
        self.assertTrue(updater.active)
        self.assertFalse(updater.pending.exists())

    def test_success_retains_full_recovery_snapshot(self):
        updater = FakeUpdater(self.root)
        updater.healthy = lambda *args: (123, updater.routes)
        updater.activate(updater.candidate, updater.routing, updater.routes, updater.configuration())
        self.assertEqual(updater.binary.read_bytes(), b"candidate")
        self.assertFalse(updater.pending.exists())
        self.assertEqual((updater.stage / "configuration.before/Caddyfile").read_bytes(), b"configuration")
        self.assertEqual(updater.transaction["status"], "verified_all_routes")

    def test_explicit_current_check_does_not_build_or_restart(self):
        updater = FakeUpdater(self.root)
        with patch.object(updater, "compile", side_effect=AssertionError("Unexpected build")):
            result = updater.execute(check_current=True)
        self.assertEqual(result["pid"], 123)
        self.assertEqual(updater.started, [])

    def test_scheduled_unchanged_pins_are_pid_preserving_noop(self):
        updater = FakeUpdater(self.root)
        d.write_json(updater.installed, {"build_files": updater.build_files(),
                                        "binary_sha256": d.checksum(updater.binary)})
        with patch.object(updater, "compile", side_effect=AssertionError("Unexpected build")), \
                patch.object(updater, "verify_build") as verify:
            result = updater.execute()
        self.assertEqual(result["status"], "already_current")
        self.assertEqual(updater.started, [])
        verify.assert_called_once_with(updater.binary)

    def test_unknown_disk_binary_is_not_replaced(self):
        updater = FakeUpdater(self.root)
        d.write_json(updater.installed, {"build_files": updater.build_files(), "binary_sha256": "different"})
        with patch.object(updater, "compile", side_effect=AssertionError("Unexpected build")):
            with self.assertRaisesRegex(RuntimeError, "Unreviewed current binary"):
                updater.execute()

    def test_pending_recovery_prevents_retry(self):
        updater = FakeUpdater(self.root)
        d.write_json(updater.pending, {"receipt": "previous"})
        with self.assertRaisesRegex(RuntimeError, "Unresolved"):
            updater.execute()

    def test_failed_candidate_validation_never_stops_current_service(self):
        updater = FakeUpdater(self.root)
        d.write_json(updater.installed, {"build_files": {}, "binary_sha256": d.checksum(updater.binary)})
        with patch.object(updater, "compile", return_value=updater.candidate), \
                patch.object(updater, "validate", side_effect=RuntimeError("Invalid candidate")):
            with self.assertRaisesRegex(RuntimeError, "Invalid candidate"):
                updater.execute()
        self.assertTrue(updater.active)
        self.assertFalse(updater.pending.exists())
        self.assertEqual(updater.binary.read_bytes(), b"original")

    def test_configuration_edit_during_build_prevents_activation(self):
        updater = FakeUpdater(self.root)
        d.write_json(updater.installed, {"build_files": {}, "binary_sha256": d.checksum(updater.binary)})

        def compile_():
            updater.config.write_bytes(b"operator edit")
            return updater.candidate

        with patch.object(updater, "compile", side_effect=compile_), patch.object(updater, "validate"):
            with self.assertRaisesRegex(RuntimeError, "changed during preparation"):
                updater.execute()
        self.assertTrue(updater.active)
        self.assertFalse(updater.pending.exists())

    def test_changed_route_or_identity_rejects_health(self):
        updater = FakeUpdater(self.root)
        with patch.object(updater, "runtime", return_value=123), \
                patch.object(updater, "live", return_value=updater.routing), \
                patch.object(updater, "probe", return_value={"gemini": "different"}):
            with self.assertRaisesRegex(RuntimeError, "identity changed"):
                d.Updater.healthy(updater, updater.routing, updater.routes)

    def test_runtime_configuration_divergence_is_rejected(self):
        updater = FakeUpdater(self.root)
        with patch.object(updater, "runtime", return_value=123), \
                patch.object(updater, "live", return_value={"different": True}):
            with self.assertRaisesRegex(RuntimeError, "routing differs"):
                d.Updater.healthy(updater, updater.routing)

    def test_stop_refuses_unreviewed_process(self):
        updater = FakeUpdater(self.root)
        process = self.root / "proc/123"
        process.mkdir(parents=True)
        (process / "exe").symlink_to(self.root / "unrelated")
        with patch.object(updater, "property", return_value="123"), \
                patch.object(updater, "run", side_effect=AssertionError("Unexpected stop")):
            with self.assertRaisesRegex(RuntimeError, "Unreviewed"):
                d.Updater.stop(updater)

    def test_snapshot_preserves_metadata_and_syncs_files(self):
        source = self.root / "source"
        source.mkdir(mode=0o750)
        (source / "certificate").write_bytes(b"certificate")
        (source / "certificate").chmod(0o640)
        original = os.fsync
        synced = []

        def fsync(fd):
            synced.append(Path(os.readlink("/proc/self/fd/" + str(fd))))
            original(fd)

        with patch.object(d.os, "fsync", side_effect=fsync):
            recorded = d.snapshot(source, self.root / "saved")
        self.assertEqual(recorded, d.manifest(self.root / "saved"))
        self.assertIn(self.root / "saved/certificate", synced)
        self.assertIn(self.root / "saved", synced)

    def test_symlinks_and_hardlinks_are_rejected(self):
        original = self.root / "original"
        original.write_bytes(b"original")
        link = self.root / "link"
        link.symlink_to(original)
        with self.assertRaises(RuntimeError):
            d.manifest(link)
        link.unlink()
        os.link(original, link)
        with self.assertRaises(RuntimeError):
            d.manifest(original)

    def test_backup_lock_inode_and_permissions_preserved(self):
        backup = self.root / "var/lib/backuper/job.lock"
        backup.parent.mkdir(parents=True)
        backup.write_bytes(b"")
        backup.chmod(0o640)
        before = backup.stat()
        with d.locks(self.root):
            with self.assertRaises(BlockingIOError):
                with d.locks(self.root):
                    self.fail("Concurrent update admitted")
        after = backup.stat()
        self.assertEqual((before.st_ino, before.st_mode, before.st_uid, before.st_gid),
                         (after.st_ino, after.st_mode, after.st_uid, after.st_gid))

    def test_missing_backup_lock_is_not_created(self):
        with self.assertRaisesRegex(RuntimeError, "Existing backup lock"):
            with d.locks(self.root):
                self.fail("Missing lock accepted")

    def test_build_pins_require_exact_compiler_and_both_modules(self):
        directory = self.root / "build"
        directory.mkdir()
        (directory / "go.mod").write_text(
            "module example\n\ngo 1.25.6\n\nrequire (\n"
            "github.com/caddyserver/caddy/v2 v2.10.2\n"
            "github.com/mholt/caddy-l4 v0.0.0-20260127203130-040d25cc886a\n)\n")
        compiler, modules = d.build_pins(directory)
        self.assertEqual(compiler, "go1.25.6")
        self.assertEqual(modules["github.com/caddyserver/caddy/v2"], "v2.10.2")
        with (directory / "go.mod").open("a") as module:
            module.write("replace example => /tmp/unreviewed\n")
        with self.assertRaises(RuntimeError):
            d.build_pins(directory)

    def test_uncovered_storage_and_certificate_loaders_are_rejected(self):
        updater = FakeUpdater(self.root)
        for configuration in ({"storage": {"module": "file_system", "root": "/uncovered"}},
                              {"apps": {"tls": {"certificates": {"load_files": []}}}}):
            with self.subTest(configuration=configuration), \
                    patch.object(updater, "run", return_value=json.dumps(configuration)):
                with self.assertRaisesRegex(RuntimeError, "separately reviewed coverage"):
                    d.Updater.adapted(updater)


if __name__ == "__main__":
    unittest.main()
