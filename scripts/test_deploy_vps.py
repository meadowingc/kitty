from contextlib import closing
import copy
import io
import json
import os
from pathlib import Path
import sqlite3
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import deploy_vps as deploy


def create_database(path):
    with closing(sqlite3.connect(path)) as db:
        db.executescript("CREATE TABLE entries(id INTEGER PRIMARY KEY AUTOINCREMENT, value TEXT);"
                         "INSERT INTO entries(value) VALUES(CAST(X'80FF00' AS TEXT));")


BACKUP = '''[settings]
keep_last = 10
[[databases]]
label = "kitty"
path = "/mnt/volume-hel1-1/kitty/kitty.db"
[[databases]]
label = "other"
path = "/var/lib/other/data.db"
[[files]]
label = "kitty-certificates"
path = "/mnt/volume-hel1-1/kitty/cert"
[[files]]
label = "kitty-configuration"
path = "/mnt/volume-hel1-1/kitty/.env"
[[destinations.rclone]]
remote = "preserve:first"
keep_last = 2
drive_use_trash = false
'''
BACKUP_UNIT = '[Service]\nReadWritePaths="/mnt/volume-hel1-1/kitty" "/var/lib/backuper" "/var/lib/other"\n'
LEGACY_ENV = "CSRF_AUTH_KEY=fixture-with-at-least-32-bytes-not-a-real-secret\n"


class SafetyTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.db = self.root / "source.db"
        create_database(self.db)

    def test_wal_snapshot_and_non_utf8_rows_preserved(self):
        with closing(sqlite3.connect(self.db)) as writer:
            writer.execute("PRAGMA journal_mode=WAL")
            writer.execute("INSERT INTO entries(value) VALUES('WAL row')")
            writer.commit()
            snapshot = self.root / "snapshot.db"
            self.assertEqual(deploy.snapshot(self.db, snapshot), deploy.read_digest(self.db))
            self.assertEqual(deploy.read_digest(snapshot), deploy.read_digest(self.db))
            self.assertEqual(snapshot.stat().st_mode & 0o777, 0o600)

    def test_missing_and_redirected_databases_rejected(self):
        link = self.root / "link.db"
        link.symlink_to(self.db)
        for source in (self.root / "missing.db", link):
            with self.assertRaises(deploy.DeploymentError):
                deploy.snapshot(source, self.root / "copy.db")
        self.assertFalse((self.root / "missing.db").exists())

    def test_snapshot_never_overwrites_destination(self):
        before = self.db.read_bytes()
        with self.assertRaises(FileExistsError):
            deploy.snapshot(self.db, self.db)
        self.assertEqual(self.db.read_bytes(), before)

    def test_complete_digest_detects_data_schema_and_sequences(self):
        for mutation in ("INSERT INTO entries(value) VALUES('new')",
                         "ALTER TABLE entries ADD COLUMN other TEXT",
                         "UPDATE sqlite_sequence SET seq=100 WHERE name='entries'",
                         "PRAGMA user_version=2"):
            before = deploy.read_digest(self.db)
            with closing(sqlite3.connect(self.db)) as db:
                db.executescript(mutation)
            self.assertNotEqual(before, deploy.read_digest(self.db))

    def test_archive_rejects_traversal_links_and_duplicates(self):
        for names, link in ((["../escape"], False), (["/absolute"], False),
                            (["linked"], True), (["same", "./same"], False)):
            with self.subTest(names=names), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                with tarfile.open(root / "archive.tar", "w") as archive:
                    for name in names:
                        member = tarfile.TarInfo(name)
                        if link:
                            member.type, member.linkname = tarfile.SYMTYPE, "/elsewhere"
                            archive.addfile(member)
                        else:
                            member.size = 1
                            archive.addfile(member, io.BytesIO(b"x"))
                with self.assertRaises(deploy.DeploymentError):
                    deploy.extract(root / "archive.tar", root / "target")

    def test_nested_manifest_is_checksummed_and_links_rejected(self):
        (self.root / "assets").mkdir()
        (self.root / "assets/release.json").write_text("runtime file")
        (self.root / "release.json").write_text("manifest")
        self.assertIn("assets/release.json", deploy.release_files(self.root))
        self.assertNotIn("release.json", deploy.release_files(self.root))
        (self.root / "redirect").symlink_to(self.db)
        with self.assertRaises(deploy.DeploymentError):
            deploy.release_files(self.root)

    def test_environment_preserves_secret_and_requires_managed_guards(self):
        original = deploy.read_environment(LEGACY_ENV)
        actual = deploy.read_environment(deploy.managed_environment(LEGACY_ENV))
        self.assertEqual(actual, {**original, **deploy.SETTINGS})
        for suffix in ("KITTY_DB_PATH=somewhere\n", "CSRF_AUTH_KEY=duplicate\n",
                       "OTHER=$(command)\n", "export OTHER=value\n"):
            with self.assertRaises(deploy.DeploymentError):
                deploy.managed_environment(LEGACY_ENV + suffix)

    def test_only_three_backup_sources_and_parent_permission_change(self):
        config, unit = deploy.backup_configuration(BACKUP, BACKUP_UNIT)
        expected = BACKUP.replace('"/mnt/volume-hel1-1/kitty/kitty.db"', '"/mnt/volume-hel1-1/kitty-state/kitty.db"')
        expected = expected.replace('"/mnt/volume-hel1-1/kitty/.env"', '"/etc/kitty/kitty.env"')
        expected = expected.replace('"/mnt/volume-hel1-1/kitty/cert"', '"/etc/kitty/cert"')
        self.assertEqual(config, expected)
        self.assertEqual(unit, BACKUP_UNIT.replace('"/mnt/volume-hel1-1/kitty"', '"/mnt/volume-hel1-1/kitty-state"'))

    def test_unexpected_backup_source_or_parent_rejected(self):
        for text, unit in (
            (BACKUP.replace("kitty/kitty.db", "different/kitty.db"), BACKUP_UNIT),
            (BACKUP, BACKUP_UNIT.replace('"/mnt/volume-hel1-1/kitty"', '"/elsewhere"')),
            (BACKUP, BACKUP_UNIT.replace('"/mnt/volume-hel1-1/kitty"', '"/mnt/volume-hel1-1/kitty" "/mnt/volume-hel1-1/kitty"')),
            (BACKUP + '\n[[files]]\npath="/etc/kitty/cert"\nlabel="duplicate"\n', BACKUP_UNIT),
        ):
            with self.assertRaises(deploy.DeploymentError):
                deploy.backup_configuration(text, unit)

    def test_maintenance_changes_only_kitty_routes(self):
        text = "other {\n reverse_proxy :9999\n}\nkitty {\n reverse_proxy :6835\n}\n route {\n proxy localhost:19666\n}\n"
        result = deploy.maintenance_configuration(text, 25000)
        self.assertEqual(result, text.replace("reverse_proxy :6835", 'respond "Kitty is temporarily down for maintenance." 503')
                         .replace("proxy localhost:19666", "proxy 127.0.0.1:25000"))
        for bad in (text + "other {\n reverse_proxy :6835\n}", text.replace(":19666", ":19667"),
                    text + "another proxy localhost:19666\n"):
            with self.assertRaises(deploy.DeploymentError):
                deploy.maintenance_configuration(bad, 25000)

    def test_changed_process_is_never_signalled(self):
        with patch("deploy_vps.process_identity", return_value={"pid": 123, "start": "new"}), \
                patch("deploy_vps.os.kill") as kill:
            with self.assertRaises(deploy.DeploymentError):
                deploy.stop_exact({"pid": 123, "start": "old"})
            kill.assert_not_called()


class ActivationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        stage = self.root / "receipt"
        stage.mkdir()
        self.installer = deploy.Installer(stage, self.root)
        self.installer.user = SimpleNamespace(pw_uid=os.getuid(), pw_gid=os.getgid())
        self.previous = self.installer.root / "releases/previous"
        self.release = self.installer.root / "releases/next"
        self.previous.mkdir(parents=True)
        self.release.mkdir()
        self.installer.current.symlink_to(self.previous)
        self.installer.data.mkdir(parents=True)
        self.installer.checks.parent.mkdir(parents=True)
        self.installer.environment.parent.mkdir(parents=True)
        self.installer.unit.parent.mkdir(parents=True)
        self.installer.backup_config.parent.mkdir(parents=True)
        self.installer.certs.mkdir()
        for name in deploy.CERT_FILES:
            (self.installer.certs / name).write_text("preserved " + name)
        self.installer.environment.write_text(deploy.managed_environment(LEGACY_ENV))
        self.installer.unit.write_text("old unit")
        self.installer.backup_config.write_text(BACKUP)
        self.installer.backup_unit.write_text(BACKUP_UNIT)
        (self.release / "kitty.service").write_text("new unit")
        (self.previous / "release.json").write_text(json.dumps({"revision": "b" * 40}))
        create_database(self.installer.database)
        self.original = deploy.read_digest(self.installer.database)
        self.commands = []
        self.on_start = lambda: None
        self.enterContext(patch.object(self.installer, "run", side_effect=self.fake_run))
        self.enterContext(patch.object(self.installer, "wait_health"))
        self.enterContext(patch.object(self.installer, "check_process"))
        self.enterContext(patch("deploy_vps.certificate_identity", return_value="fixture"))
        self.enterContext(patch("deploy_vps.check_http"))
        self.enterContext(patch("deploy_vps.check_gemini"))

    def fake_run(self, arguments, **kwargs):
        self.commands.append(arguments)
        if arguments[:2] == ["systemctl", "start"]:
            self.on_start()
        if arguments[:2] == ["systemctl", "show"]:
            return "0"
        return ""

    def activate(self, legacy=None):
        self.installer.activate(self.release, "a" * 40, legacy)

    def failure(self, mutation=None):
        def fail():
            self.on_start = lambda: None
            if mutation:
                mutation()
            raise deploy.DeploymentError("synthetic start failure")
        self.on_start = fail

    def test_success_preserves_full_state_and_pending_until_public_checks(self):
        before = self.installer.environment.read_bytes()
        self.activate()
        self.assertEqual(self.installer.current.resolve(), self.release)
        self.assertEqual(deploy.read_digest(self.installer.database), self.original)
        self.assertEqual(deploy.read_digest(self.installer.stage / "before.db"), self.original)
        self.assertEqual(self.installer.environment.read_bytes(), before)
        self.assertTrue(self.installer.pending.exists())

    def test_unchanged_data_allows_binary_only_rollback(self):
        self.failure()
        with self.assertRaisesRegex(deploy.DeploymentError, "synthetic"):
            self.activate()
        self.assertEqual(self.installer.current.resolve(), self.previous)
        self.assertEqual(deploy.read_digest(self.installer.database), self.original)
        self.assertFalse(self.installer.pending.exists())
        self.assertEqual(self.installer.unit.read_text(), "old unit")

    def test_accepted_data_or_schema_changes_refuse_rollback(self):
        for statement in ("INSERT INTO entries(value) VALUES('accepted')", "ALTER TABLE entries ADD COLUMN future TEXT"):
            with self.subTest(statement=statement):
                def mutate():
                    with closing(sqlite3.connect(self.installer.database)) as db:
                        db.executescript(statement)
                self.failure(mutate)
                with self.assertRaisesRegex(deploy.DeploymentError, "Data changed"):
                    self.activate()
                self.assertEqual(self.installer.current.resolve(), self.release)
                self.assertTrue(self.installer.pending.exists())
                self.assertIn(["systemctl", "disable", "kitty.service"], self.commands)
                (self.installer.stage / "before.db").unlink()

    def test_operator_configuration_is_preserved(self):
        self.failure(lambda: self.installer.environment.write_text("operator edit"))
        with self.assertRaisesRegex(deploy.DeploymentError, "Operator configuration"):
            self.activate()
        self.assertEqual(self.installer.environment.read_text(), "operator edit")
        self.assertTrue(self.installer.pending.exists())

    def test_certificate_changes_are_preserved_without_downgrade(self):
        self.failure(lambda: (self.installer.certs / "gemini_key.pem").write_text("operator replacement"))
        with self.assertRaisesRegex(deploy.DeploymentError, "Certificate files changed"):
            self.activate()
        self.assertEqual((self.installer.certs / "gemini_key.pem").read_text(), "operator replacement")
        self.assertEqual(self.installer.current.resolve(), self.release)

    def test_snapshot_failure_never_restores_old_data(self):
        with patch("deploy_vps.snapshot", side_effect=sqlite3.OperationalError("snapshot failed")):
            with self.assertRaisesRegex(deploy.DeploymentError, "snapshot failed"):
                self.activate()
        self.assertEqual(deploy.read_digest(self.installer.database), self.original)
        self.assertTrue(self.installer.pending.exists())

    def test_unconfirmed_stop_never_switches_release(self):
        with patch.object(self.installer, "stop_service", side_effect=deploy.DeploymentError("still running")):
            with self.assertRaisesRegex(deploy.DeploymentError, "shutdown unconfirmed"):
                self.activate()
        self.assertEqual(self.installer.current.resolve(), self.previous)
        self.assertFalse((self.installer.stage / "before.db").exists())

    def test_initial_copy_preserves_legacy_and_retargets_backup(self):
        self.installer.current.unlink()
        self.installer.unit.unlink()
        self.installer.environment.unlink()
        self.installer.legacy.mkdir(parents=True)
        self.installer.database.replace(self.installer.legacy / "kitty.db")
        self.installer.certs.replace(self.installer.legacy / "cert")
        (self.installer.legacy / ".env").write_text(LEGACY_ENV)
        app = {"pid": 123, "start": "old", "exe": "kitty", "cwd": "legacy", "argv": [b"./kitty"], "parent": 456}
        wrapper = {"pid": 456}
        with patch("deploy_vps.process_identity", side_effect=lambda pid: copy.deepcopy(app if pid == 123 else wrapper)), \
                patch("deploy_vps.stop_exact") as stop, patch("deploy_vps.os.chown"):
            self.activate({"app": app, "wrapper": wrapper})
        self.assertEqual(stop.call_args_list[0].args[0], wrapper)
        self.assertEqual(stop.call_args_list[1].args[0], app)
        self.assertEqual(deploy.read_digest(self.installer.database), self.original)
        self.assertEqual(deploy.read_digest(self.installer.legacy / "kitty.db"), self.original)
        self.assertEqual(self.installer.backup_config.read_text(), deploy.backup_configuration(BACKUP, BACKUP_UNIT)[0])
        for name in deploy.CERT_FILES:
            self.assertEqual((self.installer.certs / name).read_bytes(), (self.installer.legacy / "cert" / name).read_bytes())

    def test_rehearsal_is_isolated_and_leaves_source_unchanged(self):
        self.installer.preflight(self.release, "a" * 40, self.installer.database,
                                 self.installer.environment.read_text(), self.installer.certs)
        launch = next(command for command in self.commands if command[0] == "systemd-run")
        for option in ("IPAddressDeny=any", "IPAddressAllow=localhost", "User=kitty", "ProtectSystem=strict",
                       "ProtectHome=true", "SendSIGKILL=no"):
            self.assertIn(option, launch)
        self.assertEqual(deploy.read_digest(self.installer.database), self.original)
        self.assertEqual(list(self.installer.checks.iterdir()), [])

    def test_rehearsal_schema_changes_are_rejected_and_cleaned(self):
        original_run = self.fake_run
        trial = None

        def altered(arguments, **kwargs):
            nonlocal trial
            if arguments[0] == "systemd-run":
                env = Path(next(arg.split("=", 1)[1] for arg in arguments if arg.startswith("EnvironmentFile=")))
                trial = Path(deploy.read_environment(env.read_text())["KITTY_DB_PATH"])
            if arguments[:2] == ["systemctl", "stop"] and trial:
                with closing(sqlite3.connect(trial)) as db:
                    db.executescript("ALTER TABLE entries ADD COLUMN future TEXT")
            return original_run(arguments, **kwargs)

        with patch.object(self.installer, "run", side_effect=altered):
            with self.assertRaisesRegex(deploy.DeploymentError, "Rehearsal changed"):
                self.installer.preflight(self.release, "a" * 40, self.installer.database,
                                         self.installer.environment.read_text(), self.installer.certs)
        self.assertEqual(deploy.read_digest(self.installer.database), self.original)
        self.assertEqual(list(self.installer.checks.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
