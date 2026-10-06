"""Build a committed Kitty release and deploy it with guarded HTTP/Gemini cutover."""

import argparse
from contextlib import closing, contextmanager
import copy
import fcntl
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import pwd
import re
import shlex
import shutil
import signal
import socket
import sqlite3
import ssl
import subprocess
import sys
import tarfile
import tempfile
import time
import tomllib
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener
import uuid


LEGACY = Path("/mnt/volume-hel1-1/kitty")
DATA = Path("/mnt/volume-hel1-1/kitty-state")
ENV = Path("/etc/kitty/kitty.env")
CERTS = Path("/etc/kitty/cert")
PUBLIC = "https://kitty.meadow.cafe"
GEMINI_HOST = "gmi.kitty.meadow.cafe"
CERT_FILES = ("gemini_cert.pem", "gemini_key.pem")
SETTINGS = {
    "KITTY_HTTP_ADDR": "127.0.0.1:6835",
    "KITTY_GEMINI_ADDR": "127.0.0.1:19666",
    "KITTY_DB_PATH": str(DATA / "kitty.db"),
    "KITTY_GEMINI_CERT": str(CERTS / CERT_FILES[0]),
    "KITTY_GEMINI_KEY": str(CERTS / CERT_FILES[1]),
    "KITTY_REQUIRE_DATABASE": "true",
    "KITTY_REQUIRE_TLS": "true",
}


class DeploymentError(RuntimeError):
    pass


def require(condition, message):
    if not condition:
        raise DeploymentError(message)


def checksum(path):
    with Path(path).open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def private_write(path, contents):
    fd, name = tempfile.mkstemp(prefix=".install-", dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(fd, "w") as output:
            output.write(contents)
            output.flush()
            os.fsync(output.fileno())
        temporary.replace(path)
        sync_directory(path.parent)
    finally:
        temporary.unlink(missing_ok=True)


def extract(archive, destination):
    seen = set()
    with tarfile.open(archive) as source:
        for member in source:
            name = PurePosixPath(member.name)
            require(name.parts and not name.is_absolute() and ".." not in name.parts
                    and name.as_posix() not in seen and (member.isfile() or member.isdir()),
                    "Unsafe, duplicate, linked or special archive member")
            seen.add(name.as_posix())
            target = destination.joinpath(*name.parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            if member.isdir():
                target.mkdir(exist_ok=True)
            else:
                with source.extractfile(member) as incoming, target.open("xb") as output:
                    shutil.copyfileobj(incoming, output)


def release_files(directory):
    result = {}
    for path in [directory, *directory.rglob("*")]:
        require(not path.is_symlink() and (path.is_file() or path.is_dir()),
                "Release contains a link or special file")
        if path.is_file() and path != directory / "release.json":
            result[path.relative_to(directory).as_posix()] = checksum(path)
    return result


def database_digest(connection):
    require(connection.execute("PRAGMA integrity_check").fetchall() == [("ok",)], "Database integrity check failed")
    digest = hashlib.sha256()
    connection.text_factory = bytes
    try:
        digest.update(repr(connection.execute(
            "SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY type,name").fetchall()).encode("ascii"))
        for (name,) in connection.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name").fetchall():
            quoted = '"' + name.decode().replace('"', '""') + '"'
            primary = sorted((row[5], row[1]) for row in connection.execute(f"PRAGMA table_info({quoted})") if row[5])
            order = ",".join('"' + column.decode().replace('"', '""') + '"' for _, column in primary) or "rowid"
            digest.update(name)
            for row in connection.execute(f"SELECT * FROM {quoted} ORDER BY {order}"):
                digest.update(repr(row).encode("ascii"))
        for pragma in ("user_version", "application_id"):
            digest.update(repr(connection.execute(f"PRAGMA {pragma}").fetchone()).encode("ascii"))
    finally:
        connection.text_factory = str
    return digest.hexdigest()


def read_digest(path):
    require(path.is_file() and not path.is_symlink(), "Database is missing or redirected")
    with closing(sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True)) as db:
        db.execute("BEGIN")
        return database_digest(db)


def snapshot(source, target):
    require(source.is_file() and not source.is_symlink(), "Source database is missing or redirected")
    fd = os.open(target, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    os.close(fd)
    deadline = time.monotonic() + 120

    def progress(*_):
        require(time.monotonic() < deadline, "Database snapshot exceeded its deadline")

    with closing(sqlite3.connect(source.resolve().as_uri() + "?mode=ro", uri=True)) as incoming:
        with closing(sqlite3.connect(target)) as output:
            incoming.backup(output, pages=256, progress=progress, sleep=0.05)
            return database_digest(output)


def read_environment(text):
    values = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        key, separator, value = line.partition("=")
        require(separator and re.fullmatch("[A-Z_][A-Z_0-9]*", key) and key not in values,
                "Unsupported or duplicate environment assignment")
        parts = shlex.split(value, comments=True)
        require(len(parts) == 1 and not any(char in parts[0] for char in "$`\r\n"),
                "Environment expansion is not supported")
        values[key] = parts[0]
    return values


def write_environment(values):
    return "".join(key + "=" + json.dumps(value) + "\n" for key, value in values.items())


def managed_environment(text):
    values = read_environment(text)
    require(set(values) == {"CSRF_AUTH_KEY"} and len(values["CSRF_AUTH_KEY"]) >= 32,
            "Legacy environment differs from the reviewed configuration")
    return write_environment({**values, **SETTINGS})


def backup_configuration(text, unit):
    expected = copy.deepcopy(tomllib.loads(text))
    for section, label, old, new in (
        ("databases", "kitty", str(LEGACY / "kitty.db"), str(DATA / "kitty.db")),
        ("files", "kitty-configuration", str(LEGACY / ".env"), str(ENV)),
        ("files", "kitty-certificates", str(LEGACY / "cert"), str(CERTS)),
    ):
        entries = [item for item in expected[section] if item.get("label") == label]
        require(len(entries) == 1 and entries[0]["path"] == old and text.count(json.dumps(old)) == 1,
                "Unexpected Kitty backup source")
        require(not any(item["path"] == new for item in expected[section]), "Duplicate managed backup path")
        entries[0]["path"] = new
        text = text.replace(json.dumps(old), json.dumps(new), 1)
    require(tomllib.loads(text) == expected, "Unexpected backup configuration changes")
    lines = re.findall(r"(?m)^ReadWritePaths=(.*)$", unit)
    require(len(lines) == 1 and shlex.split(lines[0]).count(str(LEGACY)) == 1
            and unit.count(json.dumps(str(LEGACY))) == 1, "Unexpected backup SQLite-parent permission")
    return text, unit.replace(json.dumps(str(LEGACY)), json.dumps(str(DATA)), 1)


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args):
        return None


def request(url):
    outgoing = Request(url, headers={"User-Agent": "KittyDeploymentCheck/1.0", "Accept": "text/html"})
    try:
        response = build_opener(ProxyHandler({}), NoRedirect()).open(outgoing, timeout=20)
    except HTTPError as error:
        response = error
    with response:
        body = response.read(4 * 1024**2 + 1)
        require(len(body) <= 4 * 1024**2, "Unexpectedly large response")
        return response.status, response.headers, body


def check_http(origin, revision=None):
    if revision is not None:
        code, headers, body = request(origin + "/healthz")
        require(code == 200 and body.strip() == b"ok" and headers.get("X-Kitty-Revision") == revision,
                "Database/revision health check failed")
    for path in ("/", "/signin", "/signup"):
        code, _, body = request(origin + path)
        require(code == 200 and b"<html" in body.lower(), f"Page check failed: {path} HTTP {code}")
    code, _, body = request(origin + "/assets/js/passkeys.js")
    require(code == 200 and b"navigator.credentials" in body, "Passkey runtime asset check failed")


def certificate_identity(path):
    return hashlib.sha256(ssl.PEM_cert_to_DER_cert(path.read_text())).hexdigest()


def check_gemini(host, port, fingerprint, path="/"):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    # Gemini uses TOFU: compare the exact preserved identity, never silently trust a replacement.
    with socket.create_connection((host, port), timeout=15) as connection:
        with context.wrap_socket(connection, server_hostname=GEMINI_HOST) as tls:
            require(hashlib.sha256(tls.getpeercert(binary_form=True)).hexdigest() == fingerprint,
                    "Gemini certificate identity changed")
            tls.sendall(("gemini://" + GEMINI_HOST + path + "\r\n").encode())
            with tls.makefile("rb") as response:
                body = response.read(4 * 1024**2 + 1)
            require(len(body) <= 4 * 1024**2 and body.startswith(b"20 "), "Gemini request failed")
            return body


def process_identity(pid):
    require(type(pid) is int and pid > 1, "Invalid target process")
    process = Path("/proc") / str(pid)
    fields = (process / "stat").read_text().rsplit(") ", 1)[1].split()
    return {"pid": pid, "start": fields[19], "parent": int(fields[1]),
            "exe": os.readlink(process / "exe"), "cwd": os.readlink(process / "cwd"),
            "argv": (process / "cmdline").read_bytes().split(b"\0")[:-1]}


def stop_exact(identity, timeout=120):
    require(process_identity(identity["pid"]) == identity, "Process identity changed; refusing to signal")
    os.kill(identity["pid"], signal.SIGTERM)
    deadline = time.monotonic() + timeout
    while Path(f"/proc/{identity['pid']}").exists():
        try:
            fields = Path(f"/proc/{identity['pid']}/stat").read_text().rsplit(") ", 1)[1].split()
        except FileNotFoundError:
            return
        if fields[0] == "Z":
            return
        require(fields[19] == identity["start"], "Process ID was reused")
        require(time.monotonic() < deadline, "Process did not stop; no forced kill performed")
        time.sleep(0.1)


def maintenance_configuration(text, blocked_port):
    require(type(blocked_port) is int and 1024 < blocked_port < 65536, "Invalid maintenance endpoint")
    for old, replacement in (
        ("reverse_proxy :6835", 'respond "Kitty is temporarily down for maintenance." 503'),
        ("proxy localhost:19666", f"proxy 127.0.0.1:{blocked_port}"),
    ):
        pattern = r"(?m)^([ \t]*)" + re.escape(old) + r"[ \t]*$"
        require(len(re.findall(pattern, text)) == 1, "Kitty proxy differs from the reviewed configuration")
        text = re.sub(pattern, lambda match: match[1] + replacement, text)
    require(":6835" not in text and ":19666" not in text, "Another proxy still reaches legacy Kitty")
    return text


class Installer:
    def __init__(self, stage, system_root=Path("/")):
        self.stage = stage
        self.root = system_root / "opt/kitty"
        self.current = self.root / "current"
        self.data = system_root / DATA.relative_to("/")
        self.database = self.data / "kitty.db"
        self.environment = system_root / ENV.relative_to("/")
        self.certs = system_root / CERTS.relative_to("/")
        self.unit = system_root / "etc/systemd/system/kitty.service"
        self.legacy = system_root / LEGACY.relative_to("/")
        self.pending = self.root / "deployment-pending.json"
        self.backup_config = system_root / "etc/backuper/config.toml"
        self.backup_unit = system_root / "etc/systemd/system/backuper.service"
        self.checks = system_root / "var/lib/kitty-deploy-checks"

    def run(self, arguments, timeout=180, check=True):
        with (self.stage / "install.private.log").open("ab") as log:
            result = subprocess.run(arguments, stdout=subprocess.PIPE, stderr=log, timeout=timeout)
            if result.returncode and check:
                log.write(result.stdout)
                raise DeploymentError(f"{arguments[0]} failed; inspect the private receipt")
        return result.stdout.decode().strip()

    def record(self, status, **fields):
        path = self.stage / "deployment.json"
        result = json.loads(path.read_text()) if path.exists() else {}
        result.update(status=status, **fields)
        private_write(path, json.dumps(result, indent=2) + "\n")

    def switch(self, release):
        link = self.root / (".current-" + uuid.uuid4().hex)
        link.symlink_to(release)
        link.replace(self.current)
        sync_directory(self.root)

    def permissions(self):
        for suffix in ("", "-wal", "-shm"):
            path = Path(str(self.database) + suffix)
            if path.exists():
                require(path.is_file() and not path.is_symlink(), "Database path redirected")
                os.chown(path, self.user.pw_uid, self.user.pw_gid)
                path.chmod(0o600)

    def stop_service(self):
        self.run(["systemctl", "stop", "kitty.service"], timeout=150)
        require(self.run(["systemctl", "show", "kitty.service", "-p", "MainPID", "--value"]) == "0",
                "Kitty has not stopped; preserving current state")

    def require_recovery(self, message):
        self.run(["systemctl", "disable", "kitty.service"], check=False)
        raise DeploymentError(message + "; inspect deployment-pending.json")

    def check_process(self, release):
        require(self.run(["systemctl", "is-active", "kitty.service"]) == "active", "Kitty is not active")
        pid = int(self.run(["systemctl", "show", "kitty.service", "-p", "MainPID", "--value"]))
        require(Path(f"/proc/{pid}/exe").resolve() == release / "kitty"
                and Path(f"/proc/{pid}").stat().st_uid == self.user.pw_uid, "Unexpected executable/user")
        for port in (6835, 19666):
            listeners = self.run(["ss", "-ltnp", f"sport = :{port}"])
            require(f"127.0.0.1:{port}" in listeners and f"pid={pid}," in listeners
                    and f"*:{port}" not in listeners and f"[::]:{port}" not in listeners, "Unexpected listener")
        environment = dict(item.split(b"=", 1) for item in Path(f"/proc/{pid}/environ").read_bytes().split(b"\0")
                           if b"=" in item)
        require(all(environment.get(key.encode()) == value.encode()
                    for key, value in read_environment(self.environment.read_text()).items()),
                "Running environment differs from configuration")

    def wait_health(self, origin, revision):
        deadline = time.monotonic() + 30
        while True:
            try:
                code, headers, body = request(origin + "/healthz")
                if code == 200 and body.strip() == b"ok" and headers.get("X-Kitty-Revision") == revision:
                    return
            except (URLError, TimeoutError):
                pass
            require(time.monotonic() < deadline, "Kitty did not become healthy")
            time.sleep(0.25)

    @contextmanager
    def maintenance(self, legacy):
        if legacy is None:
            yield
            return
        path = Path("/etc/caddy/Caddyfile")
        original, mode = path.read_text(), path.stat().st_mode & 0o777
        with socket.socket() as blocked:
            blocked.bind(("127.0.0.1", 0))
            candidate = maintenance_configuration(original, blocked.getsockname()[1])
            private_write(self.stage / "Caddyfile.before", original)
            private_write(self.stage / "Caddyfile.maintenance", candidate)
            adapted = json.loads(self.run(["caddy", "adapt", "--config", str(path), "--adapter", "caddyfile"]))
            code, _, live = request("http://127.0.0.1:2019/config/")
            require(code == 200 and json.loads(live) == adapted, "Live/disk Caddy configuration differs")
            self.run(["caddy", "validate", "--config", str(self.stage / "Caddyfile.maintenance"), "--adapter", "caddyfile"])
            try:
                require(path.read_text() == original, "Caddy changed before maintenance")
                private_write(path, candidate)
                path.chmod(mode)
                self.run(["caddy", "reload", "--config", str(path), "--adapter", "caddyfile"])
                self.record("maintenance")
                deadline, stable_since, previous = time.monotonic() + 120, None, None
                while True:
                    require(process_identity(legacy["app"]["pid"]) == legacy["app"], "Legacy process changed during drain")
                    connections = self.run(["ss", "-Hnt", "state", "established", "( sport = :6835 or sport = :19666 )"])
                    digest = read_digest(self.legacy / "kitty.db")
                    if connections or digest != previous:
                        stable_since = time.monotonic()
                    elif stable_since is not None and time.monotonic() - stable_since >= 10:
                        break
                    previous = digest
                    require(time.monotonic() < deadline, "Legacy requests did not drain; leaving old app intact")
                    time.sleep(1)
                yield
            finally:
                require(path.read_text() in (candidate, original), "Caddy has operator changes; restore Kitty routes manually")
                private_write(path, original)
                path.chmod(mode)
                self.run(["caddy", "reload", "--config", str(path), "--adapter", "caddyfile"])
                code, _, live = request("http://127.0.0.1:2019/config/")
                require(code == 200 and json.loads(live) == adapted, "Caddy restoration mismatch")

    def preflight(self, release, revision, source, environment, certs):
        self.checks.mkdir(mode=0o711, exist_ok=True)
        self.checks.chmod(0o711)
        trial = Path(tempfile.mkdtemp(prefix="check-", dir=self.checks))
        name = "kitty-check-" + uuid.uuid4().hex
        started = False
        try:
            before = snapshot(source, trial / "kitty.db")
            shutil.copyfile(trial / "kitty.db", self.stage / "preflight.db")
            values = read_environment(environment)
            ports = []
            for _ in range(2):
                with socket.socket() as listener:
                    listener.bind(("127.0.0.1", 0))
                    ports.append(listener.getsockname()[1])
            require(ports[0] != ports[1], "Ephemeral listener collision; retry rehearsal")
            values.update(KITTY_DB_PATH=str(trial / "kitty.db"),
                          KITTY_HTTP_ADDR=f"127.0.0.1:{ports[0]}", KITTY_GEMINI_ADDR=f"127.0.0.1:{ports[1]}",
                          KITTY_GEMINI_CERT=str(trial / CERT_FILES[0]), KITTY_GEMINI_KEY=str(trial / CERT_FILES[1]))
            private_write(trial / "kitty.env", write_environment(values))
            for name_part in CERT_FILES:
                shutil.copyfile(certs / name_part, trial / name_part)
            for path in [trial, *trial.iterdir()]:
                os.chown(path, self.user.pw_uid, self.user.pw_gid)
                path.chmod(0o700 if path.is_dir() else 0o600)
            self.run([
                "systemd-run", "--quiet", "--collect", "--unit=" + name,
                "-p", "Type=exec", "-p", "User=kitty", "-p", "Group=kitty", "-p", "UMask=0077",
                "-p", "WorkingDirectory=" + str(release), "-p", "EnvironmentFile=" + str(trial / "kitty.env"),
                "-p", "NoNewPrivileges=true", "-p", "ProtectSystem=strict", "-p", "ProtectHome=true",
                "-p", "PrivateTmp=true", "-p", "PrivateDevices=true", "-p", "ReadWritePaths=" + str(trial),
                "-p", "TimeoutStopSec=120", "-p", "SendSIGKILL=no",
                "-p", "IPAddressDeny=any", "-p", "IPAddressAllow=localhost",
                "-p", "StandardOutput=append:" + str(self.stage / "preflight.private.log"),
                "-p", "StandardError=append:" + str(self.stage / "preflight.private.log"),
                str(release / "kitty"),
            ])
            started = True
            origin = f"http://127.0.0.1:{ports[0]}"
            self.wait_health(origin, revision)
            check_http(origin, revision)
            check_gemini("127.0.0.1", ports[1], certificate_identity(certs / CERT_FILES[0]))
            self.run(["systemctl", "stop", name])
            started = False
            require(read_digest(trial / "kitty.db") == before,
                    "Rehearsal changed database data/schema; review migration separately")
            self.record("preflight_passed", preflight_digest=before)
        finally:
            if started:
                self.run(["systemctl", "stop", name])
            shutil.rmtree(trial)

    def activate(self, release, revision, legacy):
        initial = legacy is not None
        previous = None if initial else self.current.resolve()
        before = {path: path.read_text() if path.exists() else None
                  for path in (self.environment, self.unit, self.backup_config, self.backup_unit)}
        cert_source = self.legacy / "cert" if initial else self.certs
        cert_hashes = {name: checksum(cert_source / name) for name in CERT_FILES}
        environment = managed_environment((self.legacy / ".env").read_text()) if initial else before[self.environment]
        backup_after = backup_configuration(before[self.backup_config], before[self.backup_unit]) if initial else None
        transaction = {"previous": str(previous) if previous else None, "release": str(release),
                       "initial": initial, "files_before": {str(path): value for path, value in before.items()},
                       "certificate_hashes": cert_hashes}
        private_write(self.stage / "transaction.json", json.dumps(transaction, indent=2))
        private_write(self.pending, json.dumps({"receipt": str(self.stage), **transaction}, indent=2))
        original_digest, legacy_stopped, changed = None, False, {}
        try:
            if initial:
                require(process_identity(legacy["app"]["pid"]) == legacy["app"]
                        and process_identity(legacy["wrapper"]["pid"]) == legacy["wrapper"], "Legacy process changed")
                stop_exact(legacy["wrapper"], timeout=15)
                identity = process_identity(legacy["app"]["pid"])
                require(all(identity[key] == legacy["app"][key] for key in ("pid", "start", "exe", "cwd", "argv")),
                        "Legacy app changed while wrapper stopped")
                stop_exact(identity)
                legacy_stopped = True
                original_digest = snapshot(self.legacy / "kitty.db", self.stage / "before.db")
                require(not self.database.exists(), "Managed database appeared concurrently")
                shutil.copyfile(self.stage / "before.db", self.database)
                require(read_digest(self.database) == original_digest, "Relocated database differs")
                self.certs.mkdir(mode=0o750)
                self.certs.chmod(0o750)
                os.chown(self.certs, 0, self.user.pw_gid)
                for name in CERT_FILES:
                    shutil.copyfile(cert_source / name, self.certs / name)
                    os.chown(self.certs / name, 0, self.user.pw_gid)
                    (self.certs / name).chmod(0o640)
                    with (self.certs / name).open("rb") as certificate:
                        os.fsync(certificate.fileno())
                sync_directory(self.certs)
                sync_directory(self.certs.parent)
                changed[self.environment] = environment
                changed[self.backup_config], changed[self.backup_unit] = backup_after
            else:
                self.stop_service()
                original_digest = snapshot(self.database, self.stage / "before.db")
            self.record("backed_up", original_digest=original_digest)
            changed[self.unit] = (release / "kitty.service").read_text()
            for path, contents in changed.items():
                require((path.read_text() if path.exists() else None) == before[path], "Configuration changed concurrently")
                private_write(path, contents)
                if path in (self.unit, self.backup_unit):
                    path.chmod(0o644)
            require(all(checksum(self.certs / name) == value for name, value in cert_hashes.items()), "Certificate copy differs")
            self.switch(release)
            self.permissions()
            with self.database.open("rb") as database:
                os.fsync(database.fileno())
            sync_directory(self.data)
            self.run(["systemctl", "daemon-reload"])
            self.run(["systemd-analyze", "verify", str(self.unit)])
            self.run(["systemctl", "start", "kitty.service"])
            self.wait_health("http://127.0.0.1:6835", revision)
            self.check_process(release)
            check_http("http://127.0.0.1:6835", revision)
            check_gemini("127.0.0.1", 19666, certificate_identity(self.certs / CERT_FILES[0]))
            self.run(["systemctl", "enable", "kitty.service"])
            self.record("healthy", revision=revision, release=str(release), data_relocation_verified=initial)
        except BaseException:
            self.record("needs_recovery", original_digest=original_digest)
            if initial and not legacy_stopped:
                raise DeploymentError("Legacy shutdown unconfirmed; preserve processes and inspect the pending receipt") from None
            try:
                self.stop_service()
            except Exception:
                self.require_recovery("Candidate shutdown unconfirmed; no rollback attempted")
            if original_digest is None or (self.database.exists() and read_digest(self.database) != original_digest):
                self.require_recovery("Data changed or snapshot failed; stopped and disabled without restoring old data")
            if not all((path.read_text() if path.exists() else None) in (changed.get(path, contents), contents)
                       for path, contents in before.items()):
                self.require_recovery("Operator configuration changed; no rollback attempted")
            if not all((self.certs / name).is_file() and checksum(self.certs / name) == value
                       for name, value in cert_hashes.items()):
                self.require_recovery("Certificate files changed; preserve identity and recover manually")
            for path in changed:
                if before[path] is None:
                    path.unlink(missing_ok=True)
                else:
                    private_write(path, before[path])
                    if path in (self.unit, self.backup_unit):
                        path.chmod(0o644)
            if previous:
                self.switch(previous)
            elif self.current.is_symlink():
                self.current.unlink()
            self.run(["systemctl", "daemon-reload"])
            if initial:
                require(read_digest(self.legacy / "kitty.db") == original_digest
                        and checksum(self.legacy / "kitty") == legacy["sha256"], "Legacy fallback changed; manual recovery required")
                self.run(["systemd-run", "--quiet", "--unit=kitty-legacy-rollback", "-p", "Type=exec",
                          "-p", "WorkingDirectory=" + str(self.legacy), "-p", "Restart=on-failure", str(self.legacy / "kitty")])
            else:
                self.permissions()
                self.run(["systemctl", "start", "kitty.service"])
                self.wait_health("http://127.0.0.1:6835", json.loads((previous / "release.json").read_text())["revision"])
                self.check_process(previous)
            self.record("rolled_back")
            self.pending.unlink()
            raise

    def install(self):
        require(os.geteuid() == 0, "Run remote installer as root")
        os.umask(0o077)
        require(not self.root.is_symlink() and not self.data.is_symlink()
                and not self.environment.parent.is_symlink(), "Managed directory was redirected")
        self.root.mkdir(mode=0o755, exist_ok=True)
        self.root.chmod(0o755)
        with (self.root / ".deploy.lock").open("a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            require(not self.pending.exists(), "Interrupted deployment requires recovery")
            require(os.path.ismount("/mnt/volume-hel1-1"), "Required data volume is not mounted")
            metadata = json.loads((self.stage / "request.json").read_text())
            initial = metadata["migrate_tmux"]
            require(initial == (not self.current.exists()), "Migration/update mode differs from live layout")
            legacy = None
            if initial:
                require(not any(path.exists() or path.is_symlink() for path in (
                    self.environment, self.certs, self.database, self.unit, self.current, self.root / "deployed.json")),
                    "Partial managed installation requires manual review")
                app, wrapper = process_identity(metadata["legacy_pid"]), process_identity(metadata["wrapper_pid"])
                require(app["exe"] == str(LEGACY / "kitty") and app["cwd"] == str(LEGACY)
                        and app["argv"] == [b"./kitty"] and app["parent"] == wrapper["pid"]
                        and wrapper["cwd"] == str(LEGACY) and wrapper["argv"] == [b"bash", b"run_forever.sh"],
                        "Legacy process/wrapper differs from reviewed deployment")
                require(checksum(Path(f"/proc/{app['pid']}/exe")) == metadata["legacy_sha256"], "Legacy binary changed")
                inherited = dict(item.split(b"=", 1) for item in Path(f"/proc/{app['pid']}/environ").read_bytes().split(b"\0")
                                 if b"=" in item)
                require(not any(key.startswith(b"KITTY_") or key in (b"CSRF_AUTH_KEY", b"GEMINI_PLAINTEXT")
                                for key in inherited), "Legacy has unreviewed environment overrides")
                legacy = {"app": app, "wrapper": wrapper, "sha256": metadata["legacy_sha256"]}
                source, certs = self.legacy / "kitty.db", self.legacy / "cert"
                environment = managed_environment((self.legacy / ".env").read_text())
                backup_configuration(self.backup_config.read_text(), self.backup_unit.read_text())
            else:
                require(self.current.is_symlink() and self.current.resolve().parent == self.root / "releases",
                        "Unrecognized current release")
                require(self.unit.read_bytes() == (self.current / "kitty.service").read_bytes()
                        and not self.run(["systemctl", "show", "kitty.service", "-p", "DropInPaths", "--value"]),
                        "Installed unit has operator changes")
                source, certs, environment = self.database, self.certs, self.environment.read_text()
                values = read_environment(environment)
                require(set(values) == {*SETTINGS, "CSRF_AUTH_KEY"} and len(values["CSRF_AUTH_KEY"]) >= 32
                        and all(values.get(key) == value for key, value in SETTINGS.items()), "Unsupported managed environment")
            require(not certs.is_symlink() and {path.name for path in certs.iterdir()} == set(CERT_FILES)
                    and all((certs / name).is_file() and not (certs / name).is_symlink() for name in CERT_FILES),
                    "Unexpected certificate directory contents")
            for path in (self.root, self.data.parent, self.environment.parent.parent):
                require(not path.is_symlink(), "Managed parent was redirected")
            require(shutil.disk_usage(self.root).free > source.stat().st_size * 5 + 512 * 1024**2
                    and shutil.disk_usage(self.data.parent).free > source.stat().st_size * 3 + 256 * 1024**2,
                    "Insufficient space for snapshots/release")
            require(checksum(self.stage / "release.tar") == metadata["archive_sha256"], "Upload checksum mismatch")
            unpacked = self.stage / "unpacked"
            unpacked.mkdir()
            extract(self.stage / "release.tar", unpacked)
            manifest = json.loads((unpacked / "release.json").read_text())
            revision, files = manifest["revision"], release_files(unpacked)
            require(re.fullmatch("[0-9a-f]{40}", revision) and manifest["architecture"] == platform.machine(),
                    "Invalid release revision/architecture")
            require(files == manifest["files"] and {"kitty", "kitty.service"} <= files.keys()
                    and all(name in ("kitty", "kitty.service") or name.startswith(("assets/", "templates/")) for name in files),
                    "Release manifest/runtime payload mismatch")
            releases = self.root / "releases"
            require(not releases.is_symlink(), "Releases directory was redirected")
            releases.mkdir(mode=0o755, exist_ok=True)
            releases.chmod(0o755)
            release = releases / (revision + "-" + files["kitty"][:12])
            if release.exists():
                require(release_files(release) == files, "Existing release differs")
            else:
                shutil.copytree(unpacked, release)
            for path in [release, *release.rglob("*")]:
                path.chmod(0o755 if path.is_dir() or path == release / "kitty" else 0o644)
                if path.is_file():
                    with path.open("rb") as content:
                        os.fsync(content.fileno())
            for path in sorted([release, *(path for path in release.rglob("*") if path.is_dir())],
                               key=lambda path: len(path.parts), reverse=True):
                sync_directory(path)
            sync_directory(releases)
            try:
                self.user = pwd.getpwnam("kitty")
            except KeyError:
                self.run(["useradd", "--system", "--user-group", "--no-create-home",
                          "--home-dir", "/var/lib/kitty", "--shell", "/usr/sbin/nologin", "kitty"])
                self.user = pwd.getpwnam("kitty")
            require(self.user.pw_uid != 0 and self.user.pw_dir == "/var/lib/kitty"
                    and self.user.pw_shell == "/usr/sbin/nologin", "Unexpected service account")
            self.data.mkdir(mode=0o700, exist_ok=True)
            os.chown(self.data, self.user.pw_uid, self.user.pw_gid)
            self.environment.parent.mkdir(mode=0o750, exist_ok=True)
            self.environment.parent.chmod(0o750)
            os.chown(self.environment.parent, 0, self.user.pw_gid)
            fingerprint = certificate_identity(certs / CERT_FILES[0])
            check_http(PUBLIC, None if initial else json.loads((self.current / "release.json").read_text())["revision"])
            check_gemini(GEMINI_HOST, 1965, fingerprint)
            if not initial and self.current.resolve() == release:
                self.check_process(release)
                require(self.run(["systemctl", "is-enabled", "kitty.service"]) == "enabled", "Service is not enabled")
                self.record("already_current", revision=revision, release=str(release))
                return
            watched = (self.environment, self.unit, self.backup_config, self.backup_unit,
                       *((self.legacy / ".env",) if initial else ()), *(certs / name for name in CERT_FILES))
            expected = {path: path.read_bytes() if path.exists() else None for path in watched}
            self.preflight(release, revision, source, environment, certs)
            require(all((path.read_bytes() if path.exists() else None) == value for path, value in expected.items()),
                    "Configuration/certificates changed during rehearsal")
            if metadata.get("rehearse"):
                self.record("rehearsal_complete", revision=revision, release=str(release))
                return
            with Path("/var/lib/backuper/job.lock").open("a") as backup_lock:
                fcntl.flock(backup_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                with self.maintenance(legacy):
                    require(all((path.read_bytes() if path.exists() else None) == value for path, value in expected.items()),
                            "Configuration/certificates changed before cutover")
                    self.activate(release, revision, legacy)
            check_http(PUBLIC, revision)
            check_gemini(GEMINI_HOST, 1965, fingerprint)
            self.record("verified_public")
            private_write(self.root / "deployed.json", (self.stage / "deployment.json").read_text())
            self.pending.unlink()


def ssh(host, arguments):
    return subprocess.run(["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=15",
                           "-o", "ServerAliveInterval=15", "-o", "ServerAliveCountMax=3",
                           host, shlex.join(arguments)], check=True)


def deploy(args):
    require(re.fullmatch("[A-Za-z0-9_][A-Za-z0-9_.@-]*", args.host), "Invalid SSH host")
    require(not args.migrate_tmux or (args.legacy_pid and args.wrapper_pid and args.legacy_sha256
            and re.fullmatch("[0-9a-f]{64}", args.legacy_sha256)), "Migration requires verified PIDs and binary SHA256")
    repository = Path(__file__).resolve().parents[1]

    def git(*arguments):
        return subprocess.check_output(["git", "-C", str(repository), *arguments], text=True).strip()

    require(not git("status", "--porcelain", "--untracked-files=no"), "Commit intended tracked changes first")
    revision = git("rev-parse", "HEAD")
    if not args.yes:
        require(input(f"Deploy {revision[:12]} to {args.host}, with a brief Kitty stop? [y/N] ").lower() == "y", "Cancelled")
    print("Only committed files are deployed; untracked files and local state are not included.", flush=True)
    with tempfile.TemporaryDirectory(prefix="kitty-deploy-") as directory:
        directory = Path(directory)
        source = directory / "source"
        source.mkdir()
        subprocess.run(["git", "-C", str(repository), "archive", "--format=tar",
                        "-o", str(directory / "source.tar"), revision], check=True)
        extract(directory / "source.tar", source)
        for tags in ("", "release"):
            subprocess.run(["go", "test", "-mod=readonly", "-tags", tags, "-count=1", "-timeout", "5m", "./..."],
                           cwd=source, check=True)
        subprocess.run([sys.executable, "-B", "-m", "unittest", "discover", "-s", "scripts", "-p", "test_deploy*.py"],
                       cwd=source, check=True)
        require(git("rev-parse", "HEAD") == revision and not git("status", "--porcelain", "--untracked-files=no"),
                "Tracked source changed during validation")
        architecture = {"x86_64": "amd64", "aarch64": "arm64"}.get(platform.machine())
        require(platform.system() == "Linux" and architecture, "Build on native Linux amd64 or arm64")
        payload = directory / "payload"
        payload.mkdir()
        subprocess.run(["go", "build", "-mod=readonly", "-trimpath", "-buildvcs=false", "-tags", "release",
                        "-ldflags", "-X main.buildRevision=" + revision, "-o", str(payload / "kitty"), "."],
                       cwd=source, env={**os.environ, "CGO_ENABLED": "1", "CC": "/usr/bin/gcc",
                                       "GOOS": "linux", "GOARCH": architecture}, check=True)
        for name in ("assets", "templates"):
            shutil.copytree(source / name, payload / name)
        shutil.copyfile(source / "deploy/kitty.service", payload / "kitty.service")
        (payload / "release.json").write_text(json.dumps({
            "revision": revision, "architecture": platform.machine(), "files": release_files(payload)}, indent=2))
        archive = directory / "release.tar"
        with tarfile.open(archive, "w") as output:
            for path in sorted(payload.iterdir()):
                output.add(path, arcname=path.name)
        metadata = {"archive_sha256": checksum(archive), "migrate_tmux": args.migrate_tmux,
                    "rehearse": args.rehearse, "legacy_pid": args.legacy_pid,
                    "wrapper_pid": args.wrapper_pid, "legacy_sha256": args.legacy_sha256}
        (directory / "request.json").write_text(json.dumps(metadata))
        identifier = uuid.uuid4().hex
        stage = "/root/kitty-deploy-backups/update-" + identifier
        ssh(args.host, ["install", "-d", "-m", "0700", stage])
        print("Private deployment receipt: " + stage, flush=True)
        subprocess.run(["scp", "-q", str(archive), str(directory / "request.json"), str(directory / "source.tar"),
                        str(source / "scripts/deploy_vps.py"), args.host + ":" + stage + "/"], check=True)
        ssh(args.host, [
            "systemd-run", "--quiet", "--wait", "--collect", "--unit=kitty-deploy-" + identifier,
            "-p", "Type=oneshot", "-p", "TimeoutStartSec=infinity", "-p", "UMask=0077",
            "-p", "StandardOutput=append:" + stage + "/install.private.log",
            "-p", "StandardError=append:" + stage + "/install.private.log",
            "/usr/bin/python3", "-B", stage + "/deploy_vps.py", "--install", stage,
        ])
        print("Kitty operation completed; inspect " + stage + "/deployment.json", flush=True)


def main():
    if sys.argv[1:2] == ["--install"]:
        require(len(sys.argv) == 3 and re.fullmatch("/root/kitty-deploy-backups/update-[0-9a-f]{32}", sys.argv[2]),
                "Invalid receipt path")
        installer = Installer(Path(sys.argv[2]))
        try:
            installer.install()
        except BaseException:
            if installer.pending.exists():
                installer.record("needs_recovery")
            elif not (installer.stage / "deployment.json").exists():
                installer.record("failed")
            raise
        return
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("host", nargs="?", default="meadow-ubuntu-8gb-hel1-1")
    parser.add_argument("--yes", action="store_true")
    parser.add_argument("--migrate-tmux", action="store_true")
    parser.add_argument("--legacy-pid", type=int)
    parser.add_argument("--wrapper-pid", type=int)
    parser.add_argument("--legacy-sha256")
    parser.add_argument("--rehearse", action="store_true", help="Run only isolated production-copy startup checks")
    deploy(parser.parse_args())


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        detail = str(error) if isinstance(error, DeploymentError) else type(error).__name__
        print("Deployment failed: " + detail + "; inspect the private receipt before retrying", file=sys.stderr)
        raise SystemExit(1)
