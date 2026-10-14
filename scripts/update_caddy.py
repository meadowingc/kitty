"""Pinned, independently installed Caddy/layer4 updates with guarded recovery."""

import argparse
from contextlib import contextmanager
import fcntl
import hashlib
import http.client
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import socket
import ssl
import stat
import subprocess
import sys
import tempfile
import time
from urllib.request import ProxyHandler, Request, build_opener
import uuid


PUBLIC_HOSTS = ("guestbooks", "kite", "after", "ntfy-3242", "mire", "mochi",
                "readeck", "aether", "kitty", "podslice", "aviary-console", "backuper-info")
GEMINI_HOSTS = ("gmi.meadow.cafe", "gmi.kitty.meadow.cafe")
BUILD_FILES = ("main.go", "go.mod", "go.sum")


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def checksum(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def write_json(path, value):
    fd, name = tempfile.mkstemp(prefix=".receipt-", dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(fd, "w") as output:
            json.dump(value, output, sort_keys=True, indent=2)
            output.flush()
            os.fsync(output.fileno())
        temporary.replace(path)
        sync_directory(path.parent)
    finally:
        temporary.unlink(missing_ok=True)


def manifest(path):
    if not path.exists() and not path.is_symlink():
        return None
    record = path.lstat()
    require(stat.S_ISDIR(record.st_mode) or stat.S_ISREG(record.st_mode),
            "Symlinks/special files require separate review: " + str(path))
    value = {"uid": record.st_uid, "gid": record.st_gid, "mode": stat.S_IMODE(record.st_mode)}
    if path.is_dir():
        value["children"] = {item.name: manifest(item) for item in sorted(path.iterdir())}
    else:
        require(record.st_nlink == 1, "Hardlinked file requires separate review: " + str(path))
        value["sha256"] = checksum(path)
    return value


def snapshot(source, destination):
    before = manifest(source)
    shutil.copytree(source, destination, copy_function=shutil.copy2)
    for path in [destination, *destination.rglob("*")]:
        relative = path.relative_to(destination)
        original = source / relative
        metadata = original.stat()
        os.chown(path, metadata.st_uid, metadata.st_gid)
        path.chmod(stat.S_IMODE(metadata.st_mode))
        if path.is_file():
            with path.open("rb") as saved:
                os.fsync(saved.fileno())
    for path in sorted((p for p in destination.rglob("*") if p.is_dir()), reverse=True):
        sync_directory(path)
    sync_directory(destination)
    sync_directory(destination.parent)
    require(manifest(source) == before and manifest(destination) == before,
            "State changed during capture; no activation")
    return before


@contextmanager
def locks(root):
    descriptors = []
    try:
        backup = root / "var/lib/backuper/job.lock"
        require(backup.is_file() and not backup.is_symlink(), "Existing backup lock required")
        descriptors.append(os.open(backup, os.O_RDONLY | os.O_NOFOLLOW))
        fcntl.flock(descriptors[-1], fcntl.LOCK_EX | fcntl.LOCK_NB)
        directory = root / "var/lib/caddy-updates"
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        require(directory.is_dir() and not directory.is_symlink()
                and directory.stat().st_uid == os.geteuid()
                and stat.S_IMODE(directory.stat().st_mode) == 0o700, "Unsafe receipt directory")
        sync_directory(directory.parent)
        descriptors.append(os.open(directory / "update.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600))
        fcntl.flock(descriptors[-1], fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def build_pins(directory):
    module = (directory / "go.mod").read_text()
    require("replace" not in module and "exclude" not in module, "Module overrides require separate review")
    versions = dict(re.findall(r"^\s*([a-zA-Z0-9./_-]+)\s+(v[^\s]+)", module, re.MULTILINE))
    compiler = re.search(r"^go ([0-9]+\.[0-9]+\.[0-9]+)$", module, re.MULTILINE)
    require(compiler and "github.com/caddyserver/caddy/v2" in versions
            and "github.com/mholt/caddy-l4" in versions, "Exact compiler/Caddy/layer4 pins required")
    return "go" + compiler[1], versions


class Updater:
    service = "caddy.service"

    def __init__(self, root=Path("/"), build=None):
        self.root = root
        self.binary = root / "usr/bin/caddy"
        self.config = root / "etc/caddy/Caddyfile"
        self.data = root / "var/lib/caddy"
        self.receipts = root / "var/lib/caddy-updates"
        self.pending = self.receipts / "pending.json"
        self.installed = self.receipts / "installed.json"
        self.build = build or Path(__file__).resolve().parent / "caddy-build"
        self.go = root / "root/.local/share/mise/installs/go/1.25.6/bin/go"
        self.workspace = root / "mnt/volume-hel1-1/caddy-update-build"
        self.stage = None
        self.transaction = None

    def run(self, command, **kwargs):
        result = subprocess.run(command, capture_output=True, timeout=kwargs.pop("timeout", 60), **kwargs)
        if self.stage:
            with (self.stage / "operations.private.log").open("ab") as log:
                log.write(result.stdout + result.stderr)
        require(result.returncode == 0, command[0] + " failed; inspect private updater receipt")
        return result.stdout.decode().strip()

    def property(self, name):
        return self.run(["systemctl", "show", self.service, "-p", name, "--value"])

    def configuration(self):
        require(not self.property("DropInPaths") and not self.property("Environment")
                and not self.property("EnvironmentFiles"), "Caddy overrides require separate review")
        fragment = Path(self.property("FragmentPath"))
        require(fragment == self.root / "usr/lib/systemd/system/caddy.service",
                "Unexpected Caddy unit")
        require(self.property("User") == "caddy" and self.property("Group") == "caddy",
                "Unexpected Caddy service identity")
        return {str(path): manifest(path) for path in (
            self.config.parent, fragment, self.root / "usr/local/lib/caddy-update")}

    def runtime(self):
        pid = int(self.property("MainPID") or "0")
        require(pid > 1 and self.property("ActiveState") == "active", "Caddy not active")
        process = self.root / "proc" / str(pid)
        require((process / "exe").resolve() == self.binary
                and process.stat().st_uid == pwd.getpwnam("caddy").pw_uid, "Unexpected running Caddy process")
        require(checksum(process / "exe") == checksum(self.binary), "Disk/running Caddy binaries differ")
        arguments = (process / "cmdline").read_bytes().split(b"\0")
        require(b"--config" in arguments
                and arguments[arguments.index(b"--config") + 1] == str(self.config).encode()
                and b"--resume" not in arguments, "Uncovered Caddy runtime configuration")
        environment = dict(item.split(b"=", 1) for item in (process / "environ").read_bytes().split(b"\0")
                           if b"=" in item)
        require(environment.get(b"HOME") == str(self.data).encode()
                and not any(key.startswith(b"XDG_") for key in environment),
                "Caddy storage overrides require separate review")
        return pid

    def adapted(self, binary=None):
        configuration = json.loads(self.run([str(binary or self.binary), "adapt", "--config", str(self.config)]))
        certificates = configuration.get("apps", {}).get("tls", {}).get("certificates", {})
        require(not configuration.get("storage")
                and isinstance(certificates, dict) and set(certificates) <= {"automate"}
                and isinstance(certificates.get("automate", []), list)
                and all(isinstance(name, str) and name and not any(char in name for char in "{}")
                        for name in certificates.get("automate", [])),
                "Custom storage/certificate loaders require separately reviewed coverage")
        return configuration

    def live(self):
        with build_opener(ProxyHandler({})).open("http://127.0.0.1:2019/config/", timeout=5) as response:
            return json.load(response)

    def probe(self, configuration):
        result = {}
        hosts = {host for server in configuration["apps"]["http"]["servers"].values()
                 for route in server.get("routes", []) for match in route.get("match", [])
                 for host in match.get("host", []) if "*" not in host}
        hosts.update(host + ".meadow.cafe" for host in PUBLIC_HOSTS)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        for host in sorted(hosts):
            path = "/manifest.json" if host == "post-audios.meadow.cafe" else "/"
            with socket.create_connection(("127.0.0.1", 443), timeout=10) as connection:
                with context.wrap_socket(connection, server_hostname=host) as tls:
                    tls.settimeout(10)
                    identity = hashlib.sha256(tls.getpeercert(binary_form=True)).hexdigest()
                    tls.sendall(("GET " + path + " HTTP/1.1\r\nHost: " + host
                                 + "\r\nConnection: close\r\n\r\n").encode())
                    response = http.client.HTTPResponse(tls)
                    response.begin()
                    require(response.status < 500, "Origin route failed: " + host)
                    result["origin:" + host] = {"status": response.status, "certificate": identity}
                    response.close()
        for host in GEMINI_HOSTS:
            with socket.create_connection(("127.0.0.1", 1965), timeout=10) as connection:
                with context.wrap_socket(connection, server_hostname=host) as tls:
                    tls.settimeout(10)
                    identity = hashlib.sha256(tls.getpeercert(binary_form=True)).hexdigest()
                    tls.sendall(("gemini://" + host + "/\r\n").encode())
                    with tls.makefile("rb") as incoming:
                        header = incoming.readline(1024)
                        body = incoming.read(2 * 1024 * 1024 + 1)
                    require(header.startswith(b"20 ") and len(body) <= 2 * 1024 * 1024,
                            "Gemini route failed: " + host)
                    result["gemini:" + host] = {"certificate": identity,
                                               "body_sha256": hashlib.sha256(body).hexdigest()}
        opener = build_opener(ProxyHandler({}))
        for host in PUBLIC_HOSTS:
            with opener.open(Request("https://" + host + ".meadow.cafe/",
                                     headers={"User-Agent": "MeadowCaddyUpdate/1.0"}), timeout=20) as response:
                require(response.status == 200, "Public route failed: " + host)
                result["public:" + host] = response.status
        return result

    def healthy(self, configuration, routes=None):
        pid = self.runtime()
        require(self.adapted() == configuration == self.live(), "Disk/live Caddy routing differs")
        actual = self.probe(configuration)
        require(routes is None or actual == routes, "HTTP/Gemini routing or identity changed")
        return pid, actual

    def wait_healthy(self, configuration, routes):
        for attempt in range(10):
            try:
                return self.healthy(configuration, routes)
            except (OSError, RuntimeError, http.client.HTTPException):
                if attempt == 9:
                    raise
                time.sleep(2)

    def verify_build(self, binary):
        compiler, versions = build_pins(self.build)
        metadata = self.run([str(binary), "build-info"])
        lines = [line.split() for line in metadata.splitlines()]
        require(["go", compiler] in lines, "Unexpected Caddy compiler")
        sums = set((self.build / "go.sum").read_text().splitlines())
        dependencies = {line[1]: line[2] for line in lines if line and line[0] == "dep"}
        require(all(dependencies.get(name) == versions[name]
                    for name in ("github.com/caddyserver/caddy/v2", "github.com/mholt/caddy-l4")),
                "Caddy/layer4 pin mismatch")
        require(not any(line and line[0] == "=>" for line in lines), "Unreviewed dependency replacements")
        for line in lines:
            if line and line[0] == "dep":
                require(len(line) == 4 and versions.get(line[1]) == line[2]
                        and " ".join(line[1:]) in sums, "Dependency differs from reviewed lock")
        settings = {line[1].split("=", 1)[0]: line[1].split("=", 1)[1]
                    for line in lines if line and line[0] == "build" and "=" in line[1]}
        require(all(settings.get(key) == value for key, value in {
            "CGO_ENABLED": "0", "GOOS": "linux", "GOARCH": "amd64", "GOAMD64": "v1",
            "-tags": "nobadger,nomysql,nopgx", "-trimpath": "true",
            "-compiler": "gc", "-buildmode": "exe"}.items())
                and not settings.get("GOEXPERIMENT") and not settings.get("-race"),
            "Unexpected Caddy build settings")
        modules = self.run([str(binary), "list-modules"]).splitlines()
        require(all(name in modules for name in ("layer4", "layer4.handlers.proxy", "layer4.matchers.tls")),
                "Required layer4 modules missing")

    def validate(self, binary, configuration):
        require(self.adapted(binary) == configuration, "Candidate changes adapted routing")
        user = pwd.getpwnam("caddy")
        directory = Path(tempfile.mkdtemp(prefix="caddy-update-validation-", dir=self.root / "var/tmp"))
        try:
            os.chown(directory, user.pw_uid, user.pw_gid)
            directory.chmod(0o700)
            candidate = directory / "caddy"
            shutil.copyfile(binary, candidate)
            candidate.chmod(0o755)
            environment = dict(os.environ, HOME=str(directory),
                               XDG_DATA_HOME=str(directory / "data"), XDG_CONFIG_HOME=str(directory / "config"))
            self.run(["runuser", "-u", "caddy", "--", str(candidate), "validate",
                      "--config", str(self.config)], env=environment)
        finally:
            shutil.rmtree(directory)

    def build_files(self):
        return {name: checksum(self.build / name) for name in BUILD_FILES}

    def compile(self):
        require(os.path.ismount(self.workspace.parent), "Mounted build volume required")
        require(shutil.disk_usage(self.workspace.parent).free >= 3 * 1024 ** 3,
                "Insufficient build/backup headroom")
        compiler, _ = build_pins(self.build)
        environment = dict(os.environ, GOTOOLCHAIN="local", CGO_ENABLED="0", GOOS="linux",
                           GOARCH="amd64", GOAMD64="v1", GOEXPERIMENT="", GOFLAGS="",
                           GOWORK="off", GOENV="off")
        require(self.run([str(self.go), "version"], env=environment)
                == "go version " + compiler + " linux/amd64", "Reviewed compiler required")
        self.workspace.mkdir(mode=0o700, exist_ok=True)
        require(not self.workspace.is_symlink() and self.workspace.stat().st_uid == 0,
                "Unsafe build workspace")
        directory = self.workspace / self.stage.name
        directory.mkdir(mode=0o700)
        for name in BUILD_FILES:
            shutil.copyfile(self.build / name, directory / name)
        candidate = self.stage / "candidate"
        environment.update(GOCACHE=str(self.workspace / "cache"), GOMODCACHE=str(self.workspace / "modules"))
        try:
            self.run([str(self.go), "build", "-mod=readonly", "-buildvcs=false", "-trimpath",
                      "-tags=nobadger,nomysql,nopgx", "-o", str(candidate), "."],
                     cwd=directory, env=environment, timeout=1800)
            require({name: checksum(directory / name) for name in BUILD_FILES} == self.build_files(),
                    "Build inputs changed")
            self.verify_build(candidate)
            return candidate
        finally:
            shutil.rmtree(directory)

    def stop(self):
        pid = int(self.property("MainPID") or "0")
        if pid:
            require((self.root / "proc" / str(pid) / "exe").resolve() == self.binary,
                    "Unreviewed service process; no stop attempted")
        self.run(["systemctl", "stop", self.service], timeout=120)
        require(self.property("MainPID") == "0" and self.property("ActiveState") in ("inactive", "failed"),
                "Caddy stop unconfirmed")
        group = self.property("ControlGroup")
        if group:
            require(group.startswith("/") and ".." not in Path(group).parts, "Unsafe service cgroup")
            parent = self.root / "sys/fs/cgroup" / group.lstrip("/")
            require(all(not path.read_text().strip() for path in parent.rglob("cgroup.procs")),
                    "Caddy descendants remain")

    def replace(self, source):
        require(manifest(self.binary) is not None, "Current binary missing")
        temporary = self.binary.parent / (".caddy-" + uuid.uuid4().hex)
        try:
            shutil.copyfile(source, temporary)
            os.chown(temporary, 0, 0)
            temporary.chmod(0o755)
            with temporary.open("rb") as binary:
                os.fsync(binary.fileno())
            temporary.replace(self.binary)
            sync_directory(self.binary.parent)
        finally:
            temporary.unlink(missing_ok=True)

    def record(self, status):
        self.transaction["status"] = status
        write_json(self.stage / "transaction.json", self.transaction)

    def recover(self):
        t = self.transaction
        if not t["activated"]:
            require(not t.get("stop_attempted") or t.get("stopped"), "Stop unconfirmed; manual recovery required")
            require(manifest(self.binary) == t["binary_before"] and self.configuration() == t["configuration"],
                    "Pre-activation operator edits; manual recovery required")
            if t.get("stopped"):
                self.run(["systemctl", "start", self.service], timeout=120)
                self.wait_healthy(t["routing"], t["routes"])
            self.record("aborted_before_activation")
            self.pending.unlink()
            sync_directory(self.receipts)
            return
        self.stop()
        require(self.configuration() == t["configuration"] and manifest(self.data) == t["state_before"]
                and manifest(self.binary) == t["candidate_record"]
                and checksum(self.stage / "binary.before") == t["binary_before"]["sha256"],
                "Storage/configuration/binary changed; no automatic rollback")
        self.replace(self.stage / "binary.before")
        self.run(["systemctl", "start", self.service], timeout=120)
        self.wait_healthy(t["routing"], t["routes"])
        self.record("rolled_back_binary_only_state_unchanged")
        self.pending.unlink()
        sync_directory(self.receipts)

    def activate(self, candidate, routing, routes, configuration):
        self.transaction = {"activated": False, "routing": routing, "routes": routes,
                            "configuration": configuration, "binary_before": manifest(self.binary)}
        saved = self.stage / "binary.before"
        shutil.copy2(self.binary, saved)
        with saved.open("rb") as binary:
            os.fsync(binary.fileno())
        sync_directory(self.stage)
        write_json(self.pending, {"receipt": str(self.stage)})
        self.record("preparing")
        try:
            self.transaction["stop_attempted"] = True
            self.stop()
            self.transaction["stopped"] = True
            self.transaction["state_before"] = snapshot(self.data, self.stage / "state.before")
            snapshot(self.config.parent, self.stage / "configuration.before")
            require(self.configuration() == configuration
                    and manifest(self.binary) == self.transaction["binary_before"],
                    "Operator edits before activation")
            self.record("stopped_complete_state_captured")
            self.transaction["activated"] = True
            self.record("switching_candidate")
            self.replace(candidate)
            self.transaction["candidate_record"] = manifest(self.binary)
            self.record("starting_candidate")
            self.run(["systemctl", "start", self.service], timeout=120)
            self.wait_healthy(routing, routes)
            require(self.configuration() == configuration
                    and manifest(self.binary) == self.transaction["candidate_record"],
                    "Operator edits during activation")
            self.record("verified_all_routes")
            self.pending.unlink()
            sync_directory(self.receipts)
        except BaseException:
            try:
                self.recover()
            except BaseException as recovery_error:
                try:
                    self.stop()
                except (OSError, RuntimeError, subprocess.SubprocessError) as stop_error:
                    self.record("manual_recovery_required_stop_unconfirmed")
                    raise RuntimeError("Caddy recovery stop unconfirmed; inspect " + str(self.stage)) from stop_error
                self.record("manual_recovery_required_current_state_preserved")
                raise RuntimeError("Caddy recovery requires review; inspect " + str(self.stage)) from recovery_error
            raise

    def execute(self, check_current=False):
        require(not self.pending.exists(), "Unresolved Caddy recovery; inspect " + str(self.pending))
        configuration = self.configuration()
        routing = self.adapted()
        pid, routes = self.healthy(routing)
        if check_current:
            return {"status": "verified_current", "pid": pid, "binary_sha256": checksum(self.binary)}
        require(self.installed.is_file(), "Reviewed current-binary baseline required")
        installed = json.loads(self.installed.read_text())
        inputs = self.build_files()
        if installed["build_files"] == inputs and installed["binary_sha256"] == checksum(self.binary):
            self.verify_build(self.binary)
            return {"status": "already_current", "pid": pid, "binary_sha256": checksum(self.binary)}
        require(installed["binary_sha256"] == checksum(self.binary), "Unreviewed current binary; refusing deployment")
        self.stage = self.receipts / ("update-" + uuid.uuid4().hex)
        self.stage.mkdir(mode=0o700)
        sync_directory(self.receipts)
        write_json(self.stage / "preparation.json", {"build_files": inputs, "pid_before": pid,
                                                  "configuration": configuration, "routing": routing, "routes": routes})
        candidate = self.compile()
        self.validate(candidate, routing)
        require(self.configuration() == configuration and self.build_files() == inputs,
                "Configuration/build inputs changed during preparation")
        self.healthy(routing, routes)
        self.activate(candidate, routing, routes, configuration)
        write_json(self.installed, {"build_files": inputs, "binary_sha256": checksum(self.binary),
                                   "receipt": str(self.stage)})
        return {"status": "verified_updated", "receipt": str(self.stage)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check-current", action="store_true", help="Check real routes without building or restarting")
    args = parser.parse_args()
    require(os.geteuid() == 0, "Run the independently installed updater as root")
    os.umask(0o077)
    with locks(Path("/")):
        result = Updater().execute(args.check_current)
    print(json.dumps(result))


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, subprocess.SubprocessError, http.client.HTTPException) as error:
        print("Caddy update failed: " + str(error), file=sys.stderr)
        sys.exit(1)
