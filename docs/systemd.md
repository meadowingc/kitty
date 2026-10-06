# VPS deployment

Kitty's HTTP and Gemini listeners belong to one foreground process and one
`kitty.service`. Caddy continues terminating HTTPS and routing Gemini TLS by SNI.
Do not run `run_forever.sh` alongside the service or rebuild Caddy during a Kitty
update. Caddy's existing updater is a separate infrastructure operation.

## Update

From a Linux checkout with Go 1.25 or newer, a system C compiler and Python 3.11+:

```sh
git pull --ff-only
python3 scripts/deploy_vps.py meadow-ubuntu-8gb-hel1-1 --yes
```

Commit and publish intended changes first. Only the committed `git archive`
snapshot is built; untracked files, `.env`, databases and private certificates
are never shipped. An untracked personal README can stay untouched. Tracked
uncommitted changes are rejected. The updater runs debug/release tests (including
the existing browser suite), deployment safety tests and a native release build.
Chromium must be available to the existing Rod browser test launcher.

Each update stages an immutable, checksummed release and rehearses it against a
disposable SQLite backup under a dedicated user with external networking denied.
A rehearsal changing the schema or existing rows is refused: a data migration
needs a separate compatibility review. The updater then stops both listeners,
backs up committed SQLite state, switches the release, verifies HTTP and native
Gemini (including the preserved certificate identity), and enables boot startup.
Repeating the same healthy release is a no-op.

## Layout

| Purpose | Path |
| --- | --- |
| Current release, binary, templates and assets | `/opt/kitty/current` |
| Immutable releases | `/opt/kitty/releases/` |
| Live SQLite database and journals | `/mnt/volume-hel1-1/kitty-state/kitty.db` |
| Private runtime environment | `/etc/kitty/kitty.env` |
| Preserved Gemini certificate and key | `/etc/kitty/cert/` |
| Unit | `/etc/systemd/system/kitty.service` |
| Private deployment receipts and snapshots | `/root/kitty-deploy-backups/` |
| Last verified deployment | `/opt/kitty/deployed.json` |

The unit requires the mounted volume and existing database/certificates. It runs
as `kitty`, with only the state directory writable. Caddy connects to
`127.0.0.1:6835` for HTTP and `127.0.0.1:19666` for Gemini; public Gemini remains
on port 1965. The RP origin, CSRF secret, session records, certificate/private key
and public URLs do not change. Backuper must select the managed database, runtime
configuration and complete certificate directory.

`KITTY_DB_PATH`, `KITTY_HTTP_ADDR`, `KITTY_GEMINI_ADDR`, `KITTY_GEMINI_CERT` and
`KITTY_GEMINI_KEY` override development paths/listeners. Production additionally
sets `KITTY_REQUIRE_DATABASE=true` and `KITTY_REQUIRE_TLS=true`: a missing database
must not bootstrap an empty site, and missing certificates must not downgrade
Gemini to plaintext. Existing development defaults remain available.

On SIGTERM/SIGINT the app stops accepting requests, drains HTTP and Gemini, waits
for accepted backlink work and only then closes SQLite. Gemini connections have
a 30-second deadline. The unit does not force-kill an overdue shutdown; the
updater refuses to switch a still-running process. Investigate such a stop
instead of killing a database writer or launching another instance.

## Initial conversion

Initial conversion is operator-only. Capture the exact source revision, live
binary hash, process identities, configuration, database and certificate
fingerprint first. The command requires both the application and wrapper PIDs:

```sh
python3 scripts/deploy_vps.py HOST --migrate-tmux \
  --legacy-pid APP_PID --wrapper-pid WRAPPER_PID \
  --legacy-sha256 VERIFIED_BINARY_SHA256 --rehearse --yes
```

Run isolated authenticated/browser acceptance against the staged release before
rerunning without `--rehearse`. The installer temporarily takes only Kitty's
HTTP/Gemini proxy routes out of service, drains old connections and waits for
stable database contents before stopping the exact old wrapper/application.
The drain allows up to five minutes, including Caddy's idle backend connection
timeout; a timeout restores routing and leaves the old processes untouched.
It does not stop tmux or the interactive shell. It retains the old installation,
copies SQLite with the backup API, verifies complete logical equality, preserves
the secret/certificate identity, and changes only Kitty's Backuper sources and
SQLite-parent write permission under the backup lock. Original Caddy configuration
is restored, with both public protocols checked afterward.

## Failure and recovery

The remote installer runs as a durable transient systemd unit. An SSH disconnect
does not establish failure: check its unit and the printed private receipt
before retrying. Logs and `transaction.json` can contain private configuration;
do not post them publicly.

`/opt/kitty/deployment-pending.json` blocks another deployment until an incomplete
operation is reviewed. A prior binary is selected automatically only when the
complete database, watched configuration and certificate files are unchanged.
No old database is restored over accepted writes. Changed/uncertain state leaves
Kitty stopped and disabled for explicit recovery, preserving snapshots and live
data. A public-probe failure after local activation leaves the pending receipt
for investigation rather than guessing that accepted writes can be rolled back.

An initial safe fallback starts the exact old binary in a separate transient
unit, never the auto-pull/build wrapper. A partial initial installation still
needs review before another migration; do not delete state or pending markers
blindly. Preserve certificate keys and the original CSRF secret during recovery.

After deployment, verify a deliberate restart, production-copy authenticated
workflows, public HTTP/RSS and native Gemini, unchanged unrelated services, and
fresh full restores from both configured backup destinations. A VPS reboot is
a separate operator-approved check.
