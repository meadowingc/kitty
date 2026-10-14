# Independent Caddy infrastructure updates

These files are maintained here alongside the historical Caddy helper, but
installed independently of Kitty. A Kitty application update must never install,
build, restart or update Caddy. The old `update-caddy-l4.sh` now delegates to the
separately installed `/usr/local/sbin/update-caddy-l4`, or fails explicitly if it
is absent.
Retained historical VPS source/recovery copies are not canonical entrypoints;
do not run their old build script with `bash`.

`caddy-build/main.go`, `go.mod` and `go.sum` lock the custom executable's source,
compiler, Caddy, layer4 and transitive dependency versions. The initial lock
matches the running Caddy v2.10.2 / layer4
v0.0.0-20260127203130-040d25cc886a / Go1.25.6 deployment. There is no `@latest`
download, automatic source pull or automatic choice of a newer version.

Install reviewed tooling under `/usr/local/lib/caddy-update/`, with the locked
build in its `caddy-build/` subdirectory, and the `update-caddy` wrapper as
`/usr/local/sbin/update-caddy-l4`. Files are root-owned, directories mode0755,
Python/Go inputs mode0644 and the wrapper mode0755. Python3.12+ is required.
Keep the packaged `caddy.service` and existing `/usr/bin/caddy` intact.

Before enabling the timer, create a root-private tooling receipt and seed
`/var/lib/caddy-updates/installed.json` only after verifying the actual running
binary, exact locked dependencies, current disk/live configuration and routes:

```json
{
  "build_files": {
    "main.go": "<reviewed SHA256>",
    "go.mod": "<reviewed SHA256>",
    "go.sum": "<reviewed SHA256>"
  },
  "binary_sha256": "<actual unchanged /usr/bin/caddy SHA256>"
}
```

Do not seed a changed binary as healthy to bypass a failed update. Existing
`pending.json` requires explicit review, not deletion followed by a retry.

Install `deploy/caddy-update.service` and `.timer` independently of the Caddy
service. Remove only the exact historical Caddy root-cron entry after preserving
the crontab in a receipt. The timer keeps day12 at03:00UTC monthly, is persistent,
and logs success/failure to the journal. A new timer is not an application
upgrade: unchanged pins and actual binary produce a checked PID-preserving
no-op without invoking Go or downloading anything.

Keep Backuper's existing Caddy binary, TLS storage and Caddyfile selections.
Also select Caddy's autosave directory, the installed updater library/entrypoint,
both new units and `installed.json`; the source profile in Backuper includes
these paths. Preserve backup settings, destinations, encryption and retention.
Deployment receipts remain private local recovery artifacts, not automatic
replacement sources.

```sh
sudo /usr/local/sbin/update-caddy-l4 --check-current
sudo systemctl start caddy-update.service
sudo journalctl -u caddy-update.service --no-pager
```

For a future approved version change, review and update the locked module with
the Go module tools, run Python regressions, build/test the candidate and install
the reviewed inputs. Changing the compiler also requires reviewing its installed
path in the updater. Builds use the exact installed Go compiler, CGO0, readonly
module resolution and mounted-volume caches; they do not grow root's Go cache.
Keep at least3GiB of volume headroom. No certificate/storage/configuration is
replaced by installing build inputs.

Preparation checks actual service identity, covered default storage, no systemd
overrides, disk/live routing equality, every explicit HTTP origin plus the
production wildcard tenants,12 public HTTPS endpoints and both Gemini SNI
routes. Origin TLS certificates and Gemini certificate/content identities are
captured before activation and compared afterward. Existing origin responses
such as authentication redirects or404s are baselines, not claims of application
functional correctness; public checks require valid HTTPS and HTTP200.
Candidate validation runs as the service user with disposable isolated storage.

Explicit `tls force_automate` subjects are supported: they use the same covered
default Caddy storage, not manually loaded certificate files. Custom storage,
other certificate loaders and placeholder-expanded automation subjects still
require separate review. A public alias alongside an internally issued wildcard
needs both its public issuer and explicit automation; otherwise Caddy prefers the
wildcard and may never request the public certificate:

```caddyfile
public-alias.example {
    tls {
        ca https://acme-v02.api.letsencrypt.org/directory
        force_automate
    }
    reverse_proxy 127.0.0.1:8080
}
```

This does not change wildcard issuance, proxying or TLS policy for other sites.

The updater serializes with Backuper and itself. It saves the original binary,
complete stopped Caddy storage and configuration with durable private receipts
before switching. Recovery never restores old certificates, ACME accounts or
other storage. Old-binary rollback is permitted only if all state, configuration,
binary metadata and routing assumptions are unchanged; its readiness and all
routes must then pass. Otherwise current storage stays intact and the reviewed
service is stopped, with `pending.json` retained for manual recovery. An
unconfirmed stop or unexpected executable is reported explicitly. Original
binaries/receipts are not automatically pruned.

The custom `/usr/bin/caddy` still occupies the vendor package's executable path.
An external package upgrade replacing it is detected as an unreviewed binary
and blocks this updater. Package upgrades and storage-format changes require
separate review; this tooling does not silently manage apt holds or restores.
