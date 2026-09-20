# leakwatch

Finds secrets in logs by matching their real plaintext values — not by
guessing their shape.

A masking regex has to guess where a secret starts and ends, and every
guess it gets wrong is a leak: a 20-character password under a `{24,}`
length bound, an `api_key` inside JSON quotes a field-name mask never
matched, a URL-encoded copy in a `next=` parameter, a tracker announce URL
with a passkey nobody thought to look for. Six real incidents in this
household's homeserver, each one a different way of guessing wrong. leakwatch
does not guess: it is handed the actual secret values — the same plaintext
every service already reads from `/run/secrets` — and searches for exactly
those bytes with Aho-Corasick. No boundaries to get right, no shape to miss.

## Why no HMAC

An index of hashed tokens would need the same boundary guess a masking
regex needs — where does a secret start and end in a log line — before it
could hash anything to compare against. Since the values already sit in
plaintext on the machine leakwatch runs on (every service reads them from
there), an HMAC buys no confidentiality either. Plaintext matching is not
the lazy option here; it is the only one that does not reintroduce the
guessing the tool exists to avoid.

## What it finds and does not

Every run injects one canary value into every source before scanning and
checks, per adapter, that the canary came back. Without this, "0 findings"
and "the scanner never got to look" print identically — which is exactly
how a broken command, a dead ssh path or a stale glob turns into silence.
The canary is never reported as a finding itself; it only proves the
wiring. A source that delivers nothing beyond the canary is reported as a
tool failure, not as a clean result.

```console
$ leakwatch scan --source files --files /var/log/caddy/*.log
test-secret  files  /var/log/caddy/access.log  1758300012
  GET /api?apikey=<REDACTED> HTTP/1.1
  → just rotor-leser test-secret
2 of 214 secrets are shorter than the minimum length and are not searched
```

A finding never prints the value — only the secret's name, where it was
found, and a redacted line with context trimmed around the hit. The last
line of every finding names the rotation command
(`just rotor-leser <secret>`), because a leak's real fix is a rotation, not
a suppressed alert.

## Sources

| Source | What | Reads |
|---|---|---|
| `journal` | the host's own journal, or one or more guests' via `journalctl -M` (`--machine`, repeatable) | locally, streamed, or over `ssh` |
| `loki` | the aggregated log store, which also proves whether a log-scrubbing regex mask elsewhere actually holds | `curl`, optionally wrapped in `ssh` — Loki commonly listens on an address the machine running leakwatch cannot reach directly |
| `sessions` | Claude session transcripts, where the household's real chat leaks actually landed | streamed, files opened lazily (972 files would cost 972 descriptors at once) |
| `files` | log files that never pass through Loki, e.g. Caddy's access log | glob patterns, `--files`, repeatable; not selected by default because a guessed default path is not a finding |

None of the adapters ever puts a secret value into a subprocess's argv —
that is itself a leak (systemd logs a transient unit's argv, and 26 lines
of it once ended up in guest journals).

## Usage

```
leakwatch scan   [OPTIONS]
leakwatch sensor [OPTIONS]

    --since DURATION     e.g. 7d, 1h (scan default: 7d, sensor default: 1h)
    --source LIST        comma-separated: journal,loki,sessions,files
                          (default: journal,loki,sessions for scan, journal
                          for sensor — files is never picked by default)
    --machine NAME       scan a guest's journal via `journalctl -M NAME`
                          instead of the host's own; repeatable, several
                          guests can be scanned in one run
    --secrets-repo PATH  read secrets via sops from a homeserver-secrets
                          checkout instead of the local /run/secrets
    --secrets-root PATH  an ADDITIONAL runtime secrets root, searched
                          alongside the two defaults; repeatable
    --ssh TARGET         reach the journal or loki source over ssh (for a
                          machine the tool does not run on itself);
                          combine with --machine to reach a guest on a
                          remote host
    --loki-base URL      override the Loki base URL
    --files GLOB         a glob for the files source; repeatable
    --sessions-root PATH override the sessions root
-c, --config FILE        exceptions, see below
    --output PATH        sensor: where to write the textfile metric
-h, --help
-V, --version
```

`scan` runs on demand and prints every finding as text. `sensor` runs the
same pipeline from a systemd timer and additionally writes a Prometheus
textfile metric — the same shape as this house's other sensors
(gast-speicher, dns-abgleich, sicherung, groundtruth): a oneshot, written
atomically (temp file, then renamed), so node-exporter's textfile collector
never reads a half-written file. `leakwatch_finding{secret,source}` never
carries a value, only a secret's name and its source; `leakwatch_canary_found{source}`
is `0`, not absent, when the canary did not come back for a source — an
absent series and a healthy one look the same to an alerting rule, a zero
does not. `leakwatch_run_timestamp` names when the run happened.

### Exit status

| Code | Meaning |
|---|---|
| `0` | no findings, every canary found, no source silent |
| `1` | findings |
| `2` | tool failure — canary missing from the scanner, a canary not found for some source, a source that delivered only the canary, an unused exception, or an adapter error |

"Nothing found" and "could not look" are deliberately never the same code.

## Exceptions

A match that is accepted says so, with a reason — the unit-lint pattern:

```toml
[[exception]]
secret = "grafana-anon-token"
source = "loki"
reason = "the token is intentionally public on the read-only dashboard"
```

An exception without a reason fails to parse. One that matches nothing in
a run that could have matched it is reported as a tool failure — an
exception list that ages silently is worse than no list.

An exception naming the canary (`leakwatch-canary`) is rejected outright,
before any source runs: canary hits are filtered before they can become
findings, so such an exception could never match and would fail every run
as a stale exception instead — a message pointing at the wrong cause.

## Limits

- A value shorter than 8 bytes is never searched for — it would match
  constantly and drown every real finding. A run states how many of the
  loaded secrets were skipped this way.
- A secret that spans more than one line is only found if it appears in
  the data whole. Splitting it into single-line patterns is not the fix:
  `-----BEGIN PRIVATE KEY-----` would then match every PEM file. A run
  states how many of the loaded values are multiline.
- `sessions` and `files` read the local filesystem only; `journal` reads
  the local host or one or more named guests via `journalctl -M`
  (`--machine`); `journal` and `loki` can both be reached over `ssh`.
  Scanning a remote host's `sessions` or `files` means running leakwatch on
  that host.
- The canary proves a source delivered lines, not that a specific line was
  read correctly — a source that silently drops a small fraction of its
  output can still look healthy.

## Install

```sh
nix run github:achimcc/leakwatch -- scan --help
cargo install --git https://github.com/achimcc/leakwatch
```

## License

AGPL-3.0-only. See [LICENSE](LICENSE).
