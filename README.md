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

And not only those bytes: logs rarely carry a secret verbatim. Each value is
also searched in the spellings it takes on its way into a log — Base64
(standard and URL-safe, in all three byte alignments, so `Authorization:
Basic base64(user:password)` is found), percent-encoding (several common
safe sets, upper- and lowercase, `+` for a space), JSON escapes (standard,
`\/`, Go's `\u0026`, ASCII-only) and hex (lower- and uppercase). A value
that spans several lines is additionally searched line by line, for the
lines shaped like key material. A report names the spelling that leaked:
`radarr-apikey[b64]`.

## Why no HMAC

An index of hashed tokens would need the same boundary guess a masking
regex needs — where does a secret start and end in a log line — before it
could hash anything to compare against. Since the values already sit in
plaintext on the machine leakwatch runs on (every service reads them from
there), an HMAC buys no confidentiality either. Plaintext matching is not
the lazy option here; it is the only one that does not reintroduce the
guessing the tool exists to avoid.

## What it finds and does not

Every run injects a canary into every source before scanning — in every
spelling it searches for, each probe a real embedding (`base64("u:" +
canary + "!")`, the canary percent-encoded in a query string, JSON-escaped
in an object, …) — and checks, per adapter, that every probe came back as a
hit of its own spelling. Without this, "0 findings"
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
found, and a redacted line with context trimmed around the hit. Every
secret in that line is masked, not just the one reported: a second
occurrence of the same value, the password next to its user name, an
excepted identifier. Control characters in the line are replaced, so an
escape sequence in a log cannot reach the terminal that reads the report.

`sensor` prints no line content at all — only name, source, location and
time. Its stdout ends up in the host journal, and from there in a log store
and in every chat log that quotes it; a redacted copy of someone else's log
line has no business there. The context is one `leakwatch scan` away on the
machine. The last
line of every finding names the rotation command
(`just rotor-leser <secret>`), because a leak's real fix is a rotation, not
a suppressed alert.

## Sources

| Source | What | Reads |
|---|---|---|
| `journal` | the host's own journal, or one or more guests' via `journalctl -M` (`--machine`, repeatable) | locally, streamed, or over `ssh` |
| `loki` | the aggregated log store, which also proves whether a log-scrubbing regex mask elsewhere actually holds | `curl`, optionally wrapped in `ssh` — Loki commonly listens on an address the machine running leakwatch cannot reach directly. The window is paged oldest-first (5000 entries per request) and every log line is scanned as its own line; a full page that cannot be paged past (all entries on one timestamp) is a tool failure, not a truncated clean result |
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
does not. `leakwatch_lines_scanned{source}` counts the lines each source
delivered (summed per source name, probes excluded) — the canary proves a
source delivered something, the count says how much, and comparing it with
the log store's own count shows a shortfall. `leakwatch_run_timestamp`
names when the run happened.

A finding in an encoded spelling counts under the secret's own name in
`leakwatch_finding` — that is the name a rotation needs; the report text
names the spelling. Likewise an exception for `foo` covers every spelling
of `foo`; one for `foo[url]` covers only that spelling.

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

### Intermittent findings: `optional`

That staleness check assumes a finding either keeps happening or is gone for
good. Real logs are not like that. A mail server writes the sender address
while mail is going out and stays quiet otherwise; a client logs its own
account name when it reconnects. Such an exception matches in one window and
not in the next, and both available answers are wrong: keep it and the run
goes red for a healthy system, drop it and an identifier raises an alert.

```toml
[[exception]]
secret = "smtp-user"
source = "journal"
optional = true
reason = "the mail log carries the sender only while mail is going out"
```

`optional` exempts that one entry from the staleness check and nothing else —
it still only excepts the pair it names. The flag defaults to false, so
leaving it out keeps the check on.

**Do not reach for it to quiet a list.** Frequency is no guide either: an
exception with 18 hits in a three-hour window has been observed matching
nothing three hours later, because those 18 were one burst and not a rate.
The question is whether the finding is intermittent *by nature*, and the
answer belongs in the `reason` next to it. A file in which every exception is
`optional` has given up the staleness check.

An exception naming the canary (`leakwatch-canary`) is rejected outright,
before any source runs: canary hits are filtered before they can become
findings, so such an exception could never match and would fail every run
as a stale exception instead — a message pointing at the wrong cause.

## Limits

- A value shorter than 8 bytes is never searched for — it would match
  constantly and drown every real finding — and neither is any spelling of
  it; every encoded spelling must itself be at least 8 bytes long. A run
  states how many of the loaded secrets were skipped this way.
- A secret that spans more than one line is found whole in its JSON-escaped
  form (one log line) and otherwise line by line — but only for lines of at
  least 16 characters that look like key material: Base64/token characters
  only, letters and digits mixed. Taking every line would make
  `-----BEGIN PRIVATE KEY-----` match every PEM file and `LOG_LEVEL=info`
  half the rendered templates. A run states how many values are multiline.
- Spellings not searched: UTF-16, case-changed copies, double encodings,
  Base64 wrapped at 76 columns, and anything compressed or encrypted.
- `sessions` and `files` read the local filesystem only; `journal` reads
  the local host or one or more named guests via `journalctl -M`
  (`--machine`); `journal` and `loki` can both be reached over `ssh`.
  Scanning a remote host's `sessions` or `files` means running leakwatch on
  that host.
- The canary proves a source delivered lines, not that a specific line was
  read correctly — a source that silently drops a small fraction of its
  output can still look healthy.
- `leakwatch_canary_found` carries one line per source NAME, not per source.
  Several journals scanned in one run (one per guest) fold into a single
  `source="journal"` line, and the fold is an AND: one silent guest makes it
  zero. Which guest is named in the error line and in `location`, not in the
  metric — a label per guest would multiply the label sets that exception
  lists and alert rules key on.
- `timestamp` is the time of the RUN, not of the line. For the journal the
  line's own timestamp is in the report text; for the other adapters there is
  no per-finding time. "Is this one of the leaks from last Tuesday?" is not a
  question a report answers.

## Running it as a unit

The process holds every secret of the machine in memory. On the code side,
releases are built with `panic = "abort"`, and the buffers the values are
read into (files under the secrets roots, `sops` output, the pattern list)
are wiped with `zeroize` once the automaton is built. What cannot be wiped:
the automaton's own copy of every pattern, which lives as long as the run,
and the YAML tree `serde_norway` builds from `sops` output. The rest belongs
in the unit:

```ini
LimitCORE=0            # no core dump carrying every secret to disk
MemorySwapMax=0        # no page of it in swap
IPAddressDeny=any
IPAddressAllow=192.0.2.12/32   # only where Loki listens; nothing without Loki
                               # (or PrivateNetwork=true)
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
MemoryDenyWriteExecute=true
SystemCallFilter=@system-service
ProtectSystem=strict
NoNewPrivileges=true
CapabilityBoundingSet=CAP_DAC_READ_SEARCH   # only for journalctl -M into guests
```

## Install

```sh
nix run github:achimcc/leakwatch -- scan --help
cargo install --git https://github.com/achimcc/leakwatch
```

## License

AGPL-3.0-only. See [LICENSE](LICENSE).
