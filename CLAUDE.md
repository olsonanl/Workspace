# CLAUDE.md

Guidance for Claude Code working in the BV-BRC Workspace repository.

## What this is

The Workspace service: a JSON-RPC API over MongoDB plus Shock object storage,
with a separate download service for serving file bytes to browsers.

## Services and how they run

`service/start_service.tt` starts **three** servers, and their concurrency models
differ in ways that matter:

| Service | PSGI | Port | Server | Concurrency |
|---|---|---|---|---|
| Workspace (RPC) | `Workspace.psgi` | 7125 | starman | **25 worker processes** |
| WorkspaceDownload | `WorkspaceDownload.psgi` | 7129 | **Twiggy** | **1 process, 1 event loop** |
| WorkspaceCompletion | `WorkspaceCompletion.psgi` | 7140 | Monoceros | |

**`kb_starman_workers=25` in the Makefile applies only to starman.** The download
service gets no `--workers` and is single-threaded. Anything that blocks its event
loop blocks *every* download — this is the single most important fact about this
codebase's runtime behavior.

All three sit behind nginx. `p3.theseed.org` is a direct A record
(`140.221.78.42`, `Server: nginx`) and is **not** behind Cloudflare, unlike the
MAAGE-Web front end.

## The download service (`WorkspaceImpl.pm:1460-2040`)

Four routes, mounted by `WorkspaceDownload.psgi`: `/download`, `/view`,
`/set-cookie-auth`, and `/` (a legacy fallback identical to `/download`).
`/archive/{sig}` is reachable via both `/download/archive/...` and `/archive/...`.

Things that will surprise you:

- **`$MAX_PER_HOST` must stay set.** `AnyEvent::HTTP` defaults it to 4 and
  *queues* everything beyond that per hostname. Since all Shock fetches share one
  hostname, the default caps the whole service at four concurrent downloads. This
  caused a multi-hour production stall (see below). It is now set explicitly in
  `WorkspaceDownload.psgi` — **do not remove it**, and think before raising it
  (it also bounds memory, see next point).
- **There is no backpressure on the body copy.** `on_body` calls
  `$writer->write` and returns 1 regardless of whether the client can keep up,
  and `Twiggy::Writer::write` is `push_write` into an unbounded buffer. The
  service pulls from Shock at ~46 MB/s while a slow client may drain at tens of
  KB/s, so each in-flight transfer can buffer most of its response in memory.
  `MAX_PER_HOST` is therefore also the memory bound: ~253 MB per slot worst case.
- **`/view` returns 503**, not 401/403, for every session failure.
- **Expiry is not checked on `/download` or `/archive`** — only the 120s sweep
  removes expired records, so a key stays usable in the gap.
- **Four distinct 404 bodies** exist: `Invalid path\n`, `Not found\n`,
  `Not a file\n`, and URLMap's unreachable one. Preserve them if touching this.
- `db-path` gains a `/P3WSDB/` suffix in the constructor (`:2182`).
- Download keys and session cookies are **bearer secrets**. Never log them.

## Shock object storage (and reading it directly)

Shock shards its on-disk data by node id:
`<root>/<id[0:2]>/<id[2:4]>/<id[4:6]>/<id>/<id>.data`. This isn't something we
invented — `lib/Bio/P3/Workspace/WSFileMember.pm` (used by the zip-archive
builder) has read it directly off disk for years: `_get_path` (`:186`)
reconstructs the shard path, and `_openFile` (`:74-76`) hardcodes
`$shock_base = "/disks/shock/Shock/data"` and pulls the node id out of the
stored `shocknode` URL with the end-anchored `m,node/([a-f0-9-]+)$,i`. `shock-url`
in `deploy.cfg` is an internal address (`10.1.16.5`), distinct from the public
`p3.theseed.org` host baked into stored `shocknode` URLs — i.e. Shock and
Workspace are co-located, which is the whole premise of skipping the HTTP hop.

**`WSFileMember.pm` falls back to `curl … $url?download` silently** if the
direct `open()` fails (`:92-110`) — no distinction between "file legitimately
isn't there yet" and "file is corrupt," it just goes to HTTP either way.

The Go download service (`go/internal/shockstore`) does this on purpose
differently, because three deployment invariants make the direct read safe
enough to trust instead of falling back:

- There is only **one copy** of the Shock data tree — no replica or cache to
  diverge from what Mongo records.
- A Mongo record with a **nonzero size means the file is already complete**
  on disk — no torn-write/in-progress-upload race to account for.
- If the on-disk file **disagrees** with that recorded size (or isn't there),
  that is a bug, not a fallback trigger.

So `shockstore.OpenLocal` treats a missing file or a size mismatch as
`ErrIntegrity` → the download service answers a hard **500, with no HTTP
fallback**. Masking that class of failure is exactly what turned a one-line bug
into a multi-day investigation once already (see "The 2026-09-24 download
stall" below) — don't reintroduce it here. `ErrUnsupportedURL` (the stored URL
doesn't look like a Shock node reference at all) is the one case that *does*
fall through to HTTP, since it isn't evidence of anything wrong.

Enabled via the **Go-only** deploy.cfg key `shock-data-path` in `[Workspace]`
(`go/internal/wsconfig/wsconfig.go:83`, field `ShockDataDir`). Perl never reads
this key; absent or empty means the feature is off and every Shock read goes
over HTTP, unchanged from today.

## /view: workspace resolution and permissions

Not yet ported (phase 3), but worth recording now — these are all verified
against `WorkspaceImpl.pm` directly, not inferred:

- **`_get_ws_permission` (`:405`) checks "published" before "owner."** A
  workspace with `global_permission eq "p"` returns `"p"` at `:407-409`,
  *before* the owner check at `:411`. So the owner of their own published
  workspace gets permission level `p` (=1 on the `n/p/r/w/a/o` =
  `0/1/1/2/3/4` ladder), not `o` (=4). Harmless for `/view` (only needs `r`,
  and `p`/`r` are both 1), but breaks any write check built the same way.
  `set_permissions` (`:4156`) already works around it with its own explicit
  owner test rather than calling `_check_ws_permissions` — evidence this is a
  known, load-bearing wart, not an oversight to silently "fix" while porting.
- **`workspaces.permissions` keys are Mongo-escaped usernames.** MongoDB
  forbids `.` and `$` in field names, and every BV-BRC username has a `.` in
  its domain, so `_escape_username_for_mongo` (`:458`,
  `uri_escape($name, '.\$')`) stores `olson@patricbrc%2Eorg`.
  `_get_db_ws` (`:253`) unescapes the *entire* permissions map on every read,
  so in memory the keys are always plain — `_get_ws_permission`'s
  plain-username lookup only works because of that unescape. Skip it in a
  port and every non-owner is silently denied. Note the pair is **not a true
  inverse**: escape touches only `.`/`$` (`:454-459`), but
  `_unescape_username_for_mongo` (`:461-466`) is a blanket `uri_unescape` that
  decodes any `%XX`. Implement the escape/unescape as a strict two-character
  swap (`.`↔`%2E`, `$`↔`%24`, uppercase hex) rather than reaching for a
  general URI decoder.
- **`_query_database` (`:655`) mutates and deletes on a read path.** It
  rewrites the caller's `$query->{path}` in place, stripping leading/trailing
  `/` (`:657-660`), and when two documents share `(workspace_uuid, path,
  name)` it `remove()`s one from Mongo (`:682-687`) rather than just
  returning both. A GET request can delete a document. Anyone porting this
  needs to decide deliberately whether to keep that behavior.
- **The same function can block on the network and spawn subprocesses.** A
  row with `shock == 1 && size == 0` triggers `_update_shock_node` (`:814`):
  a synchronous LWP GET to Shock, a Mongo write, and potentially spawning a
  `ws-autometa-*.pl` script. On the download service's single-threaded
  Twiggy event loop this is a second, uncatalogued stall source alongside the
  `MAX_PER_HOST` one below.
- **`_wsauth` (`:164`) caches the service-account token forever**, with no
  expiry check, no refresh, and no invalidation on a 401. Since the download
  service is one long-lived process, an expired token makes the `/view`
  Shock ACL-granting PUT (`:1823`) fail — and that failure is invisible,
  because the response is assigned to `$res` and never inspected. That PUT
  also uses a bare `LWP::UserAgent->new()` with no timeout. Related:
  `P3AuthLogin::login_rast` (in `p3_auth`) authenticates over **plain HTTP**
  (`http://rast.nmpdr.org/goauth/token`) with the credentials in a Basic
  auth header.
- `/view` never sets `_adminmode`, so the admin bypass at `:433` is dead code
  on this path — don't port it into a Go `/view` handler. And every failure
  mode (object not found, path is a folder, permission denied) collapses to
  the same `404 Invalid path\n`; preserve the body, keep the distinction only
  in server-side logs.

## Logging

`Bio::P3::Workspace::StampedStderr` ties STDERR so `warn`, `die`, `Dumper` and
every `print STDERR` get `[timestamp pid]`. Installed in all three `.psgi` files.
Add new services to it.

Per-transfer lines, one per fetch, in `download.error.log`:

```
shock-fetch client=140.221.78.40 status=200 ttfb=0.164 total=30.191 bytes=253425891 url=...
file-fetch  client=140.221.78.40 total=2.114 bytes=88210 path=...
```

**`ttfb` vs `total` is the diagnostic.** A large `ttfb` means a slow dependency;
a small `ttfb` with a large `total` means a slow client. Two investigations went
down blind alleys for want of that split — keep it.

Note the **main RPC service does not use StampedStderr for RPC errors**. It routes
them through `ServiceStderrWrapper` (`Service.pm:314`, `:562`) to a per-request
log file with its own ISO-8601 stamp. Only `warn` from inside handlers reaches
real STDERR.

Client IP comes from `_client_address`: X-Forwarded-For first hop → X-Real-IP →
socket peer, mirroring `Service.pm:187`. **Treat as diagnostic, not
authorization** — the value is only as trustworthy as the proxy that set it, and
the code cannot tell a proxy-set header from a client-supplied one.

> **Fixed 2026-09-25 in the nginx config.** The `/services/WorkspaceDownload/`
> location now sets the forwarding header, and the real client address is
> logging correctly:
>
> ```nginx
> location /services/WorkspaceDownload/ {
>     proxy_set_header X-Forwarded-For $remote_addr;
>     proxy_pass http://spruce.cels.anl.gov:7129/;
> }
> ```
>
> Note this uses `$remote_addr` rather than `$proxy_add_x_forwarded_for`. That
> is deliberate here and arguably safer: `$proxy_add_x_forwarded_for` *appends*
> to any client-supplied `X-Forwarded-For`, so a client can inject a bogus first
> hop, and `_client_address` takes the first hop. With `$remote_addr` the header
> is overwritten with the address nginx actually observed, which cannot be
> spoofed. The trade-off is that a genuine upstream proxy's chain is discarded —
> fine for this deployment.
>
> **Two ways to get an internal address in the log, both expected:**
>
> 1. **The request bypassed nginx.** The service also listens directly on
>    `http://spruce.cels.anl.gov:7129/`, which carries no forwarding headers at
>    all, so `_client_address` falls through to the socket peer. Confirmed by
>    tshark. Test through the public `https://p3.theseed.org/...` URL to
>    exercise the proxy path.
> 2. A `location` block without the `proxy_set_header` line. Each one needs it
>    individually — an RPC-service capture showed
>    `X-Forwarded-For: 140.221.78.20, 140.221.78.20`, an internal host
>    duplicated rather than an originating client, which is what a differently
>    configured location produces.

## The 2026-09-24 download stall (resolved)

The service was blocked ~91-93% of wall-clock time in ~9s blocks. Root cause was
`$MAX_PER_HOST = 4`. Fixed in PRs #101-#103.

Worth reading if you are debugging something similar, because **four plausible
hypotheses were wrong** before the right one: missing Mongo indexes, replica-set
health, slow-client backpressure, and upstream Shock latency. Each was killed by
data, not argument:

- Shock's own access log (paired `REQ RECEIVED`/`RESPONDED TO`) gave median 0s,
  p99 1s over 368,752 requests — and showed the service *never sent* a request
  during the gaps.
- Ganglia showed the host idle (~7% CPU, 0.19% wio) — blocked, not busy, and not
  I/O bound, which also cleared NFS.
- Collection counts of 16 and 23 documents killed the index theory outright.
- A purpose-built load tool (`go/cmd/slowclient`) failed to reproduce at 2, 20,
  and 200 slow clients.

The lesson: **instrument first.** The `ttfb`/`total` line found the answer on its
first real use, after days of inference from logs that recorded the wrong thing.

## Go components (`go/`)

- `cmd/p3-mount-ws` — FUSE driver. Needs CGO and platform FUSE headers.
- `cmd/ws-download` — in-progress Go port of the download service, phases 1-2
  of 7 done: `/download` serves both local-filesystem and Shock-backed files
  (ranged, ctx-cancellable). `/view` and `/set-cookie-auth` still answer 501.
  See `go/cmd/ws-download/PORT_STATUS.md`, whose §1.5 lists the six defects the
  port must not reproduce, and §1.6 for the direct-Shock-read design below.
- `cmd/slowclient` — load tool for reproducing download stalls against a live
  service. Read its header for safety notes before pointing it at production.

Build the Go server components with `make server` / `make test-server`; both set
`CGO_ENABLED=0` so they stay independent of the FUSE toolchain. Plain `make test`
runs `./...` and needs FUSE headers. `test-server`'s package list is explicit
(`go/Makefile:15`, `SERVER_PKGS`) rather than a wildcard — a new `internal/`
package needs adding there or its tests silently never run in the CGO-free target.

## Local development caveat

`WorkspaceImpl.pm` cannot be compiled on a machine without the deployment runtime
— it fails at line 18 on a missing `RPC::Any`, and Plack/Twiggy/MongoDB are
usually absent too. `perl -c` on individual new modules still works. Verify
`.psgi` changes on a host with the runtime before deploying.
