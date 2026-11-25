# Work log

## 2026-11-17: preserve station ID mapping during allocation optimization

- Own adversarial review found the ASCII-only replacement changed non-ASCII
  and invalid UTF-8 IDs, unlike the original strings.ToUpper mapping.
- Added a conservative original-code fallback for non-ASCII input and permanent
  table regressions for normal UUIDs, short/empty/dash-only/malformed IDs.
- Tests fail before the fallback and pass after it. Full go test ./... and
  go vet ./... pass. BenchmarkRBUID: 48.84 ns/op,16 B/op,1 alloc/op locally.
- No device/receiver runtime tested. One hidden Devin flag still needs its
  contents recovered before merge, regardless of green check status.

## 2026-11-24: README Go guidance

Owner requested the attribution paragraph mention Go and stale Pascal build
guidance be corrected. Attribution paragraph changes only the compiler phrase.
Reviewed go.mod, script/build.sh, CI matrix, embedded SQLite driver and Go HTTP
client. README now names actual CI targets, Go1.26.0 requirement, go build/test
and current output paths; removes obsolete Pascal toolchain/library steps and
unverified4.6MB/8MB claims. No receiver/runtime or binary-size claim.
Checked master, branches and recent/open PRs:78 is unmerged RM50 support, no
README overlap. Separate branch from current master, not78. CalVer402 matches
add-on metadata; config-format/upstream versions unchanged. Own adversarial
docs review ran, text/diff checks pass. Full Go build/smoke not run locally
because disk is nearly full; no claimed executable measurements. No merge.

## 2026-11-25: bound learned DNS forwarding clients

Owner requested a separate expiry/cap PR after78. Checked current master
84e93d4, remote branches and latest12 PRs:78/79 merged, no open or duplicate
cache implementation. Trace: server.noteWebClient gets the socket RemoteAddr
at the login endpoint, NoteWebClient learns it, clientAllowed gates only
non-intercepted DNS when RestrictForwarding is enabled. No proxy-header trust
or authenticated-login claim. Explicit allow-list and intercepted names remain
independent of the cache.

Failing first: expiry pruning,4096limit and non-IP tests all failed on master
for the expected retained/oversized/invalid map reasons. Implementation rejects
non-IP input, removes an expired queried entry, and sweeps at most once per
minute on valid web traffic. New addresses fail closed at capacity rather than
evict working receivers. Existing receivers refresh even when full. Expired
unqueried entries may remain while idle, always bounded; a new address may need
a later login within one minute for a sweep to free space. No new goroutine,
config, DNS destination, dependency or wider forwarding permission.

Own pre/post adversarial review RAN: checked map accesses and all callers,
mutex scope including prune/admission/refresh, one-minute scan throttle under
full-cache address churn, TTL not extended by DNS, allow-list bypass retained,
refusal/relogin on real UDP with local upstream, concurrent cap admission.
Full go test ./..., go vet ./..., and go test -race ./internal/dnsserver
./internal/server pass. No real RM50/receiver or production deployment run.
Version403 and add-on metadata agree, INI/upstream versions untouched. No merge.

Independent review80 follow-up: FIND-80-1 reproduced zone-bearing IPv6 loss;
FIND-80-2 reproduced one IPv6 prefix filling the map and silent capacity drops.
New failing-first tests catch both. Canonical netip addresses now retain zones
and unmap IPv4 on BOTH web learning and DNS/allow-list lookup. Authorization
remains exact IP plus zone: deliberately not a /64 grant to unseen neighbours.
Instead, each IPv6 /64 plus zone has64 learned-address slots within the4096
whole-cache limit. Rate-limited fixed log reports overflow, at most once per
minute. Earliest-expiry tracking forces immediate reclamation on a full-cache
insert once any entry could expire, without rescanning per hostile packet.
This supersedes earlier one-minute refusal caveat; normal idle sweeps remain
traffic-driven. Added prefix-slot-reclamation and unseen-neighbour tests.
Full tests/vet and DNS/server race pass after fixes; independent re-review
requested. Fixed limits mean a very large shared /64 can still need explicit
allow-list entries; this is not authentication or general DoS prevention.
