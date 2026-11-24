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
