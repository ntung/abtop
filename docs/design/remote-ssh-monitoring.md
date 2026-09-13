# Design: Remote/SSH session monitoring

Status: sketch / not yet implemented. Currently listed as a Non-Goal (v0.1) in AGENTS.md.

## Summary

Add optional SSH-based monitoring of `abtop`-supported agent sessions (Claude
Code, Codex CLI, OpenCode) running on remote hosts, e.g. a dev box reached via
SSH. Today this is out of scope: the whole collection pipeline (`ps`/`lsof`/
filesystem reads) is local-only by design.

## Proposed approach

Rather than abstracting every `ps`/`lsof`/filesystem call in
`collector/process.rs`, `collector/claude.rs`, `collector/codex.rs`,
`collector/opencode.rs` behind a remote-capable backend trait (a large, risky
refactor, and wasteful on the wire — it would mean shipping raw multi-MB
JSONL transcripts over SSH just to re-parse them locally), reuse the fact
that `abtop` already has a complete, correct local collection pipeline via
its `--once` snapshot mode:

> Remote monitoring = run `abtop --once --json` *on the remote host* over
> SSH, parse its output, tag it with a hostname, and merge it into the local
> session list.

### New pieces

**1. `abtop --once --json` output contract**
- New flag alongside existing `--once`. Emits a slim, versioned DTO (not the
  raw `AgentSession`, to decouple wire format from internal refactors):
  ```rust
  struct RemoteSnapshot {
      schema_version: u32,
      sessions: Vec<RemoteSessionDto>,
      orphan_ports: Vec<OrphanPort>,
      rate_limits: Vec<RateLimitInfo>,
  }
  ```
- Reuses the existing `--once` redaction path (tool_use inputs already
  reduced to "tool name + file path", per the Privacy section of AGENTS.md)
  — no new redaction logic needed; secrets never hit the wire.

**2. `src/collector/remote.rs` — `RemoteCollector: AgentCollector`**
- Config-driven host list in `~/.config/abtop/config.toml`:
  ```toml
  [[remote_hosts]]
  name = "devbox"
  ssh_target = "devbox.internal"   # or user@host
  ssh_opts = ["-p", "2222"]
  poll_interval_secs = 10
  allow_remote_kill = false        # see risks below
  ```
- Must not block the 2s tick loop: SSH round trips (auth handshake + remote
  `ps`/`lsof`/JSONL scan) can take hundreds of ms to seconds. Each host polls
  on its own background thread (same idiom already used for `claude --print`
  summary generation: background process + timeout, capped concurrency),
  writing into a shared cache that the main tick reads without blocking.
- SSH multiplexing is effectively required, not optional:
  `-o ControlMaster=auto -o ControlPersist=60s -o ControlPath=...` so
  repeated polls reuse one authenticated connection instead of a full
  handshake every poll.

**3. Model change**: add `host: Option<String>` to `AgentSession` (`None` =
local; existing fixtures/tests unaffected). UI prefixes remote rows, e.g.
`[devbox] CC 7336 ...`.

**4. Identity fix**: PIDs are only unique per host. Anywhere sessions are
currently keyed/selected/killed by `pid` alone (selection state, kill
action, orphan-port tracking) needs to become keyed by `(host, pid)` — this
is the one change that touches existing code paths rather than being purely
additive.

### Failure handling (mirrors existing staleness/heuristic conventions in AGENTS.md)
- Unreachable host / auth failure → mark `Unreachable`, backoff, don't retry
  faster than `poll_interval_secs`; show stale cached rows grayed out
  ("stale, Ns ago") rather than blanking them immediately.
- Remote `abtop` missing or schema mismatch → `schema_version` checked
  before parse; clear error message instead of a serde panic.
- Clock skew across hosts → compute "last seen" from local receipt time, not
  the remote's absolute timestamps.

### Deliberately out of scope for v1
- Kill (`x`/`X`) on remote sessions/ports: default-disabled
  (`allow_remote_kill = false`) — SIGKILL over SSH on a box you don't
  locally control is a materially different risk than the existing local
  safety-checked kill.
- tmux jump (`Enter`) for remote sessions: would need
  `ssh -t host tmux select-pane`; changes the meaning of "jump," left for a
  follow-up.
- Streaming/push: stick to the existing poll-tier model, just add a slower
  "remote" tier (~10-30s) given network cost.

## Trade-offs to flag explicitly

This is a genuine scope change from today's design, which is intentionally
local-only, network-free, and auth-free ("No network, no auth" — Privacy /
Data Sources sections of AGENTS.md). This proposal introduces SSH as a real
dependency: connectivity, key/agent auth, and requiring `abtop` installed on
the remote host. Worth deciding deliberately rather than as a side effect of
an unrelated change.

## Benefit vs. cost

Nearly all new code is additive (one flag, one collector module, one config
block, one model field); the existing 3990-line `claude.rs` and friends stay
untouched.

## Corrections against the current codebase (2026-09)

The sketch above predates a look at the actual code. Two assumptions don't
hold and one is broader than necessary:

1. **`--once`/`--json` already exist**, as two separate flags — `--json`
   alone already prints the full `Snapshot`/`SessionView` (`src/snapshot.rs`),
   richer than the slim `RemoteSnapshot` sketched above (it includes chat
   tails, tool calls, subagents). There is no `schema_version` field today.
   So "piece 1" isn't new; it's (a) add `schema_version: u32` to `Snapshot`,
   and (b) decide whether `RemoteCollector` consumes the existing rich
   `Snapshot` as-is, or a new slimmer DTO behind its own flag so chat/tool
   tails aren't shipped over SSH by default.
2. **Config parsing (`src/config.rs`) is a hand-rolled line-by-line
   `key = value` parser**, not a TOML crate — no support for
   `[[remote_hosts]]` array-of-tables today. Adding it means either
   extending the hand-rolled parser for this one nested shape, or pulling in
   a real `toml`/`toml_edit` dependency. This repo has never needed a real
   TOML dependency before; worth deciding deliberately.
3. **The "keyed by (host, pid)" identity fix is narrower than it sounds.**
   Pid-keyed caches in `collector/mod.rs` (`cached_ports`,
   `tracked_port_children`, `cached_port_pids`) are local-scan-only and never
   touched by remote data — remote ports/orphans arrive pre-computed from the
   remote `abtop --once`, so those maps stay pid-only. The part that actually
   needs `(host, pid)` awareness is narrower and sharper: `kill_selected`,
   `kill_orphan_ports`, and `jump_to_selected` in `app.rs` (lines ~710/758/801)
   shell out `ps -p <pid>` / `kill -9 <pid>` against whatever pid sits in
   `AgentSession.pid`, with **no check on origin today**. Once remote sessions
   with foreign pids sit in `self.sessions`, `allow_remote_kill = false` in
   config isn't sufficient on its own — those three call sites must explicitly
   bail when `session.host.is_some()`, or a remote pid that happens to collide
   with a real local killable-agent pid gets SIGKILLed locally. Treat this as
   a correctness/safety must-fix, not a nice-to-have.

## Implementation phasing

- **Phase 0 — wire contract.** Add `schema_version: u32` to `Snapshot`
  (bump-and-check on parse). Add `host: Option<String>` to `AgentSession` and
  `SessionView` (`None` = local); thread through `to_snapshot`.
- **Phase 1 — config.** Add `[[remote_hosts]]` parsing per the schema above.
  Decision needed: extend the hand-rolled parser vs. add a `toml` dependency.
- **Phase 2 — `RemoteCollector`.** `src/collector/remote.rs`, implements
  `AgentCollector`, one background thread per configured host running
  `ssh -o ControlMaster=auto -o ControlPersist=60s ... abtop --once --json`
  (or the slimmer flag from Phase 0b), caches last-good sessions +
  `Unreachable` state, tags every session with `host`. Registered in
  `MultiCollector::with_hidden_and_claude_config_dirs` alongside the existing
  collectors, gated on `remote_hosts` being non-empty.
- **Phase 3 — safety guards + UI.** Guard `kill_selected`,
  `kill_orphan_ports`, `jump_to_selected` on `session.host.is_none()`. Add the
  `[hostname]` row prefix and "stale, Ns ago" greying per the failure-handling
  section above.
