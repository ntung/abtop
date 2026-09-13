//! Remote/SSH session monitoring: `abtop --json` on another host over SSH,
//! merged into the local session list. See
//! `docs/design/remote-ssh-monitoring.md` for the full design.
//!
//! Reuses the existing `--json` snapshot (`crate::snapshot::Snapshot`) as the
//! wire format rather than inventing a new flag: it's already redacted the
//! same way `--once` is, and already versioned via `schema_version`
//! (`crate::snapshot::SCHEMA_VERSION`). [`RemoteSnapshotDto`] below is a
//! separate, intentionally narrower `Deserialize` view of that same JSON —
//! it only picks out the fields needed to reconstruct an [`AgentSession`],
//! and every field is defaulted (`#[serde(default)]`) so an older/newer
//! remote `abtop` degrades gracefully instead of failing to parse.
//!
//! One background thread per configured host polls on its own schedule
//! (`poll_interval_secs`) and never blocks the 2s tick loop: [`collect`]
//! only ever reads the last-known-good cache, mirroring the
//! `DesktopRolloutScanner` idiom used for the Codex desktop-app rollout
//! scan elsewhere in this module.
//!
//! [`collect`]: RemoteCollector::collect

use super::{AgentCollector, SharedProcessData};
use crate::config::RemoteHostConfig;
use crate::model::{
    AgentSession, ChatMessage, ChatRole, ChildProcess, LaunchSurface, SessionStatus, SubAgent,
    ToolCall,
};
use serde::Deserialize;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// `ssh` gets this long (connect + remote `abtop --json` + transfer) before
/// we give up and kill it. Generous because a first connection (no
/// multiplexed master yet) does a full handshake.
const SSH_TIMEOUT: Duration = Duration::from_secs(20);
/// `ssh -o ConnectTimeout`: fail fast on an unreachable host rather than
/// waiting out the full `SSH_TIMEOUT` on a TCP connect that will never land.
const SSH_CONNECT_TIMEOUT_SECS: u64 = 5;

/// One host's poll state. Config plus the last-known-good result and enough
/// bookkeeping to run one fetch at a time on its own schedule.
struct RemoteHostState {
    cfg: RemoteHostConfig,
    /// Last-known-good sessions, shown (stale) even while unreachable —
    /// per the design doc, blanking a host on a transient failure is worse
    /// than a grayed-out "stale, Ns ago" row. Empty until the first success.
    cached_sessions: Vec<AgentSession>,
    reachable: bool,
    last_error: Option<String>,
    last_success_at: Option<Instant>,
    last_attempt_at: Option<Instant>,
    in_flight: bool,
    /// PID of the currently-running `ssh` child, if any (0 = none). Lets
    /// `Drop` reap a still-running poll instead of leaking it on exit,
    /// mirroring `DesktopRolloutScanner::child_pid`.
    child_pid: Arc<AtomicU32>,
    tx: Sender<RemoteFetchResult>,
    rx: Receiver<RemoteFetchResult>,
}

struct RemoteFetchResult {
    outcome: Result<Vec<AgentSession>, String>,
}

/// Point-in-time status for one configured host, for the UI (host-prefix
/// row + "stale, Ns ago" treatment — see Phase 3 in the design doc).
#[derive(Debug, Clone)]
pub struct RemoteHostStatus {
    pub name: String,
    pub reachable: bool,
    pub last_error: Option<String>,
    pub seconds_since_success: Option<u64>,
}

/// Polls `abtop --json` on each configured `[[remote_hosts]]` entry over
/// SSH and merges the sessions it reports, tagged with `host`.
pub struct RemoteCollector {
    hosts: Vec<RemoteHostState>,
    /// Directory backing SSH `ControlPath` sockets so repeated polls to the
    /// same host reuse one authenticated connection. `None` when the
    /// directory couldn't be created (e.g. no cache dir on this platform);
    /// polls still work, just without connection reuse.
    control_dir: Option<PathBuf>,
}

impl RemoteCollector {
    pub fn new(hosts: Vec<RemoteHostConfig>) -> Self {
        let control_dir = dirs::cache_dir()
            .map(|d| d.join("abtop").join("ssh"))
            .filter(|d| std::fs::create_dir_all(d).is_ok());
        Self {
            hosts: hosts.into_iter().map(RemoteHostState::new).collect(),
            control_dir,
        }
    }

    /// Status of every configured host, in config order. For the UI.
    pub fn host_statuses(&self) -> Vec<RemoteHostStatus> {
        self.hosts.iter().map(RemoteHostState::status).collect()
    }
}

impl AgentCollector for RemoteCollector {
    fn collect(&mut self, _shared: &SharedProcessData) -> Vec<AgentSession> {
        let mut all = Vec::new();
        for host in &mut self.hosts {
            host.poll_completed();
            if host.should_start() {
                host.start(self.control_dir.as_deref());
            }
            all.extend(host.cached_sessions.iter().cloned());
        }
        all
    }
}

impl RemoteHostState {
    fn new(cfg: RemoteHostConfig) -> Self {
        let (tx, rx) = mpsc::channel();
        Self {
            cfg,
            cached_sessions: Vec::new(),
            reachable: false,
            last_error: None,
            last_success_at: None,
            last_attempt_at: None,
            in_flight: false,
            child_pid: Arc::new(AtomicU32::new(0)),
            tx,
            rx,
        }
    }

    fn status(&self) -> RemoteHostStatus {
        RemoteHostStatus {
            name: self.cfg.name.clone(),
            reachable: self.reachable,
            last_error: self.last_error.clone(),
            seconds_since_success: self.last_success_at.map(|t| t.elapsed().as_secs()),
        }
    }

    fn poll_completed(&mut self) {
        while let Ok(result) = self.rx.try_recv() {
            self.in_flight = false;
            match result.outcome {
                Ok(sessions) => {
                    self.reachable = true;
                    self.last_error = None;
                    self.last_success_at = Some(Instant::now());
                    self.cached_sessions = sessions;
                }
                Err(err) => {
                    self.reachable = false;
                    self.last_error = Some(err);
                    // Keep serving the last-known-good sessions (stale) —
                    // see docs/design/remote-ssh-monitoring.md failure handling.
                }
            }
        }
    }

    /// Never faster than `poll_interval_secs`, and never a second poll while
    /// one is already in flight — a wedged SSH round trip must not pile up
    /// threads on a host that's just slow to answer.
    fn should_start(&self) -> bool {
        if self.in_flight {
            return false;
        }
        let interval = Duration::from_secs(self.cfg.poll_interval_secs.max(1));
        self.last_attempt_at
            .is_none_or(|started| started.elapsed() >= interval)
    }

    fn start(&mut self, control_dir: Option<&std::path::Path>) {
        self.in_flight = true;
        self.last_attempt_at = Some(Instant::now());
        let cfg = self.cfg.clone();
        let control_dir = control_dir.map(|p| p.to_path_buf());
        let tx = self.tx.clone();
        let child_pid = self.child_pid.clone();
        std::thread::spawn(move || {
            let outcome = fetch_remote_sessions(&cfg, control_dir.as_deref(), child_pid);
            let _ = tx.send(RemoteFetchResult { outcome });
        });
    }
}

impl Drop for RemoteHostState {
    fn drop(&mut self) {
        // Best-effort: reap a still-running `ssh` poll on exit rather than
        // leaking it. Matches the `kill -9` used by `App::kill_selected`
        // elsewhere in this codebase — no Windows-specific path, same as
        // there.
        let pid = self.child_pid.swap(0, Ordering::SeqCst);
        if pid != 0 {
            let _ = Command::new("kill").args(["-9", &pid.to_string()]).status();
        }
    }
}

/// Run `ssh <host> abtop --json`, parse the result, and map it to
/// `AgentSession`s tagged with this host's name. Blocking — call from a
/// background thread only.
fn fetch_remote_sessions(
    cfg: &RemoteHostConfig,
    control_dir: Option<&std::path::Path>,
    child_pid_slot: Arc<AtomicU32>,
) -> Result<Vec<AgentSession>, String> {
    let stdout_file =
        tempfile::NamedTempFile::new().map_err(|e| format!("failed to create temp file: {}", e))?;
    let stderr_file =
        tempfile::NamedTempFile::new().map_err(|e| format!("failed to create temp file: {}", e))?;
    let stdout_for_child = stdout_file
        .reopen()
        .map_err(|e| format!("failed to reopen temp file: {}", e))?;
    let stderr_for_child = stderr_file
        .reopen()
        .map_err(|e| format!("failed to reopen temp file: {}", e))?;

    let mut command = Command::new("ssh");
    command
        .arg("-o")
        .arg("BatchMode=yes") // never block on an interactive password prompt
        .arg("-o")
        .arg(format!("ConnectTimeout={}", SSH_CONNECT_TIMEOUT_SECS));
    // ControlMaster is a Unix-domain-socket feature; skip it on Windows
    // rather than risk an unsupported -o option failing the whole command.
    #[cfg(not(target_os = "windows"))]
    if let Some(dir) = control_dir {
        command
            .arg("-o")
            .arg("ControlMaster=auto")
            .arg("-o")
            .arg("ControlPersist=60s")
            .arg("-o")
            .arg(format!("ControlPath={}/%C", dir.display()));
    }
    command.args(&cfg.ssh_opts);
    command.arg(&cfg.ssh_target);
    command.args(["abtop", "--json"]);
    command
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout_for_child))
        .stderr(Stdio::from(stderr_for_child));

    let mut child = command
        .spawn()
        .map_err(|e| format!("failed to spawn ssh: {}", e))?;
    child_pid_slot.store(child.id(), Ordering::SeqCst);

    let started = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Ok(status),
            Ok(None) if started.elapsed() >= SSH_TIMEOUT => {
                let _ = Command::new("kill")
                    .args(["-9", &child.id().to_string()])
                    .status();
                let _ = child.wait();
                break Err(format!("ssh timed out after {:?}", SSH_TIMEOUT));
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(100)),
            Err(e) => break Err(format!("failed to wait on ssh: {}", e)),
        }
    };
    child_pid_slot.store(0, Ordering::SeqCst);
    let status = status?;

    if !status.success() {
        let stderr = std::fs::read_to_string(stderr_file.path()).unwrap_or_default();
        let stderr = stderr.trim();
        return Err(if stderr.is_empty() {
            format!("ssh exited with {}", status)
        } else {
            format!("ssh exited with {}: {}", status, stderr)
        });
    }

    let stdout = std::fs::read_to_string(stdout_file.path())
        .map_err(|e| format!("failed to read ssh output: {}", e))?;
    parse_remote_snapshot(&stdout, &cfg.name)
}

/// Parse `abtop --json` output into `AgentSession`s tagged with `host`.
/// Split out from [`fetch_remote_sessions`] so it can be unit tested without
/// spawning `ssh`.
fn parse_remote_snapshot(json: &str, host: &str) -> Result<Vec<AgentSession>, String> {
    let dto: RemoteSnapshotDto =
        serde_json::from_str(json).map_err(|e| format!("failed to parse remote JSON: {}", e))?;
    if dto.schema_version != crate::snapshot::SCHEMA_VERSION {
        return Err(format!(
            "remote abtop schema_version {} != {} (local); upgrade abtop on '{}'",
            dto.schema_version,
            crate::snapshot::SCHEMA_VERSION,
            host
        ));
    }
    Ok(dto
        .sessions
        .into_iter()
        .map(|s| s.into_agent_session(host))
        .collect())
}

/// Map a JSON `agent_cli` string to the matching interned `&'static str`
/// `AgentSession::agent_cli` requires. Falls back to `"unknown"` for a
/// value this build doesn't recognize (e.g. a newer remote abtop added an
/// agent type) rather than mislabeling it as one of the known three.
fn intern_agent_cli(s: &str) -> &'static str {
    match s {
        "claude" => "claude",
        "codex" => "codex",
        "opencode" => "opencode",
        _ => "unknown",
    }
}

/// Narrow, defensively-parsed mirror of `crate::snapshot::Snapshot`: only
/// the fields needed to rebuild an `AgentSession`. `#[serde(default)]`
/// (container-level, backed by `#[derive(Default)]`) means a missing or
/// renamed field degrades to its default instead of failing the whole
/// parse — the schema_version check above is what actually gates
/// compatibility.
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
struct RemoteSnapshotDto {
    schema_version: u32,
    sessions: Vec<RemoteSessionDto>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
struct RemoteSessionDto {
    agent_cli: String,
    launch_surface: LaunchSurface,
    pid: u32,
    session_id: String,
    project_name: String,
    cwd: String,
    config_root: String,
    status: SessionStatus,
    model: String,
    effort: String,
    version: String,
    context_percent: f64,
    context_window: u64,
    input_tokens: u64,
    output_tokens: u64,
    cache_read_tokens: u64,
    cache_create_tokens: u64,
    turn_count: u32,
    mem_mb: u64,
    git_branch: String,
    git_added: u32,
    git_modified: u32,
    started_at_ms: u64,
    summary: String,
    children: Vec<ChildProcess>,
    compaction_count: u32,
    token_history: Vec<u64>,
    subagents: Vec<RemoteSubAgentDto>,
    tool_calls: Vec<RemoteToolCallDto>,
    chat_messages: Vec<RemoteChatMsgDto>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
struct RemoteSubAgentDto {
    name: String,
    status: String,
    tokens: u64,
}

impl From<RemoteSubAgentDto> for SubAgent {
    fn from(d: RemoteSubAgentDto) -> Self {
        SubAgent {
            name: d.name,
            status: d.status,
            tokens: d.tokens,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
struct RemoteToolCallDto {
    name: String,
    arg: String,
    duration_ms: u64,
}

impl From<RemoteToolCallDto> for ToolCall {
    fn from(d: RemoteToolCallDto) -> Self {
        ToolCall {
            name: d.name,
            arg: d.arg,
            duration_ms: d.duration_ms,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
struct RemoteChatMsgDto {
    role: String,
    text: String,
}

impl From<RemoteChatMsgDto> for ChatMessage {
    fn from(d: RemoteChatMsgDto) -> Self {
        ChatMessage {
            role: if d.role == "assistant" {
                ChatRole::Assistant
            } else {
                ChatRole::User
            },
            text: d.text,
        }
    }
}

impl RemoteSessionDto {
    fn into_agent_session(self, host: &str) -> AgentSession {
        AgentSession {
            agent_cli: intern_agent_cli(&self.agent_cli),
            launch_surface: self.launch_surface,
            pid: self.pid,
            session_id: self.session_id,
            cwd: self.cwd,
            project_name: self.project_name,
            started_at: self.started_at_ms,
            status: self.status,
            model: self.model,
            effort: self.effort,
            context_percent: self.context_percent,
            total_input_tokens: self.input_tokens,
            total_output_tokens: self.output_tokens,
            total_cache_read: self.cache_read_tokens,
            total_cache_create: self.cache_create_tokens,
            turn_count: self.turn_count,
            current_tasks: Vec::new(),
            mem_mb: self.mem_mb,
            version: self.version,
            git_branch: self.git_branch,
            git_added: self.git_added,
            git_modified: self.git_modified,
            token_history: self.token_history,
            // Per-turn context history isn't on the wire (SessionView omits
            // it); the context-evolution sparkline just has nothing to show
            // for remote sessions rather than a misleading local guess.
            context_history: Vec::new(),
            compaction_count: self.compaction_count,
            context_window: self.context_window,
            subagents: self.subagents.into_iter().map(Into::into).collect(),
            // Memory file/line counts read `~/.claude/.../memory/` locally;
            // no remote equivalent is on the wire.
            mem_file_count: 0,
            mem_line_count: 0,
            children: self.children,
            // The remote already computed a final display summary (cached
            // LLM title, or its own sanitized-prompt fallback); reuse it
            // as `initial_prompt` so `App::session_summary` picks it up
            // directly. `App::drain_and_retry_summaries` must skip
            // `host.is_some()` sessions so this never triggers a *second*,
            // local `claude --print` call over the same text.
            initial_prompt: self.summary,
            first_assistant_text: String::new(),
            chat_messages: self.chat_messages.into_iter().map(Into::into).collect(),
            tool_calls: self.tool_calls.into_iter().map(Into::into).collect(),
            pending_since_ms: 0,
            thinking_since_ms: 0,
            file_accesses: Vec::new(),
            config_root: self.config_root,
            host: Some(host.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_json(schema_version: u32) -> String {
        format!(
            r#"{{
                "schema_version": {schema_version},
                "generated_at_ms": 0,
                "host": null,
                "aggregate": {{}},
                "token_rate": 0.0,
                "interval_ms": 2000,
                "sessions": [{{
                    "host": null,
                    "agent_cli": "claude",
                    "launch_surface": "Ide",
                    "pid": 4242,
                    "session_id": "abc-123",
                    "project_name": "abtop",
                    "cwd": "/home/dev/abtop",
                    "config_root": "~/.claude",
                    "status": "Executing",
                    "model": "claude-opus-4-6",
                    "effort": "",
                    "version": "2.1.86",
                    "context_percent": 42.5,
                    "context_window": 200000,
                    "total_tokens": 1000,
                    "input_tokens": 400,
                    "output_tokens": 200,
                    "cache_read_tokens": 300,
                    "cache_create_tokens": 100,
                    "turn_count": 7,
                    "mem_mb": 128,
                    "git_branch": "main",
                    "git_added": 2,
                    "git_modified": 3,
                    "started_at_ms": 1000,
                    "elapsed_secs": 500,
                    "summary": "Fixing the payment webhook",
                    "current_task": "Edit src/pay.rs",
                    "children": [{{"pid": 99, "command": "node", "mem_kb": 1024, "port": 3000}}],
                    "compaction_count": 0,
                    "token_history": [10, 20, 30],
                    "subagents": [{{"name": "explore", "status": "done", "tokens": 500}}],
                    "tool_calls": [{{"name": "Edit", "arg": "src/pay.rs", "duration_ms": 120}}],
                    "chat_messages": [{{"role": "assistant", "text": "done"}}]
                }}],
                "rate_limits": [],
                "orphan_ports": [],
                "mcp_servers": []
            }}"#
        )
    }

    #[test]
    fn parses_a_well_formed_snapshot_and_tags_host() {
        let sessions =
            parse_remote_snapshot(&sample_json(crate::snapshot::SCHEMA_VERSION), "devbox")
                .expect("valid snapshot parses");
        assert_eq!(sessions.len(), 1);
        let s = &sessions[0];
        assert_eq!(s.host.as_deref(), Some("devbox"));
        assert_eq!(s.agent_cli, "claude");
        assert_eq!(s.launch_surface, LaunchSurface::Ide);
        assert_eq!(s.pid, 4242);
        assert_eq!(s.session_id, "abc-123");
        assert_eq!(s.model, "claude-opus-4-6");
        assert_eq!(s.status, SessionStatus::Executing);
        assert_eq!(s.total_input_tokens, 400);
        assert_eq!(s.total_cache_read, 300);
        assert_eq!(s.children.len(), 1);
        assert_eq!(s.children[0].port, Some(3000));
        assert_eq!(s.subagents.len(), 1);
        assert_eq!(s.tool_calls.len(), 1);
        assert_eq!(s.chat_messages.len(), 1);
        assert_eq!(s.chat_messages[0].role, ChatRole::Assistant);
        // The remote's precomputed summary becomes the display title source,
        // never raw transcript text.
        assert_eq!(s.initial_prompt, "Fixing the payment webhook");
        assert!(s.first_assistant_text.is_empty());
    }

    #[test]
    fn rejects_a_schema_version_mismatch_with_a_clear_message() {
        let err =
            parse_remote_snapshot(&sample_json(crate::snapshot::SCHEMA_VERSION + 1), "devbox")
                .unwrap_err();
        assert!(err.contains("schema_version"));
        assert!(err.contains("devbox"));
    }

    #[test]
    fn rejects_non_json_with_an_error_not_a_panic() {
        let err = parse_remote_snapshot("not json at all", "devbox").unwrap_err();
        assert!(err.contains("failed to parse"));
    }

    #[test]
    fn missing_optional_fields_default_instead_of_failing() {
        // A minimal, schema_version-only payload (e.g. an older remote
        // abtop that predates most SessionView fields) still parses.
        let json = format!(
            r#"{{"schema_version": {}, "sessions": []}}"#,
            crate::snapshot::SCHEMA_VERSION
        );
        let sessions = parse_remote_snapshot(&json, "devbox").expect("degrades, doesn't fail");
        assert!(sessions.is_empty());
    }

    #[test]
    fn session_missing_launch_surface_defaults_to_cli() {
        // An older remote abtop built before launch_surface existed (e.g.
        // one built from this branch alone, without the launch-surface
        // feature merged in) shouldn't fail to parse — every other field
        // in a minimal session object degrades the same way.
        let json = format!(
            r#"{{"schema_version": {}, "sessions": [{{"agent_cli": "claude", "pid": 1, "session_id": "s"}}]}}"#,
            crate::snapshot::SCHEMA_VERSION
        );
        let sessions = parse_remote_snapshot(&json, "devbox").expect("degrades, doesn't fail");
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].launch_surface, LaunchSurface::Cli);
    }

    #[test]
    fn unknown_agent_cli_falls_back_instead_of_mislabeling() {
        assert_eq!(intern_agent_cli("gemini"), "unknown");
        assert_eq!(intern_agent_cli("claude"), "claude");
    }

    #[test]
    fn host_statuses_reports_unreachable_before_first_poll() {
        let collector = RemoteCollector::new(vec![RemoteHostConfig {
            name: "devbox".into(),
            ssh_target: "devbox.internal".into(),
            ssh_opts: Vec::new(),
            poll_interval_secs: 10,
            allow_remote_kill: false,
        }]);
        let statuses = collector.host_statuses();
        assert_eq!(statuses.len(), 1);
        assert_eq!(statuses[0].name, "devbox");
        assert!(!statuses[0].reachable);
        assert!(statuses[0].seconds_since_success.is_none());
    }

    #[test]
    fn should_start_respects_poll_interval_and_in_flight_guard() {
        let mut host = RemoteHostState::new(RemoteHostConfig {
            name: "devbox".into(),
            ssh_target: "devbox.internal".into(),
            ssh_opts: Vec::new(),
            poll_interval_secs: 10,
            allow_remote_kill: false,
        });
        assert!(host.should_start(), "never polled yet");

        host.in_flight = true;
        assert!(!host.should_start(), "a poll is already running");

        host.in_flight = false;
        host.last_attempt_at = Some(Instant::now());
        assert!(!host.should_start(), "polled moments ago");
    }
}
