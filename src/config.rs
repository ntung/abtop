use std::path::PathBuf;

#[derive(Clone, Copy)]
pub struct PanelVisibility {
    pub context: bool,
    pub quota: bool,
    pub tokens: bool,
    pub projects: bool,
    pub ports: bool,
    pub sessions: bool,
    pub mcp: bool,
}

impl Default for PanelVisibility {
    fn default() -> Self {
        Self {
            context: true,
            quota: true,
            tokens: true,
            projects: true,
            ports: true,
            sessions: true,
            mcp: true,
        }
    }
}

/// One `[[remote_hosts]]` block: an SSH-reachable host to poll for remote
/// session monitoring (see docs/design/remote-ssh-monitoring.md). Read-only
/// config — nothing in the app writes this back, so `write_with_updates`'s
/// comment/unknown-key preservation never needs to reproduce it.
#[derive(Clone, Debug, PartialEq)]
pub struct RemoteHostConfig {
    /// Display name, e.g. "devbox". Used as the `host` tag on remote
    /// sessions and must be non-empty for the entry to be kept.
    pub name: String,
    /// `ssh` destination, e.g. "devbox.internal" or "user@host". Must be
    /// non-empty for the entry to be kept.
    pub ssh_target: String,
    /// Extra arguments passed to `ssh` verbatim, e.g. `["-p", "2222"]`.
    pub ssh_opts: Vec<String>,
    /// How often to poll this host, in seconds.
    pub poll_interval_secs: u64,
    /// Whether `x`/`X` kill actions may target this host's sessions/ports.
    /// Defaults to `false`: SIGKILL over SSH on a box you don't locally
    /// control is a materially different risk than local kill.
    pub allow_remote_kill: bool,
}

impl Default for RemoteHostConfig {
    fn default() -> Self {
        Self {
            name: String::new(),
            ssh_target: String::new(),
            ssh_opts: Vec::new(),
            poll_interval_secs: 10,
            allow_remote_kill: false,
        }
    }
}

pub struct AppConfig {
    pub theme: String,
    /// Agent CLI names to exclude from the TUI (e.g. ["codex"] to hide Codex).
    /// Matched case-insensitively against each collector's agent_cli identifier.
    pub hidden_agents: Vec<String>,
    /// Additional Claude config directories to scan for sessions.
    /// Useful for multi-profile setups that use separate CLAUDE_CONFIG_DIR roots.
    pub claude_config_dirs: Vec<PathBuf>,
    pub panels: PanelVisibility,
    /// UI language override. Empty string means auto-detect from `LANG`.
    /// Recognized values: "en", "zh" (anything starting with "zh" maps to Simplified Chinese).
    pub language: String,
    /// SSH-reachable hosts to poll for remote session monitoring, from
    /// `[[remote_hosts]]` blocks. Empty unless configured.
    pub remote_hosts: Vec<RemoteHostConfig>,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            theme: "btop".to_string(),
            hidden_agents: Vec::new(),
            claude_config_dirs: Vec::new(),
            panels: PanelVisibility::default(),
            language: String::new(),
            remote_hosts: Vec::new(),
        }
    }
}

fn config_path() -> Option<PathBuf> {
    dirs::config_dir().map(|d| d.join("abtop").join("config.toml"))
}

pub fn load_config() -> AppConfig {
    let path = match config_path() {
        Some(p) => p,
        None => return AppConfig::default(),
    };

    let content = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(_) => return AppConfig::default(),
    };

    parse_config_body(&content)
}

fn parse_config_body(content: &str) -> AppConfig {
    let mut config = AppConfig::default();
    // `true` while inside a `[[remote_hosts]]` block, i.e. until the next
    // table header (of any kind) or EOF — same scoping TOML itself uses for
    // array-of-tables. There's exactly one supported table shape today, so
    // this is a bool rather than a general section stack.
    let mut in_remote_host = false;
    for line in content.lines() {
        let line = line.trim();
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        // Strip inline comments up front so table headers (no `=`) get the
        // same `# comment` handling as key/value lines below.
        let line = match line.find('#') {
            Some(pos) => line[..pos].trim(),
            None => line,
        };
        if line.is_empty() {
            continue;
        }
        if let Some(inner) = line.strip_prefix("[[").and_then(|s| s.strip_suffix("]]")) {
            in_remote_host = inner.trim() == "remote_hosts";
            if in_remote_host {
                config.remote_hosts.push(RemoteHostConfig::default());
            }
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            // Any other (currently unsupported) table header ends the
            // remote_hosts block rather than letting its keys leak in.
            in_remote_host = false;
            continue;
        }
        if let Some((key, val)) = line.split_once('=') {
            let key = key.trim();
            let val = val.trim();
            if in_remote_host {
                // `push` above guarantees a current entry whenever this flag is set.
                if let Some(host) = config.remote_hosts.last_mut() {
                    apply_remote_host_key(host, key, val);
                }
                continue;
            }
            if key == "hidden_agents" {
                config.hidden_agents = parse_string_array(val);
                continue;
            }
            if key == "claude_config_dirs" {
                config.claude_config_dirs = parse_path_array(val);
                continue;
            }
            let val = val.trim_matches('"').trim_matches('\'');
            match key {
                "theme" => config.theme = val.to_string(),
                "language" => config.language = val.to_string(),
                "show_context" => config.panels.context = parse_bool(val).unwrap_or(true),
                "show_quota" => config.panels.quota = parse_bool(val).unwrap_or(true),
                "show_tokens" => config.panels.tokens = parse_bool(val).unwrap_or(true),
                "show_projects" => config.panels.projects = parse_bool(val).unwrap_or(true),
                "show_ports" => config.panels.ports = parse_bool(val).unwrap_or(true),
                "show_sessions" => config.panels.sessions = parse_bool(val).unwrap_or(true),
                "show_mcp" => config.panels.mcp = parse_bool(val).unwrap_or(true),
                _ => {}
            }
        }
    }
    // Drop entries missing a name or ssh_target — nothing downstream can
    // address a host without both, and config loading must stay infallible
    // rather than surface a parse error for a malformed block.
    config
        .remote_hosts
        .retain(|h| !h.name.is_empty() && !h.ssh_target.is_empty());
    config
}

/// Apply one `key = value` line from inside a `[[remote_hosts]]` block.
/// Unknown keys are ignored (defensive parsing, matches the top-level
/// parser's behavior for forward/backward config compatibility).
fn apply_remote_host_key(host: &mut RemoteHostConfig, key: &str, val: &str) {
    if key == "ssh_opts" {
        host.ssh_opts = parse_string_array(val);
        return;
    }
    let quoted = val.trim_matches('"').trim_matches('\'');
    match key {
        "name" => host.name = quoted.to_string(),
        "ssh_target" => host.ssh_target = quoted.to_string(),
        "poll_interval_secs" => {
            if let Ok(secs) = val.trim().parse::<u64>() {
                host.poll_interval_secs = secs;
            }
        }
        "allow_remote_kill" => {
            host.allow_remote_kill = parse_bool(val).unwrap_or(false);
        }
        _ => {}
    }
}

fn parse_bool(raw: &str) -> Option<bool> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "true" => Some(true),
        "false" => Some(false),
        _ => None,
    }
}

/// Parse a simple one-line TOML string array like `["a", "b"]`.
/// Returns an empty Vec for malformed input to keep config loading infallible.
fn parse_string_array(raw: &str) -> Vec<String> {
    let trimmed = raw.trim();
    let Some(inner) = trimmed.strip_prefix('[').and_then(|s| s.strip_suffix(']')) else {
        return Vec::new();
    };
    inner
        .split(',')
        .map(|s| s.trim().trim_matches('"').trim_matches('\'').to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

fn parse_path_array(raw: &str) -> Vec<PathBuf> {
    parse_string_array(raw)
        .into_iter()
        .map(|s| expand_home_path(&s))
        .collect()
}

fn expand_home_path(raw: &str) -> PathBuf {
    if raw == "~" {
        if let Some(home) = dirs::home_dir() {
            return home;
        }
    }
    if let Some(rest) = raw.strip_prefix("~/") {
        if let Some(home) = dirs::home_dir() {
            return home.join(rest);
        }
    }
    PathBuf::from(raw)
}

pub fn save_theme(name: &str) -> Result<(), String> {
    write_with_updates(&[("theme", format!("\"{}\"", name))])
}

pub fn save_panel_visibility(panels: &PanelVisibility) -> Result<(), String> {
    write_with_updates(&[
        ("show_context", panels.context.to_string()),
        ("show_quota", panels.quota.to_string()),
        ("show_tokens", panels.tokens.to_string()),
        ("show_projects", panels.projects.to_string()),
        ("show_ports", panels.ports.to_string()),
        ("show_sessions", panels.sessions.to_string()),
        ("show_mcp", panels.mcp.to_string()),
    ])
}

/// Read the config, replace or append each (key, value) pair, write it back.
/// Lines that don't match any key are preserved verbatim so unknown keys and
/// comments survive saves driven by unrelated parts of the UI.
fn write_with_updates(updates: &[(&str, String)]) -> Result<(), String> {
    let path = config_path().ok_or("no config directory")?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let content = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => return Err(e.to_string()),
    };
    let new_content = rewrite_kv_lines(&content, updates);
    std::fs::write(&path, new_content).map_err(|e| e.to_string())
}

/// Rewrite (or append) the listed `key = value` lines in a config body.
/// Every other line is preserved verbatim so keys set by the user or by a
/// different save_* helper survive.
fn rewrite_kv_lines(content: &str, updates: &[(&str, String)]) -> String {
    let mut found = vec![false; updates.len()];
    let mut out: Vec<String> = Vec::new();
    for line in content.lines() {
        let line_key = line.split_once('=').map(|(k, _)| k.trim().to_string());
        let mut replaced = false;
        if let Some(key) = line_key {
            if let Some(idx) = updates.iter().position(|(k, _)| *k == key) {
                out.push(format!("{} = {}", updates[idx].0, updates[idx].1));
                found[idx] = true;
                replaced = true;
            }
        }
        if !replaced {
            out.push(line.to_string());
        }
    }
    for (idx, (k, v)) in updates.iter().enumerate() {
        if !found[idx] {
            out.push(format!("{} = {}", k, v));
        }
    }
    out.join("\n") + "\n"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_config_body_reads_a_full_remote_host_block() {
        let cfg = parse_config_body(
            r#"
[[remote_hosts]]
name = "devbox"
ssh_target = "devbox.internal"
ssh_opts = ["-p", "2222"]
poll_interval_secs = 30
allow_remote_kill = true
"#,
        );
        assert_eq!(
            cfg.remote_hosts,
            vec![RemoteHostConfig {
                name: "devbox".into(),
                ssh_target: "devbox.internal".into(),
                ssh_opts: vec!["-p".into(), "2222".into()],
                poll_interval_secs: 30,
                allow_remote_kill: true,
            }]
        );
    }

    #[test]
    fn parse_config_body_applies_remote_host_defaults_for_omitted_keys() {
        // poll_interval_secs and allow_remote_kill are safety/perf defaults
        // (10s poll, kill disabled) when a block doesn't set them.
        let cfg = parse_config_body(
            r#"
[[remote_hosts]]
name = "devbox"
ssh_target = "devbox.internal"
"#,
        );
        let host = &cfg.remote_hosts[0];
        assert_eq!(host.poll_interval_secs, 10);
        assert!(!host.allow_remote_kill);
        assert!(host.ssh_opts.is_empty());
    }

    #[test]
    fn parse_config_body_reads_multiple_remote_host_blocks() {
        let cfg = parse_config_body(
            r#"
[[remote_hosts]]
name = "devbox"
ssh_target = "devbox.internal"

[[remote_hosts]]
name = "gpu-box"
ssh_target = "gpu.internal"
"#,
        );
        assert_eq!(cfg.remote_hosts.len(), 2);
        assert_eq!(cfg.remote_hosts[0].name, "devbox");
        assert_eq!(cfg.remote_hosts[1].name, "gpu-box");
    }

    #[test]
    fn parse_config_body_drops_remote_host_missing_required_fields() {
        // A block missing `name` or `ssh_target` can't be addressed by
        // anything downstream, so it's dropped rather than kept half-formed.
        let cfg = parse_config_body(
            r#"
[[remote_hosts]]
ssh_target = "devbox.internal"

[[remote_hosts]]
name = "no-target"
"#,
        );
        assert!(cfg.remote_hosts.is_empty());
    }

    #[test]
    fn parse_config_body_ignores_inline_comment_on_table_header() {
        let cfg = parse_config_body(
            r#"
[[remote_hosts]] # my dev box
name = "devbox"
ssh_target = "devbox.internal"
"#,
        );
        assert_eq!(cfg.remote_hosts.len(), 1);
    }

    #[test]
    fn parse_config_body_keeps_top_level_keys_working_alongside_remote_hosts() {
        let cfg = parse_config_body(
            r#"
theme = "dracula"
[[remote_hosts]]
name = "devbox"
ssh_target = "devbox.internal"
"#,
        );
        assert_eq!(cfg.theme, "dracula");
        assert_eq!(cfg.remote_hosts.len(), 1);
    }

    #[test]
    fn rewrite_kv_lines_leaves_a_remote_hosts_block_untouched() {
        // remote_hosts is read-only from the app's perspective (only ever
        // hand-edited); a save_* call for an unrelated key must not mangle it.
        let before = "theme = \"btop\"\n[[remote_hosts]]\nname = \"devbox\"\nssh_target = \"devbox.internal\"\n";
        let after = rewrite_kv_lines(before, &theme_update("nord"));
        assert!(after.contains("[[remote_hosts]]"));
        assert!(after.contains("name = \"devbox\""));
        assert!(after.contains("ssh_target = \"devbox.internal\""));
        assert!(after.contains("theme = \"nord\""));
        // And the rewritten body still parses back to the same host.
        let cfg = parse_config_body(&after);
        assert_eq!(cfg.remote_hosts[0].name, "devbox");
    }

    #[test]
    fn parse_string_array_basic() {
        assert_eq!(parse_string_array(r#"["codex"]"#), vec!["codex"]);
        assert_eq!(
            parse_string_array(r#"["codex", "claude"]"#),
            vec!["codex", "claude"]
        );
    }

    #[test]
    fn parse_string_array_quote_styles_and_whitespace() {
        assert_eq!(
            parse_string_array(r#"[ 'codex' , "claude" ]"#),
            vec!["codex", "claude"]
        );
    }

    #[test]
    fn parse_string_array_empty_and_malformed() {
        assert!(parse_string_array("[]").is_empty());
        assert!(parse_string_array("not an array").is_empty());
        assert!(parse_string_array(r#"["a",,]"#)
            .iter()
            .all(|s| !s.is_empty()));
    }

    #[test]
    fn parse_path_array_expands_home_relative_entries() {
        let home = dirs::home_dir().unwrap();
        let paths = parse_path_array(r#"["~/.claude-personal", "/tmp/.claude-work"]"#);

        assert_eq!(paths[0], home.join(".claude-personal"));
        assert_eq!(paths[1], PathBuf::from("/tmp/.claude-work"));
    }

    #[test]
    fn parse_config_body_loads_claude_config_dirs() {
        let home = dirs::home_dir().unwrap();
        let cfg = parse_config_body(r#"claude_config_dirs = ["~/.claude-personal"]"#);

        assert_eq!(cfg.claude_config_dirs, vec![home.join(".claude-personal")]);
    }

    fn theme_update(name: &str) -> Vec<(&'static str, String)> {
        vec![("theme", format!("\"{}\"", name))]
    }

    #[test]
    fn rewrite_theme_preserves_hidden_agents_line() {
        let before = "theme = \"btop\"\nhidden_agents = [\"codex\"]\n";
        let after = rewrite_kv_lines(before, &theme_update("dracula"));
        assert!(after.contains("theme = \"dracula\""));
        assert!(
            after.contains("hidden_agents = [\"codex\"]"),
            "hidden_agents line dropped:\n{after}"
        );
    }

    #[test]
    fn rewrite_theme_preserves_arbitrary_unknown_keys() {
        let before = "# user comment\nfuture_key = 42\ntheme = \"btop\"\n";
        let after = rewrite_kv_lines(before, &theme_update("nord"));
        assert!(after.contains("# user comment"));
        assert!(after.contains("future_key = 42"));
        assert!(after.contains("theme = \"nord\""));
    }

    #[test]
    fn rewrite_theme_appends_when_missing() {
        let before = "hidden_agents = [\"codex\"]\n";
        let after = rewrite_kv_lines(before, &theme_update("gruvbox"));
        assert!(after.contains("hidden_agents = [\"codex\"]"));
        assert!(after.contains("theme = \"gruvbox\""));
    }

    #[test]
    fn rewrite_panels_replaces_existing_and_appends_missing() {
        let before = "theme = \"btop\"\nshow_quota = true\n";
        let updates: Vec<(&str, String)> = vec![
            ("show_quota", "false".to_string()),
            ("show_projects", "false".to_string()),
        ];
        let after = rewrite_kv_lines(before, &updates);
        assert!(after.contains("show_quota = false"));
        assert!(!after.contains("show_quota = true"));
        assert!(after.contains("show_projects = false"));
        assert!(after.contains("theme = \"btop\""));
    }

    #[test]
    fn parse_bool_round_trips_visibility_keys() {
        assert_eq!(parse_bool("true"), Some(true));
        assert_eq!(parse_bool("False"), Some(false));
        assert_eq!(parse_bool("nope"), None);
    }

    #[test]
    fn rewrite_language_replaces_existing() {
        let before = "theme = \"btop\"\nlanguage = \"en\"\n";
        let updates: Vec<(&str, String)> = vec![("language", "\"zh\"".to_string())];
        let after = rewrite_kv_lines(before, &updates);
        assert!(after.contains("language = \"zh\""));
        assert!(!after.contains("language = \"en\""));
        assert!(after.contains("theme = \"btop\""));
    }
}
