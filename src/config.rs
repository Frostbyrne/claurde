use anyhow::{bail, Context, Result};
use std::io::{IsTerminal, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::PathBuf;
use std::process::Command;

const KEYS_URL: &str = "https://platform.claude.com/settings/workspaces/default/keys";

/// Supported backends for the final build/install handoff. clAURde itself does
/// resolution, fetching, and review — the helper only builds what passed.
pub const KNOWN_HELPERS: &[&str] = &["paru", "yay", "pikaur", "trizen", "aura", "makepkg"];

pub struct Config {
    pub api_key: String,
    pub model: String,
    pub helper: String,
    pub max_diff_commits: usize,
    pub cache_dir: PathBuf,
}

fn config_dir() -> Option<PathBuf> {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))?;
    Some(base.join("claurde"))
}

fn config_path() -> Option<PathBuf> {
    config_dir().map(|d| d.join("config"))
}

/// Default location for an onboarding-stored key, written with 0600 perms.
fn default_key_file() -> Option<PathBuf> {
    config_dir().map(|d| d.join("api_key"))
}

/// Resolve the API key from every supported source, in precedence order:
/// env → config `api_key` → config `api_key_file` → the onboarding key file.
pub fn resolve_api_key() -> Option<String> {
    if let Ok(k) = std::env::var("ANTHROPIC_API_KEY") {
        if !k.is_empty() {
            return Some(k);
        }
    }
    let file: std::collections::HashMap<_, _> = read_config_file().into_iter().collect();
    if let Some(k) = file.get("api_key").filter(|k| !k.is_empty()) {
        return Some(k.clone());
    }
    if let Some(s) = file
        .get("api_key_file")
        .and_then(|p| std::fs::read_to_string(p).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
    {
        return Some(s);
    }
    default_key_file()
        .and_then(|p| std::fs::read_to_string(p).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Minimal key=value config file (no TOML dep). Lines starting with # ignored.
fn read_config_file() -> Vec<(String, String)> {
    let Some(path) = config_path() else { return vec![] };
    let Ok(text) = std::fs::read_to_string(path) else { return vec![] };
    text.lines()
        .filter_map(|l| {
            let l = l.trim();
            if l.is_empty() || l.starts_with('#') {
                return None;
            }
            let (k, v) = l.split_once('=')?;
            Some((k.trim().to_string(), v.trim().to_string()))
        })
        .collect()
}

fn is_installed(name: &str) -> bool {
    Command::new("which")
        .arg(name)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// All known helpers found on PATH, in our preference order. `makepkg` is
/// excluded here — it's the last-resort fallback, never auto-picked over a
/// real helper.
fn detect_helpers() -> Vec<String> {
    KNOWN_HELPERS
        .iter()
        .filter(|h| **h != "makepkg")
        .filter(|h| is_installed(h))
        .map(|h| h.to_string())
        .collect()
}

impl Config {
    pub fn load(model_flag: Option<String>, helper_flag: Option<String>) -> Result<Config> {
        let file: std::collections::HashMap<_, _> = read_config_file().into_iter().collect();

        let api_key = resolve_api_key().context(
            "No Anthropic API key found. Set ANTHROPIC_API_KEY, or put \
             `api_key = sk-ant-...` (or `api_key_file = /path`) in ~/.config/claurde/config. \
             Run clAURde in an interactive terminal to be guided through setup.",
        )?;

        // An explicit choice (flag > env > config) always wins and is never
        // second-guessed. Only when nothing is set do we auto-detect.
        let explicit = helper_flag
            .or_else(|| std::env::var("CLAURDE_HELPER").ok())
            .or_else(|| file.get("helper").cloned());

        let helper = match explicit {
            Some(h) => h,
            None => {
                let found = detect_helpers();
                match found.as_slice() {
                    [] => "makepkg".to_string(),
                    [only] => only.clone(),
                    [chosen, ..] => {
                        // Multiple helpers installed and no preference set —
                        // pick the highest-precedence one but say so, and show
                        // how to pin it.
                        eprintln!(
                            "note: multiple AUR helpers found ({}). Using '{chosen}'. \
                             Override with --helper, CLAURDE_HELPER, or `helper =` in config.",
                            found.join(", ")
                        );
                        chosen.clone()
                    }
                }
            }
        };
        if !KNOWN_HELPERS.contains(&helper.as_str()) {
            bail!("Unknown helper '{helper}'. Supported: {}", KNOWN_HELPERS.join(", "));
        }

        let cache_dir = std::env::var_os("XDG_CACHE_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".cache")))
            .context("Cannot determine cache directory")?
            .join("claurde");

        Ok(Config {
            api_key,
            model: model_flag
                .or_else(|| file.get("model").cloned())
                .unwrap_or_else(|| "claude-opus-4-8".to_string()),
            helper,
            max_diff_commits: file
                .get("max_diff_commits")
                .and_then(|v| v.parse().ok())
                .unwrap_or(5),
            cache_dir,
        })
    }
}

/// Read a line from the terminal with echo disabled (so a pasted key isn't
/// shown or left in scrollback). Uses `stty` to avoid pulling in a crate; if
/// `stty` isn't available the input is simply visible (still functional).
fn read_secret(prompt: &str) -> Result<String> {
    eprint!("{prompt}");
    std::io::stderr().flush().ok();
    let is_tty = std::io::stdin().is_terminal();
    if is_tty {
        let _ = Command::new("stty").arg("-echo").status();
    }
    let mut s = String::new();
    let res = std::io::stdin().read_line(&mut s);
    if is_tty {
        let _ = Command::new("stty").arg("echo").status();
        eprintln!(); // the user's Enter wasn't echoed; emit the newline ourselves
    }
    res.context("failed to read key from stdin")?;
    Ok(s.trim().to_string())
}

/// Write `contents` to `path` with 0600 permissions from creation.
fn write_secret_file(path: &PathBuf, contents: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
        let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
    }
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("cannot write key file {}", path.display()))?;
    f.write_all(contents.as_bytes())?;
    f.write_all(b"\n")?;
    // belt-and-suspenders in case the file pre-existed with looser perms
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    Ok(())
}

/// First-run onboarding: if no key is configured and we're on a terminal, walk
/// the user through creating one and store it securely. No-op (returns Ok) when
/// a key already exists or when not interactive — `Config::load` then surfaces
/// the actionable error for non-interactive runs.
pub fn ensure_api_key() -> Result<()> {
    if resolve_api_key().is_some() {
        return Ok(());
    }
    if !std::io::stdin().is_terminal() {
        return Ok(());
    }

    let path = default_key_file().context("cannot determine config directory")?;
    eprintln!();
    eprintln!("  Welcome to clAURde. It needs an Anthropic API key to review packages.");
    eprintln!();
    eprintln!("  1. Create a key (Anthropic Console):");
    eprintln!("       {KEYS_URL}");
    eprintln!("  2. Paste it below. Input is hidden, and the key is stored only at:");
    eprintln!("       {}  (permissions 0600)", path.display());
    eprintln!();

    let key = read_secret("  Anthropic API key: ")?;
    if key.is_empty() {
        bail!("No key entered — aborting setup.");
    }
    if key.contains(char::is_whitespace) {
        bail!("That key contains whitespace — it may have been truncated. Re-run and paste it again.");
    }
    if !key.starts_with("sk-ant-") {
        eprintln!("  note: that doesn't look like an Anthropic key (expected an 'sk-ant-' prefix). Storing it anyway.");
    }

    write_secret_file(&path, &key)?;
    eprintln!("  ✓ Key saved to {}. Continuing.", path.display());
    eprintln!();
    Ok(())
}
