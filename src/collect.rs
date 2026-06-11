use anyhow::Result;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::path::Path;
use std::process::Command;

/// Per-file cap and overall cap on evidence sent to the model. Oversized
/// content is truncated with an explicit marker so the model knows the
/// review is partial (partial review => lower confidence, never higher).
const PER_FILE_CAP: usize = 60_000;
const TOTAL_CAP: usize = 600_000;

pub struct Evidence {
    /// Random per-run boundary tag. Package content cannot forge it because it
    /// is generated after the package content was committed to the AUR.
    pub nonce: String,
    pub sections: Vec<(String, String)>, // (label, content)
    pub truncated: bool,
}

pub fn nonce() -> String {
    let mut h = DefaultHasher::new();
    std::time::SystemTime::now().hash(&mut h);
    std::process::id().hash(&mut h);
    std::time::Instant::now().elapsed().hash(&mut h);
    format!("{:016x}", h.finish())
}

/// Neutralize content before embedding it inside our boundary tags:
/// - strip any occurrence of the run nonce (forged closing tags become inert)
/// - strip ASCII control chars except \n and \t (no terminal escape smuggling,
///   no invisible-text tricks in the prompt)
fn sanitize(raw: &str, nonce: &str) -> String {
    raw.replace(nonce, "[NONCE-COLLISION-REMOVED]")
        .chars()
        .filter(|c| *c == '\n' || *c == '\t' || !c.is_control())
        .collect()
}

fn cap(mut s: String, limit: usize) -> (String, bool) {
    if s.len() <= limit {
        return (s, false);
    }
    let mut cut = limit;
    while !s.is_char_boundary(cut) {
        cut -= 1;
    }
    s.truncate(cut);
    s.push_str("\n[TRUNCATED BY CLAURDE — content exceeded size limit; review is partial]");
    (s, true)
}

fn git(repo: &Path, args: &[&str]) -> String {
    Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(args)
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default()
}

/// Files in the AUR repo worth reviewing: PKGBUILD, install scriptlets,
/// patches, local scripts/sources. Skip .SRCINFO (derived) and binaries.
fn reviewable(name: &str) -> bool {
    if name == ".SRCINFO" || name.starts_with('.') {
        return name == ".install";
    }
    name == "PKGBUILD"
        || name.ends_with(".install")
        || name.ends_with(".sh")
        || name.ends_with(".bash")
        || name.ends_with(".py")
        || name.ends_with(".pl")
        || name.ends_with(".patch")
        || name.ends_with(".diff")
        || name.ends_with(".service")
        || name.ends_with(".hook")
        || name.ends_with(".desktop")
}

pub fn collect(
    repo: &Path,
    pkgbase: &str,
    commit: Option<&str>,
    cache_dir: &Path,
    max_diff_commits: usize,
    fetch_sources: bool,
) -> Result<Evidence> {
    let nonce = nonce();
    let mut sections = Vec::new();
    let mut truncated = false;
    let mut total = 0usize;
    // Set outside the `push` closure (which captures `truncated`); OR'd in at the end.
    let mut upstream_partial = false;

    let mut push = |label: String, raw: String, sections: &mut Vec<(String, String)>| {
        let (content, t) = cap(sanitize(&raw, &nonce), PER_FILE_CAP.min(TOTAL_CAP.saturating_sub(total)));
        total += content.len();
        truncated |= t;
        sections.push((label, content));
    };

    // Files — PKGBUILD first so it always survives the total cap.
    let mut entries: Vec<_> = std::fs::read_dir(repo)?
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().map(|t| t.is_file()).unwrap_or(false))
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| reviewable(n))
        .collect();
    entries.sort_by_key(|n| (n != "PKGBUILD", n.clone()));
    for name in entries {
        if let Ok(raw) = std::fs::read_to_string(repo.join(&name)) {
            push(format!("file: {name}"), raw, &mut sections);
        } else {
            sections.push((
                format!("file: {name}"),
                "[non-UTF8 file present in repo — claurde could not inline it; treat as a finding]"
                    .to_string(),
            ));
        }
    }

    // Upstream sources: fetch what the package actually builds from and review
    // the high-signal files (manifests, lockfiles, build/lifecycle scripts).
    // This is where payloads hide that aren't in the PKGBUILD itself.
    if fetch_sources {
        let up = crate::sources::fetch(repo, pkgbase, commit, cache_dir);
        for (label, raw) in up.files {
            push(label, raw, &mut sections);
        }
        if !up.notes.is_empty() {
            upstream_partial = true; // partial coverage must not read as "fully clean"
            push("upstream source coverage notes".into(), up.notes.join("\n"), &mut sections);
        }
    }

    // Recent history: who changed what, and the actual diffs of the last N commits.
    let log = git(repo, &["log", "--format=%h %ad %an <%ae>%n  %s", "--date=short", "-n", "30"]);
    if !log.is_empty() {
        push("git history (last 30 commits)".into(), log, &mut sections);
    }
    let n = max_diff_commits.to_string();
    let diffs = git(repo, &["log", "-p", "--format=commit %h %ad %an: %s", "--date=short", "-n", &n, "--", ".", ":!.SRCINFO"]);
    if !diffs.is_empty() {
        push(format!("diffs of last {n} commits"), diffs, &mut sections);
    }

    Ok(Evidence { nonce, sections, truncated: truncated || upstream_partial })
}
