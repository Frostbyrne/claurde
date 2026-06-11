use anyhow::Result;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::io::Read;
use std::path::Path;
use std::process::Command;

/// Per-file cap and overall cap on evidence sent to the model. Oversized
/// content is truncated with an explicit marker so the model knows the
/// review is partial (partial review => lower confidence, never higher).
const PER_FILE_CAP: usize = 60_000;
const TOTAL_CAP: usize = 600_000;
/// Refuse to read a single AUR-repo file larger than this into memory before
/// the byte cap applies (an attacker could otherwise OOM the review with a
/// multi-GB PKGBUILD/patch). Generous — real package files are tiny.
const REPO_FILE_CAP: u64 = 4_000_000;

pub struct Evidence {
    /// Random per-run boundary tag. Package content cannot forge it because it
    /// is generated after the package content was committed to the AUR.
    pub nonce: String,
    pub sections: Vec<(String, String)>, // (label, content)
    pub truncated: bool,
}

pub fn nonce() -> String {
    // The fence token must be unguessable: a package author who could predict it
    // could embed the matching closing marker and break out of the untrusted-data
    // fence. Use the OS CSPRNG (128 bits); fall back to a time/pid hash only if
    // /dev/urandom is somehow unavailable.
    let mut buf = [0u8; 16];
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        if f.read_exact(&mut buf).is_ok() {
            return buf.iter().map(|b| format!("{b:02x}")).collect();
        }
    }
    let mut h = DefaultHasher::new();
    std::time::SystemTime::now().hash(&mut h);
    std::process::id().hash(&mut h);
    std::time::Instant::now().elapsed().hash(&mut h);
    format!("{:016x}", h.finish())
}

/// Neutralize content before embedding it inside our boundary tags:
/// - strip any occurrence of the run nonce (forged closing tags become inert)
/// - strip ASCII control chars except \n and \t (no terminal escape smuggling)
/// - strip Unicode bidi overrides/isolates, zero-width chars and the BOM —
///   invisible channels that could smuggle reviewer-directed text past the
///   "this is data" framing or hide what code actually does.
fn sanitize(raw: &str, nonce: &str) -> String {
    raw.replace(nonce, "[NONCE-COLLISION-REMOVED]")
        .chars()
        .filter(|c| {
            if *c == '\n' || *c == '\t' {
                return true;
            }
            if c.is_control() {
                return false;
            }
            !matches!(*c,
                '\u{200B}'..='\u{200F}'   // zero-width space/joiner, LRM/RLM
                | '\u{202A}'..='\u{202E}' // bidi embeddings/overrides
                | '\u{2060}'..='\u{2064}' // word joiner, invisible operators
                | '\u{2066}'..='\u{2069}' // bidi isolates
                | '\u{FEFF}')             // BOM / zero-width no-break space
        })
        .collect()
}

/// First 8KB contains a NUL byte → treat as binary (don't inline as text).
fn looks_binary(path: &Path) -> bool {
    let mut buf = [0u8; 8192];
    if let Ok(mut f) = std::fs::File::open(path) {
        if let Ok(n) = f.read(&mut buf) {
            return buf[..n].contains(&0);
        }
    }
    false
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

/// Run a read-only git command in `repo`. Returns None if git failed to run or
/// exited non-zero — distinct from Some("") (ran, no output). The caller turns
/// a None into an explicit "evidence missing" note so a git failure can't
/// silently erase the recent-change signals the review leans on.
fn git(repo: &Path, args: &[&str]) -> Option<String> {
    let out = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(args)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Files committed to the AUR package-base repo that we DON'T inline. Only
/// `.SRCINFO` (derived metadata, parsed separately) is excluded — everything
/// else a maintainer commits (helper .c/.rs/.go sources, a Makefile/CMakeLists,
/// a `.conf`, an extensionless `helper`, …) can be a build input the PKGBUILD
/// compiles or runs, so an allowlist of extensions would silently hide a
/// payload from review. Inline all of it; flag (don't drop) anything unreadable.
fn skip_repo_file(name: &str) -> bool {
    name == ".SRCINFO"
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

    // Files — PKGBUILD first so it always survives the total cap. Every
    // committed repo file is reviewed (or explicitly flagged), never silently
    // skipped by extension — a non-allowlisted local source is exactly how a
    // payload would hide from the model while makepkg still compiles it.
    let mut names: Vec<String> = std::fs::read_dir(repo)?
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().map(|t| t.is_file()).unwrap_or(false))
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| !skip_repo_file(n))
        .collect();
    names.sort_by_key(|n| (n != "PKGBUILD", n.clone()));
    for name in names {
        let path = repo.join(&name);
        let size = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
        if size > REPO_FILE_CAP {
            upstream_partial = true;
            sections.push((
                format!("file: {name}"),
                format!("[repo file is {size} bytes — too large to inline; review is PARTIAL, treat as a finding]"),
            ));
        } else if looks_binary(&path) {
            upstream_partial = true;
            sections.push((
                format!("file: {name}"),
                "[binary/non-text file committed to the AUR repo — claurde could not inline it; treat as a finding]"
                    .to_string(),
            ));
        } else if let Ok(raw) = std::fs::read_to_string(&path) {
            push(format!("file: {name}"), raw, &mut sections);
        } else {
            upstream_partial = true;
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

    // Recent history: who changed what, and the actual diffs of the last N
    // commits. A git FAILURE (None) is flagged as partial coverage — the
    // system prompt leans on these for the "recent change / new maintainer /
    // coordinated push" signals, so silently omitting them would bias toward
    // a falsely-clean verdict. A genuinely empty result on success is fine.
    let has_git = repo.join(".git").is_dir();
    match git(repo, &["log", "--format=%h %ad %an <%ae>%n  %s", "--date=short", "-n", "30"]) {
        Some(log) if !log.trim().is_empty() => {
            push("git history (last 30 commits)".into(), log, &mut sections)
        }
        Some(_) => {}
        None if has_git => {
            upstream_partial = true;
            sections.push((
                "git history".into(),
                "[git log failed — recent-change evidence is MISSING; review is PARTIAL, do not treat absence as a clean history]".into(),
            ));
        }
        None => {}
    }
    let n = max_diff_commits.to_string();
    match git(repo, &["log", "-p", "--format=commit %h %ad %an: %s", "--date=short", "-n", &n, "--", ".", ":!.SRCINFO"]) {
        Some(diffs) if !diffs.trim().is_empty() => {
            push(format!("diffs of last {n} commits"), diffs, &mut sections)
        }
        Some(_) => {}
        None if has_git => {
            upstream_partial = true;
            sections.push((
                "recent diffs".into(),
                "[git diff failed — recent-change evidence is MISSING; review is PARTIAL]".into(),
            ));
        }
        None => {}
    }

    Ok(Evidence { nonce, sections, truncated: truncated || upstream_partial })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_strips_controls_nonce_and_invisible_unicode() {
        let nonce = "abc123";
        let raw = format!("ok\ttab\nline {nonce} \u{1b}[2J \u{202e}rtl \u{200b}zw end");
        let out = sanitize(&raw, nonce);
        assert!(out.contains('\n') && out.contains('\t'), "newlines/tabs kept");
        assert!(!out.contains(nonce), "nonce stripped");
        assert!(!out.contains('\u{1b}'), "ESC stripped");
        assert!(!out.contains('\u{202e}'), "bidi override stripped");
        assert!(!out.contains('\u{200b}'), "zero-width stripped");
        assert!(out.contains("rtl") && out.contains("zw"), "visible text retained");
    }
}
