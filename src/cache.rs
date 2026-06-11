//! Commit-keyed verdict cache. For a package whose build inputs are fully
//! determined by its AUR package-base commit, the verdict is a pure function of
//! (commit, model): any edit to the package-base produces a new commit → a cache
//! miss → a fresh review. This makes re-runs of unchanged packages free (no API
//! call), the bulk of repeated `-Syu` activity.
//!
//! IMPORTANT: the commit alone does NOT capture *upstream* source bytes. A
//! `git+` source pinned only to a moving branch, or any `source=` URL with a
//! `SKIP` checksum, can change what makepkg fetches/builds WITHOUT changing the
//! AUR commit. The caller (main.rs) therefore bypasses this cache entirely for
//! packages with such mutable sources (see `sources::has_mutable_sources`), so a
//! stale "safe" verdict can never be replayed for content the model never saw.

use crate::review::Verdict;
use std::path::{Path, PathBuf};

fn slug(model: &str) -> String {
    model
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect()
}

fn path(cache_dir: &Path, commit: &str, model: &str) -> PathBuf {
    cache_dir
        .join("verdicts")
        .join(format!("{commit}-{}.json", slug(model)))
}

pub fn load(cache_dir: &Path, commit: &str, model: &str) -> Option<Verdict> {
    let text = std::fs::read_to_string(path(cache_dir, commit, model)).ok()?;
    serde_json::from_str(&text).ok()
}

pub fn store(cache_dir: &Path, commit: &str, model: &str, v: &Verdict) {
    let p = path(cache_dir, commit, model);
    if let Some(parent) = p.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Ok(text) = serde_json::to_string(v) {
        let _ = std::fs::write(p, text);
    }
}
