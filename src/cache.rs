//! Commit-keyed verdict cache. A verdict is a pure function of (package
//! content, model). The AUR package-base git commit hash changes on ANY content
//! change, so caching on (commit, model) is safe: a malicious edit produces a
//! new commit → a cache miss → a fresh review. This makes re-runs of unchanged
//! packages free (no API call), which is the bulk of repeated `-Syu` activity.

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
