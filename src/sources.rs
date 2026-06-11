//! Fetch and inspect the *upstream* sources a package builds from — not just
//! the AUR repo files. This is what catches payloads that live in the fetched
//! source tree rather than the PKGBUILD (e.g. an npm `preinstall` lifecycle
//! hook, a poisoned lockfile pin, a committed binary blob).
//!
//! SAFETY: the source URLs are read from the **already-expanded** `.SRCINFO`
//! (`source = <url>` lines that makepkg wrote out), so clAURde never sources or
//! executes the PKGBUILD to learn them. Downloading a declared URL and reading
//! the bytes is not executing the package.

use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::process::Command;

/// Cap on a single source download. Big binary sources (e.g. a Chrome .deb)
/// aren't worth streaming in full — we note them and move on.
const MAX_DOWNLOAD: u64 = 64 * 1024 * 1024;
/// Most upstream-source files we'll inline for review.
const MAX_FILES: usize = 80;
/// Don't inline a single source file larger than this (lockfiles get truncated
/// by the caller's per-file cap instead).
const MAX_FILE_BYTES: u64 = 512 * 1024;
/// Bound the directory walk so a giant vendored tree can't stall a review.
const MAX_WALK_ENTRIES: usize = 40_000;

pub struct Upstream {
    /// (label, raw content) — fed through the same sanitize/cap pipeline as the
    /// AUR repo files by the caller.
    pub files: Vec<(String, String)>,
    /// Human-readable notes (oversized/binary sources we did NOT inline) so the
    /// reviewer knows coverage is partial and what was skipped.
    pub notes: Vec<String>,
}

/// Expanded remote source URLs from `.SRCINFO` (handles `source = ` and
/// arch-suffixed `source_x86_64 = `). Strips any `filename::` prefix and keeps
/// only entries with a URL scheme — bare filenames refer to local files already
/// reviewed from the AUR repo.
fn remote_sources(repo: &Path) -> Vec<String> {
    let Ok(text) = std::fs::read_to_string(repo.join(".SRCINFO")) else {
        return vec![];
    };
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        let Some((key, val)) = line.split_once('=') else { continue };
        let key = key.trim();
        if key != "source" && !key.starts_with("source_") {
            continue;
        }
        let val = val.trim();
        let url = val.rsplit("::").next().unwrap_or(val);
        if url.contains("://") {
            out.push(url.to_string());
        }
    }
    out
}

fn run(cmd: &str, args: &[&std::ffi::OsStr]) -> bool {
    Command::new(cmd)
        .args(args)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Download `url` to `dest`, capped. Returns Ok(true) if the whole body fit,
/// Ok(false) if it hit the cap (oversized — treat as not fully fetched).
fn download(url: &str, dest: &Path) -> std::io::Result<bool> {
    let resp = ureq::get(url)
        .set("User-Agent", "claurde/1.0")
        .call()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
    let mut reader = resp.into_reader().take(MAX_DOWNLOAD + 1);
    let mut f = File::create(dest)?;
    let n = std::io::copy(&mut reader, &mut f)?;
    Ok(n <= MAX_DOWNLOAD)
}

fn is_archive(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    [".tar.gz", ".tgz", ".tar.xz", ".txz", ".tar.zst", ".tar.bz2", ".tbz2", ".tar",
     ".zip", ".deb", ".gz", ".xz", ".zst", ".bz2", ".7z", ".rpm"]
        .iter()
        .any(|e| n.ends_with(e))
}

/// libarchive's `bsdtar` extracts tar/zip/deb/etc. with safe defaults
/// (rejects absolute paths and `..`). Extract into a fresh dir.
fn extract(archive: &Path, into: &Path) -> bool {
    let _ = std::fs::create_dir_all(into);
    run(
        "bsdtar",
        &[
            "-xf".as_ref(),
            archive.as_os_str(),
            "-C".as_ref(),
            into.as_os_str(),
        ],
    )
}

/// High-signal upstream files: dependency manifests/lockfiles (where a poisoned
/// pin or an npm lifecycle hook hides) and build/setup scripts.
fn interesting(name: &str, depth: usize) -> bool {
    let n = name.to_ascii_lowercase();
    const EXACT: &[&str] = &[
        "package.json", "package-lock.json", "npm-shrinkwrap.json", "yarn.lock",
        "pnpm-lock.yaml", ".npmrc", "setup.py", "setup.cfg", "pyproject.toml",
        "pipfile", "pipfile.lock", "cargo.toml", "cargo.lock", "build.rs",
        "go.mod", "go.sum", "gemfile", "gemfile.lock", "rakefile", "composer.json",
        "composer.lock", "binding.gyp", "configure", "configure.ac", "makefile",
        "makefile.am", "gnumakefile", "cmakelists.txt", ".gitmodules", "meson.build",
    ];
    if EXACT.contains(&n.as_str()) {
        return true;
    }
    if n.starts_with("requirements") && n.ends_with(".txt") {
        return true;
    }
    n.ends_with(".gemspec")
        || n.ends_with(".sh")
        || n.ends_with(".bash")
        || n.ends_with(".gyp")
        || (depth <= 2 && (n.ends_with(".py") || n.ends_with(".js") || n.ends_with(".ts")))
}

/// True if the first chunk looks non-text (NUL byte) — a binary we won't inline.
fn looks_binary(path: &Path) -> bool {
    let mut buf = [0u8; 8192];
    if let Ok(mut f) = File::open(path) {
        if let Ok(n) = f.read(&mut buf) {
            return buf[..n].contains(&0);
        }
    }
    false
}

fn walk(root: &Path, src_label: &str, files: &mut Vec<(String, String)>, notes: &mut Vec<String>) {
    let mut stack = vec![(root.to_path_buf(), 0usize)];
    let mut scanned = 0usize;
    let mut binaries = 0usize;
    while let Some((dir, depth)) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else { continue };
        for entry in entries.flatten() {
            scanned += 1;
            if scanned > MAX_WALK_ENTRIES || files.len() >= MAX_FILES {
                notes.push(format!(
                    "{src_label}: source tree large — stopped after scanning {scanned} entries / inlining {} files; coverage is partial",
                    files.len()
                ));
                return;
            }
            let path = entry.path();
            let Ok(ft) = entry.file_type() else { continue };
            if ft.is_symlink() {
                continue;
            }
            let name = entry.file_name().to_string_lossy().into_owned();
            if ft.is_dir() {
                if name == ".git" || name == "node_modules" {
                    // node_modules in a *source* tarball is itself notable.
                    if name == "node_modules" {
                        notes.push(format!("{src_label}: bundled node_modules/ present in upstream source (unusual — vendored dependencies are unreviewed)"));
                    }
                    continue;
                }
                if depth < 8 {
                    stack.push((path, depth + 1));
                }
                continue;
            }
            if !ft.is_file() || !interesting(&name, depth) {
                continue;
            }
            let rel = path.strip_prefix(root).unwrap_or(&path).display().to_string();
            let size = entry.metadata().map(|m| m.len()).unwrap_or(0);
            if size > MAX_FILE_BYTES && !name.to_ascii_lowercase().ends_with(".lock")
                && name.to_ascii_lowercase() != "package-lock.json"
            {
                notes.push(format!("{src_label}: {rel} is {size} bytes — too large to inline"));
                continue;
            }
            if looks_binary(&path) {
                binaries += 1;
                continue;
            }
            match std::fs::read_to_string(&path) {
                Ok(content) => files.push((format!("upstream source [{src_label}]: {rel}", ), content)),
                Err(_) => binaries += 1,
            }
        }
    }
    if binaries > 0 {
        notes.push(format!("{src_label}: {binaries} binary/non-text file(s) in upstream source not inlined"));
    }
}

/// Fetch every remote source for the package and return the high-signal files
/// plus coverage notes. Best-effort: network/tool failures degrade to notes,
/// never hard errors (a failed fetch must lower confidence, not crash a review).
pub fn fetch(repo: &Path, pkgbase: &str, commit: Option<&str>, cache_dir: &Path) -> Upstream {
    let mut files = Vec::new();
    let mut notes = Vec::new();

    let urls = remote_sources(repo);
    if urls.is_empty() {
        return Upstream { files, notes };
    }

    let key = commit.map(|c| &c[..c.len().min(12)]).unwrap_or("nocommit");
    let base = cache_dir.join("sources").join(format!("{pkgbase}@{key}"));
    let _ = std::fs::create_dir_all(&base);

    for (i, url) in urls.iter().enumerate() {
        let work = base.join(i.to_string());
        let extracted = work.join("x");

        if url.starts_with("git+") || url.contains("git+") {
            let clean = url.trim_start_matches("git+");
            let clean = clean.split('#').next().unwrap_or(clean);
            let _ = std::fs::create_dir_all(&extracted);
            if run("git", &["clone".as_ref(), "--depth".as_ref(), "1".as_ref(), "-q".as_ref(),
                            clean.as_ref(), extracted.as_os_str()]) {
                walk(&extracted, &short(url), &mut files, &mut notes);
            } else {
                notes.push(format!("{}: git source could not be cloned for review", short(url)));
            }
            continue;
        }

        let fname = url.rsplit('/').next().unwrap_or("source");
        let _ = std::fs::create_dir_all(&work);
        let dl = work.join(fname);
        match download(url, &dl) {
            Ok(true) => {}
            Ok(false) => {
                notes.push(format!("{}: source exceeds {MAX_DOWNLOAD} bytes — not fetched for review", short(url)));
                continue;
            }
            Err(_) => {
                notes.push(format!("{}: source could not be downloaded for review", short(url)));
                continue;
            }
        }
        if is_archive(fname) {
            if extract(&dl, &extracted) {
                walk(&extracted, &short(url), &mut files, &mut notes);
            } else {
                notes.push(format!("{}: archive could not be extracted for review", short(url)));
            }
        } else if !looks_binary(&dl) {
            // A raw downloaded script/source file.
            if let Ok(content) = std::fs::read_to_string(&dl) {
                files.push((format!("upstream source [{}]: {fname}", short(url)), content));
            }
        }
    }

    Upstream { files, notes }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remote_sources_keeps_urls_strips_local_and_filename_prefix() {
        let dir = std::env::temp_dir().join("claurde-srctest");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join(".SRCINFO"),
            "pkgbase = demo\n\
             \tsource = demo-1.0.tar.gz::https://example.com/demo-1.0.tar.gz\n\
             \tsource_x86_64 = https://example.com/blob.bin\n\
             \tsource = local-fix.patch\n\
             \tsource = git+https://github.com/o/r.git#tag=v1\n",
        )
        .unwrap();
        let got = remote_sources(&dir);
        assert!(got.contains(&"https://example.com/demo-1.0.tar.gz".to_string()));
        assert!(got.contains(&"https://example.com/blob.bin".to_string()));
        assert!(got.contains(&"git+https://github.com/o/r.git#tag=v1".to_string()));
        assert!(!got.iter().any(|s| s.contains("local-fix.patch")));
    }

    #[test]
    fn interesting_targets_manifests_hooks_and_scripts() {
        assert!(interesting("package.json", 1)); // npm lifecycle hooks
        assert!(interesting("package-lock.json", 0)); // poisoned pins
        assert!(interesting("requirements-dev.txt", 0));
        assert!(interesting("build.rs", 0));
        assert!(interesting("install.sh", 0));
        assert!(interesting("index.js", 1));
        assert!(!interesting("deep_module.py", 6)); // too deep to be a build entry point
        assert!(!interesting("logo.png", 0));
        assert!(!interesting("readme.md", 0));
    }
}

/// Compact label for a source: host + last path segment.
fn short(url: &str) -> String {
    let no_scheme = url.split("://").nth(1).unwrap_or(url);
    let host = no_scheme.split('/').next().unwrap_or(no_scheme);
    let last = url.rsplit('/').next().unwrap_or("");
    if last.is_empty() {
        host.to_string()
    } else {
        format!("{host}/{last}")
    }
}
