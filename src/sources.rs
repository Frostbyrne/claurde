//! Fetch and inspect the *upstream* sources a package builds from — not just
//! the AUR repo files. This is what catches payloads that live in the fetched
//! source tree rather than the PKGBUILD (e.g. an npm `preinstall` lifecycle
//! hook, a poisoned lockfile pin, a committed binary blob).
//!
//! SAFETY: the source URLs are read from the **already-expanded** `.SRCINFO`
//! (`source = <url>` lines that makepkg wrote out), so clAURde never sources or
//! executes the PKGBUILD to learn them. Downloading a declared URL and reading
//! the bytes is not executing the package.

use crate::net;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Cap on a single source download. Big binary sources (e.g. a Chrome .deb)
/// aren't worth streaming in full — we note them and move on.
const MAX_DOWNLOAD: u64 = 64 * 1024 * 1024;
/// Most upstream-source files we'll inline for review.
const MAX_FILES: usize = 80;
/// Hard ceiling on the bytes of a single source file we pull into memory. The
/// caller truncates further to the per-file evidence cap; this only exists so a
/// giant extracted file (e.g. a decompression-bomb lockfile) can't OOM us.
const MAX_FILE_BYTES: u64 = 4 * 1024 * 1024;
/// Bound the directory walk so a giant vendored tree can't stall a review.
const MAX_WALK_ENTRIES: usize = 40_000;
/// Cap on the number of attacker-declared source URLs we fetch per package —
/// .SRCINFO can list thousands; without a cap each multiplies every per-source
/// cost (download time, extraction disk).
const MAX_SOURCES: usize = 25;
/// Per-archive decompressed-size ceiling. bsdtar is killed and the tree dropped
/// if extraction crosses this, so a 64MB zip/zstd bomb can't fill the disk.
const MAX_EXTRACT: u64 = 256 * 1024 * 1024;
/// Wall-clock ceilings (seconds) for network-facing subprocess work.
const GIT_TIMEOUT: u64 = 180;
const EXTRACT_TIMEOUT: u64 = 180;

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

/// Read up to `cap` bytes of a file as (lossily-decoded) text. Bounds the
/// in-memory size so an attacker-sized extracted file can't OOM the review.
fn read_capped_string(path: &Path, cap: u64) -> std::io::Result<String> {
    let mut buf = Vec::new();
    File::open(path)?.take(cap).read_to_end(&mut buf)?;
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

/// Download `url` to `dest`, capped, following redirects MANUALLY so every hop's
/// host is checked against the SSRF guard before we connect. Returns Ok(true) if
/// the whole body fit, Ok(false) if it hit the size cap (treat as not fully
/// fetched). Plain `http://` is allowed (many real sources use it) but the
/// resolved host must always be public — so a `source` URL (or a redirect from
/// one) can never reach 169.254.169.254, localhost, or a private service.
fn download(agent: &ureq::Agent, url: &str, dest: &Path) -> std::io::Result<bool> {
    let mut current = url.to_string();
    for _ in 0..6 {
        let (_, host, port) = net::split_url(&current).ok_or_else(|| {
            std::io::Error::other(format!("unsupported or malformed source URL: {current}"))
        })?;
        net::check_host_public(&host, port).map_err(std::io::Error::other)?;
        let resp = agent
            .get(&current)
            .set("User-Agent", net::USER_AGENT)
            .call()
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        if (300..400).contains(&resp.status()) {
            let loc = resp
                .header("Location")
                .ok_or_else(|| std::io::Error::other("redirect without Location"))?;
            current = net::join_url(&current, loc)
                .ok_or_else(|| std::io::Error::other("unresolvable redirect target"))?;
            continue;
        }
        let mut reader = resp.into_reader().take(MAX_DOWNLOAD + 1);
        let mut f = File::create(dest)?;
        let n = std::io::copy(&mut reader, &mut f)?;
        return Ok(n <= MAX_DOWNLOAD);
    }
    Err(std::io::Error::other("too many redirects"))
}

fn is_archive(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    [".tar.gz", ".tgz", ".tar.xz", ".txz", ".tar.zst", ".tar.bz2", ".tbz2", ".tar",
     ".zip", ".deb", ".gz", ".xz", ".zst", ".bz2", ".7z", ".rpm"]
        .iter()
        .any(|e| n.ends_with(e))
}

enum Extract {
    /// bsdtar exited cleanly — full tree extracted.
    Done,
    /// bsdtar rejected some members (path traversal / absolute / symlink) or
    /// timed out; whatever it did write is still on disk and worth reviewing.
    Partial,
    /// Extraction crossed the decompressed-size ceiling — likely a bomb; the
    /// partial tree was discarded.
    TooBig,
}

/// libarchive's `bsdtar` extracts tar/zip/deb/etc. with safe defaults (rejects
/// absolute paths, `..`, and symlink traversal — verified). We additionally
/// bound the DECOMPRESSED size: bsdtar is spawned and its output dir polled, and
/// the child is killed if the tree crosses MAX_EXTRACT, so a small archive that
/// expands to hundreds of GB can't fill the disk before review.
fn extract(archive: &Path, into: &Path) -> Extract {
    let _ = std::fs::create_dir_all(into);
    let mut child = match Command::new("bsdtar")
        .args([
            "-x".as_ref(),
            "-f".as_ref(),
            archive.as_os_str(),
            "-C".as_ref(),
            into.as_os_str(),
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(c) => c,
        Err(_) => return Extract::Partial,
    };
    let deadline = Instant::now() + Duration::from_secs(EXTRACT_TIMEOUT);
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                return if status.success() { Extract::Done } else { Extract::Partial };
            }
            Ok(None) => {
                if net::dir_size_exceeds(into, MAX_EXTRACT) {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Extract::TooBig;
                }
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Extract::Partial;
                }
                std::thread::sleep(Duration::from_millis(150));
            }
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                return Extract::Partial;
            }
        }
    }
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
            if looks_binary(&path) {
                // Everything reaching here already matched interesting() — a
                // build-relevant manifest/script that is binary/contains NUL is
                // anomalous, so NAME it instead of folding it into an anonymous
                // count the model can't act on.
                notes.push(format!(
                    "{src_label}: {rel} matched as a build-relevant manifest/script but is binary/contains NUL bytes — could not inline; anomalous, treat as a finding"
                ));
                continue;
            }
            match read_capped_string(&path, MAX_FILE_BYTES) {
                Ok(content) => files.push((format!("upstream source [{src_label}]: {rel}"), content)),
                Err(_) => notes.push(format!(
                    "{src_label}: {rel} matched as a build-relevant manifest/script but could not be read for review — treat as a finding"
                )),
            }
        }
    }
}

/// A git ref token (commit/tag/branch) is safe to pass to `git checkout`/`fetch`
/// only if it can't be read as a flag or smuggle shell-irrelevant bytes.
fn safe_ref(s: &str) -> bool {
    !s.is_empty()
        && !s.starts_with('-')
        && s.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '/' | '-' | '+'))
}

/// Pull the pinned ref out of a `git+` URL fragment (`#commit=`, `#tag=`,
/// `#branch=`, `#revision=`). Returns the ref only if it's a safe token.
fn parse_git_ref(frag: &str) -> Option<String> {
    for part in frag.split('&') {
        let Some((k, v)) = part.split_once('=') else { continue };
        if matches!(k, "commit" | "tag" | "branch" | "revision") && safe_ref(v) {
            return Some(v.to_string());
        }
    }
    None
}

/// Clone an attacker-declared `git+` source for review and check out the SAME
/// ref makepkg will build, so the reviewed bytes match the built bytes. Scheme
/// is allowlisted (http/https/git only — no file://, ssh://, ext::), the URL
/// can't be read as a flag (`--` + leading-dash reject), and the clone runs
/// non-interactively under a wall-clock timeout. Any divergence becomes a note.
fn handle_git_source(
    url: &str,
    extracted: &Path,
    files: &mut Vec<(String, String)>,
    notes: &mut Vec<String>,
) {
    let body = url.trim_start_matches("git+");
    let (repo, frag) = match body.split_once('#') {
        Some((r, f)) => (r, Some(f)),
        None => (body, None),
    };
    let scheme_ok = repo.starts_with("https://")
        || repo.starts_with("http://")
        || repo.starts_with("git://");
    if !scheme_ok || repo.starts_with('-') {
        notes.push(format!(
            "{}: git source scheme not allowed for review (only http/https/git) — not fetched; coverage PARTIAL",
            short(url)
        ));
        return;
    }
    let _ = std::fs::create_dir_all(extracted);
    let cloned = net::run_git(
        &[
            "clone".as_ref(),
            "-q".as_ref(),
            "--".as_ref(),
            repo.as_ref(),
            extracted.as_os_str(),
        ],
        GIT_TIMEOUT,
    );
    if !cloned {
        notes.push(format!("{}: git source could not be cloned for review", short(url)));
        return;
    }
    match frag.and_then(parse_git_ref) {
        Some(r) => {
            let dir = extracted.as_os_str();
            let checked = net::run_git(
                &["-C".as_ref(), dir, "checkout".as_ref(), "-q".as_ref(), r.as_ref()],
                60,
            ) || (net::run_git(
                &["-C".as_ref(), dir, "fetch".as_ref(), "-q".as_ref(), "origin".as_ref(), r.as_ref()],
                GIT_TIMEOUT,
            ) && net::run_git(
                &["-C".as_ref(), dir, "checkout".as_ref(), "-q".as_ref(), "FETCH_HEAD".as_ref()],
                60,
            ));
            if !checked {
                notes.push(format!(
                    "{}: pinned ref '{r}' could not be checked out — reviewed bytes may differ from what makepkg builds; coverage PARTIAL",
                    short(url)
                ));
            }
        }
        None => notes.push(format!(
            "{}: git source pins no immutable commit — the reviewed default-branch bytes may differ from what makepkg builds later",
            short(url)
        )),
    }
    walk(extracted, &short(url), files, notes);
}

/// Last path segment of a URL, sanitized to a safe single filename.
fn download_filename(url: &str) -> String {
    let last = url.split(['?', '#']).next().unwrap_or(url);
    let name = last.rsplit('/').next().unwrap_or("source");
    if name.is_empty() || name == "." || name == ".." || name.contains('\0') {
        "source".to_string()
    } else {
        name.to_string()
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
    if urls.len() > MAX_SOURCES {
        notes.push(format!(
            "package declares {} sources; only the first {MAX_SOURCES} were fetched for review — coverage is PARTIAL",
            urls.len()
        ));
    }

    // First 12 chars of the commit, char-boundary-safe (it's hex in practice).
    let key: String = commit.map(|c| c.chars().take(12).collect()).unwrap_or_else(|| "nocommit".into());
    let base = cache_dir.join("sources").join(format!("{pkgbase}@{key}"));
    let _ = std::fs::create_dir_all(&base);
    let agent = net::no_redirect_agent();

    for (i, url) in urls.iter().take(MAX_SOURCES).enumerate() {
        let work = base.join(i.to_string());
        let extracted = work.join("x");

        if url.starts_with("git+") {
            let _ = std::fs::create_dir_all(&extracted);
            handle_git_source(url, &extracted, &mut files, &mut notes);
            let _ = std::fs::remove_dir_all(&work);
            continue;
        }

        // Only http(s) is fetchable here; other schemes (ftp/svn+/hg+/…) are
        // noted as uncovered rather than silently ignored.
        if net::split_url(url).is_none() {
            notes.push(format!(
                "{}: source scheme not fetched for review (only http/https/git+) — coverage PARTIAL",
                short(url)
            ));
            continue;
        }

        let fname = download_filename(url);
        let _ = std::fs::create_dir_all(&work);
        let dl = work.join(&fname);
        match download(&agent, url, &dl) {
            Ok(true) => {}
            Ok(false) => {
                notes.push(format!("{}: source exceeds {MAX_DOWNLOAD} bytes — not fetched for review", short(url)));
                let _ = std::fs::remove_dir_all(&work);
                continue;
            }
            Err(_) => {
                notes.push(format!("{}: source could not be downloaded for review", short(url)));
                let _ = std::fs::remove_dir_all(&work);
                continue;
            }
        }
        if is_archive(&fname) {
            let _ = std::fs::create_dir_all(&extracted);
            let result = extract(&dl, &extracted);
            let has_entries = std::fs::read_dir(&extracted)
                .map(|mut d| d.next().is_some())
                .unwrap_or(false);
            match result {
                Extract::Done => walk(&extracted, &short(url), &mut files, &mut notes),
                Extract::TooBig => notes.push(format!(
                    "{}: extracted size exceeded {MAX_EXTRACT} bytes — possible decompression bomb; not reviewed; coverage PARTIAL",
                    short(url)
                )),
                Extract::Partial if has_entries => {
                    notes.push(format!(
                        "{}: archive extraction rejected member(s) (path traversal / absolute path / symlink) or timed out — SUSPICIOUS; the members that did extract were reviewed",
                        short(url)
                    ));
                    walk(&extracted, &short(url), &mut files, &mut notes);
                }
                Extract::Partial => notes.push(format!("{}: archive could not be extracted for review", short(url))),
            }
        } else if !looks_binary(&dl) {
            // A raw downloaded script/source file.
            if let Ok(content) = read_capped_string(&dl, MAX_FILE_BYTES) {
                files.push((format!("upstream source [{}]: {fname}", short(url)), content));
            }
        }
        let _ = std::fs::remove_dir_all(&work);
    }

    // All inlined content is already in `files`; don't leave fetched trees on disk.
    let _ = std::fs::remove_dir_all(&base);
    Upstream { files, notes }
}

/// True if the package's review can't be safely cached on the AUR commit alone,
/// because at least one build input can change WITHOUT changing that commit: a
/// `git+` source with no immutable `#commit=` pin, or any source with a `SKIP`
/// checksum (the bytes a server returns aren't integrity-bound). Conservative —
/// any doubt means "mutable" so the verdict cache is bypassed and re-reviewed.
pub fn has_mutable_sources(repo: &Path) -> bool {
    let Ok(text) = std::fs::read_to_string(repo.join(".SRCINFO")) else {
        // Can't tell → don't trust a stale cache.
        return true;
    };
    for line in text.lines() {
        let line = line.trim();
        let Some((key, val)) = line.split_once('=') else { continue };
        let key = key.trim();
        let val = val.trim();
        if key.ends_with("sums") && val.eq_ignore_ascii_case("SKIP") {
            return true;
        }
        if key == "source" || key.starts_with("source_") {
            let url = val.rsplit("::").next().unwrap_or(val);
            if url.starts_with("git+") {
                let frag = url.split_once('#').map(|(_, f)| f);
                let pinned = frag
                    .and_then(parse_git_ref)
                    .map(|r| r.len() >= 7 && r.chars().all(|c| c.is_ascii_hexdigit()))
                    .unwrap_or(false);
                if !pinned {
                    return true;
                }
            } else if url.starts_with("svn+") || url.starts_with("hg+") || url.starts_with("bzr+") {
                return true;
            }
        }
    }
    false
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

    #[test]
    fn parse_git_ref_extracts_only_safe_pins() {
        assert_eq!(parse_git_ref("commit=abcdef123456"), Some("abcdef123456".into()));
        assert_eq!(parse_git_ref("tag=v1.2.3"), Some("v1.2.3".into()));
        assert_eq!(parse_git_ref("branch=main"), Some("main".into()));
        assert_eq!(parse_git_ref("signed"), None);
        // a ref that could be read as a flag is refused
        assert_eq!(parse_git_ref("commit=--upload-pack=x"), None);
        assert!(!safe_ref("-x"));
        assert!(!safe_ref("a b"));
        assert!(safe_ref("v1.0"));
    }

    #[test]
    fn download_filename_is_a_safe_single_name() {
        assert_eq!(download_filename("https://h/a/b/foo-1.0.tar.gz"), "foo-1.0.tar.gz");
        assert_eq!(download_filename("https://h/a/b/foo.tar.gz?x=1#y"), "foo.tar.gz");
        assert_eq!(download_filename("https://h/path/"), "source");
        assert_eq!(download_filename("https://h/.."), "source");
    }

    #[test]
    fn has_mutable_sources_flags_skip_and_unpinned_git() {
        let base = std::env::temp_dir().join("claurde-mutsrc");
        let immut = base.join("immut");
        let pinned = base.join("pinned");
        let skip = base.join("skip");
        let gitbranch = base.join("gitbranch");
        for d in [&immut, &pinned, &skip, &gitbranch] {
            std::fs::create_dir_all(d).unwrap();
        }
        std::fs::write(immut.join(".SRCINFO"),
            "pkgbase = a\n\tsource = https://x/y-1.0.tar.gz\n\tsha256sums = 0123abcd\n").unwrap();
        assert!(!has_mutable_sources(&immut), "pinned tarball is immutable");

        std::fs::write(pinned.join(".SRCINFO"),
            "pkgbase = a\n\tsource = git+https://x/y.git#commit=0123456789abcdef0123456789abcdef01234567\n\tsha256sums = 0123abcd\n").unwrap();
        assert!(!has_mutable_sources(&pinned), "commit-pinned git is immutable");

        std::fs::write(skip.join(".SRCINFO"),
            "pkgbase = a\n\tsource = https://x/y.tar.gz\n\tsha256sums = SKIP\n").unwrap();
        assert!(has_mutable_sources(&skip), "SKIP checksum is mutable");

        std::fs::write(gitbranch.join(".SRCINFO"),
            "pkgbase = a\n\tsource = git+https://x/y.git#branch=main\n\tsha256sums = 0123abcd\n").unwrap();
        assert!(has_mutable_sources(&gitbranch), "branch-pinned git is mutable");
    }
}
