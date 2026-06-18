use crate::net;
use anyhow::{bail, Context, Result};
use serde::Deserialize;
use std::collections::{HashMap, HashSet, VecDeque};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;

/// AUR identifier charset. Rejects path separators, `..`, a leading dash, and
/// anything outside the AUR's allowed name characters — so a tainted PackageBase
/// can never traverse the cache dir or be read as a git/CLI flag.
fn valid_pkg_ident(s: &str) -> bool {
    !s.is_empty()
        && s != "."
        && s != ".."
        && !s.starts_with('-')
        && !s.contains("..")
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '@' | '.' | '_' | '+' | '-'))
}

/// Read up to `cap` bytes of a file as text — bounds the in-memory size so an
/// attacker-sized .SRCINFO/PKGBUILD can't OOM dependency parsing.
fn read_capped(path: &Path, cap: u64) -> std::io::Result<String> {
    let mut buf = Vec::new();
    std::fs::File::open(path)?.take(cap).read_to_end(&mut buf)?;
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

const AUR_RPC: &str = "https://aur.archlinux.org/rpc/v5/info";
const AUR_SEARCH: &str = "https://aur.archlinux.org/rpc/v5/search";
const AUR_GIT: &str = "https://aur.archlinux.org";

#[derive(Debug, Clone, Deserialize)]
pub struct AurPkg {
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "PackageBase")]
    pub package_base: String,
    #[serde(rename = "Version")]
    pub version: String,
    #[serde(rename = "Maintainer")]
    pub maintainer: Option<String>,
    #[serde(rename = "LastModified")]
    pub last_modified: Option<i64>,
    #[serde(rename = "FirstSubmitted")]
    pub first_submitted: Option<i64>,
    #[serde(rename = "NumVotes")]
    pub votes: Option<i64>,
    #[serde(rename = "Popularity")]
    pub popularity: Option<f64>,
    #[serde(rename = "OutOfDate")]
    pub out_of_date: Option<i64>,
}

#[derive(Deserialize)]
struct RpcResponse {
    results: Vec<AurPkg>,
}

/// Batch query the AUR RPC for package metadata. Returns only packages that exist in the AUR.
pub fn rpc_info(names: &[String]) -> Result<HashMap<String, AurPkg>> {
    let mut out = HashMap::new();
    let agent = net::agent();
    for chunk in names.chunks(150) {
        let mut url = String::from(AUR_RPC);
        for (i, n) in chunk.iter().enumerate() {
            url.push_str(if i == 0 { "?" } else { "&" });
            url.push_str("arg[]=");
            url.push_str(&urlencode(n));
        }
        let resp: RpcResponse = agent
            .get(&url)
            .set("User-Agent", net::USER_AGENT)
            .call()
            .context("AUR RPC request failed")?
            .into_json()
            .context("AUR RPC returned invalid JSON")?;
        for p in resp.results {
            out.insert(p.name.clone(), p);
        }
    }
    Ok(out)
}

/// All AUR packages that satisfy `name` — the exact-name package plus anything
/// that lists `name` in its `provides`. This mirrors the provider set an AUR
/// helper would offer, so clAURde can make the choice happen BEFORE review (and
/// then review/build exactly the chosen package). Exact-name match is sorted
/// first (the conventional default), then by votes.
pub fn providers(name: &str) -> Result<Vec<AurPkg>> {
    let mut map: HashMap<String, AurPkg> = HashMap::new();

    // Exact-name package (a package implicitly provides its own name, but won't
    // show up in a by=provides search unless it self-declares it).
    for (n, p) in rpc_info(&[name.to_string()])? {
        map.insert(n, p);
    }

    // Packages declaring `provides = name`.
    let url = format!("{AUR_SEARCH}/{}?by=provides", urlencode(name));
    if let Ok(resp) = net::agent()
        .get(&url)
        .set("User-Agent", net::USER_AGENT)
        .call()
        .and_then(|r| r.into_json::<RpcResponse>().map_err(Into::into))
    {
        for p in resp.results {
            map.insert(p.name.clone(), p);
        }
    }

    let mut out: Vec<AurPkg> = map.into_values().collect();
    out.sort_by(|a, b| {
        let exact = (b.name == name).cmp(&(a.name == name));
        exact.then(b.votes.unwrap_or(0).cmp(&a.votes.unwrap_or(0)))
    });
    Ok(out)
}

fn urlencode(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' | b'+' | b'@' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

/// Is the package available from the configured binary repos (i.e. not an AUR build)?
fn in_repos(name: &str) -> bool {
    Command::new("pacman")
        .args(["-Si", "--", name])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Clone (or update) an AUR package-base git repo into the cache dir.
/// Returns the checkout path.
pub fn fetch(package_base: &str, cache_dir: &Path) -> Result<PathBuf> {
    if !valid_pkg_ident(package_base) {
        bail!("refusing to fetch package base with unexpected characters: {package_base:?}");
    }
    std::fs::create_dir_all(cache_dir)?;
    let dest = cache_dir.join(package_base);
    // Belt-and-suspenders: the checkout must land directly inside the cache dir.
    if dest.parent() != Some(cache_dir) {
        bail!("computed checkout path escapes the cache directory: {}", dest.display());
    }
    let url = format!("{AUR_GIT}/{package_base}.git");
    // git runs non-interactively under a wall-clock timeout (net::run_git) so a
    // stalled/credential-prompting remote can't hang the review.
    let ok = if dest.join(".git").is_dir() {
        net::run_git(
            &["-C".as_ref(), dest.as_os_str(), "fetch".as_ref(), "--quiet".as_ref(), "origin".as_ref()],
            180,
        ) && net::run_git(
            &["-C".as_ref(), dest.as_os_str(), "reset".as_ref(), "--quiet".as_ref(), "--hard".as_ref(), "origin/HEAD".as_ref()],
            60,
        )
    } else {
        net::run_git(
            &["clone".as_ref(), "--quiet".as_ref(), "--".as_ref(), url.as_ref(), dest.as_os_str()],
            180,
        )
    };
    if !ok {
        bail!("git clone/fetch failed for {package_base}");
    }
    Ok(dest)
}

/// Strip a version constraint: "foo>=1.2" -> "foo".
fn dep_name(dep: &str) -> String {
    dep.split(['>', '<', '='])
        .next()
        .unwrap_or(dep)
        .trim()
        .to_string()
}

/// Parse depends/makedepends/checkdepends out of .SRCINFO.
pub fn srcinfo_deps(repo_dir: &Path) -> Result<Vec<String>> {
    let text = read_capped(&repo_dir.join(".SRCINFO"), 4_000_000)
        .context(".SRCINFO missing in AUR repo")?;
    let mut deps = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        for key in ["depends =", "makedepends =", "checkdepends ="] {
            if let Some(v) = line.strip_prefix(key) {
                deps.push(dep_name(v));
            }
        }
    }
    Ok(deps)
}

/// Best-effort extraction of dependency arrays straight from the PKGBUILD
/// *text* (never sourced). This is a defense against a `.SRCINFO` that
/// understates the real dependency set to hide a malicious package from the
/// review tree. Statically-listed deps are captured; entries built from
/// variables (`$...`) can't be resolved here and are left to the LLM review of
/// the PKGBUILD itself. Over-inclusion is harmless — a non-existent dep is
/// simply not found in the AUR and skipped.
pub fn pkgbuild_deps(repo_dir: &Path) -> Vec<String> {
    let Ok(text) = read_capped(&repo_dir.join("PKGBUILD"), 4_000_000) else {
        return vec![];
    };
    let bytes = text.as_bytes();
    let mut deps = Vec::new();
    for key in ["depends", "makedepends", "checkdepends"] {
        let mut from = 0usize;
        while let Some(rel) = text[from..].find(key) {
            let idx = from + rel;
            from = idx + key.len();
            // word boundary before the key (avoid matching e.g. `optdepends`)
            let prev_ok = idx == 0
                || matches!(bytes[idx - 1], b'\n' | b'\t' | b' ' | b';' | b'&');
            if !prev_ok {
                continue;
            }
            let rest = text[idx + key.len()..].trim_start();
            let after = rest.strip_prefix("+=").or_else(|| rest.strip_prefix('='));
            let Some(after) = after.map(|a| a.trim_start()) else { continue };
            let Some(inner) = after.strip_prefix('(') else { continue };
            let Some(end) = inner.find(')') else { continue };
            for line in inner[..end].lines() {
                // drop inline comments (`dep # note`) before tokenizing
                let line = line.split('#').next().unwrap_or("");
                for tok in line.split_whitespace() {
                    let tok = tok.trim_matches(|c| c == '\'' || c == '"');
                    if tok.is_empty() || tok.contains('$') {
                        continue;
                    }
                    deps.push(dep_name(tok));
                }
            }
        }
    }
    deps
}

/// Current HEAD commit of a cloned package-base repo — the cache key for a verdict.
pub fn head_commit(repo: &Path) -> Option<String> {
    let out = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// Return the names of all foreign (AUR) packages that have an update available.
/// Compares `pacman -Qm` installed versions against the current AUR RPC version.
pub fn aur_upgrades() -> Result<Vec<String>> {
    let out = Command::new("pacman")
        .args(["-Qm"])
        .output()
        .context("failed to run pacman -Qm")?;
    if !out.status.success() {
        return Ok(vec![]);
    }
    let installed: Vec<(String, String)> = String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|l| {
            let mut parts = l.split_whitespace();
            let name = parts.next()?.to_string();
            let ver = parts.next()?.to_string();
            Some((name, ver))
        })
        .collect();

    if installed.is_empty() {
        return Ok(vec![]);
    }

    let names: Vec<String> = installed.iter().map(|(n, _)| n.clone()).collect();
    let info = rpc_info(&names)?;

    let mut upgrades = Vec::new();
    for (name, installed_ver) in &installed {
        if let Some(pkg) = info.get(name) {
            if pkg.version != *installed_ver {
                upgrades.push(name.clone());
            }
        }
    }
    Ok(upgrades)
}

pub struct ResolvedPkg {
    pub info: AurPkg,
    pub path: PathBuf,
    /// true if this was named on the command line (vs pulled in as a dependency)
    #[allow(dead_code)]
    pub explicit: bool,
}

/// BFS the AUR dependency tree starting from `targets`. Clones every AUR
/// package-base encountered so all of them can be reviewed before any build.
pub fn resolve(targets: &[String], cache_dir: &Path) -> Result<Vec<ResolvedPkg>> {
    let mut resolved: Vec<ResolvedPkg> = Vec::new();
    let mut seen_bases: HashSet<String> = HashSet::new();
    let mut seen_names: HashSet<String> = HashSet::new();
    let mut queue: VecDeque<(String, bool)> =
        targets.iter().map(|t| (t.clone(), true)).collect();

    while !queue.is_empty() {
        let batch: Vec<(String, bool)> = queue.drain(..).collect();
        let names: Vec<String> = batch
            .iter()
            .map(|(n, _)| n.clone())
            .filter(|n| seen_names.insert(n.clone()))
            .collect();
        if names.is_empty() {
            continue;
        }
        let infos = rpc_info(&names)?;

        for (name, explicit) in &batch {
            let Some(info) = infos.get(name) else {
                if *explicit {
                    if in_repos(name) {
                        bail!(
                            "'{name}' is in the official repos, not the AUR. \
                             Install it with pacman/your helper directly."
                        );
                    }
                    bail!("Target '{name}' not found in the AUR");
                }
                continue; // dep satisfied by repos (or a virtual provide) — not ours to review
            };
            if !seen_bases.insert(info.package_base.clone()) {
                continue;
            }
            eprintln!("  fetching {} ...", info.package_base);
            let path = fetch(&info.package_base, cache_dir)?;
            // Union both sources so an understated .SRCINFO can't hide a dep.
            let mut tree_deps = srcinfo_deps(&path)?;
            tree_deps.extend(pkgbuild_deps(&path));
            let mut local_seen = HashSet::new();
            for dep in tree_deps {
                if local_seen.insert(dep.clone())
                    && !seen_names.contains(&dep)
                    && !in_repos(&dep)
                {
                    queue.push_back((dep, false));
                }
            }
            resolved.push(ResolvedPkg { info: info.clone(), path, explicit: *explicit });
        }
    }
    Ok(resolved)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkgbuild_deps_parses_arrays_and_ignores_optdepends() {
        let dir = std::env::temp_dir().join("claurde-deptest");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("PKGBUILD"),
            "pkgname=foo\n\
             depends=('glibc' \"gtk3>=3.0\" 'nss')\n\
             makedepends=(cmake\n  ninja # build tool\n  git)\n\
             checkdepends=('python-pytest')\n\
             depends+=('hidden-evil-dep')\n\
             optdepends=('should-not-appear')\n\
             _pinned=('$srcdir/thing')\n",
        )
        .unwrap();
        let mut got = pkgbuild_deps(&dir);
        got.sort();
        got.dedup();
        // gtk3>=3.0 -> gtk3 ; optdepends excluded ; $-entries excluded
        assert!(got.contains(&"glibc".to_string()));
        assert!(got.contains(&"gtk3".to_string()));
        assert!(got.contains(&"nss".to_string()));
        assert!(got.contains(&"cmake".to_string()));
        assert!(got.contains(&"ninja".to_string()));
        assert!(got.contains(&"git".to_string()));
        assert!(got.contains(&"python-pytest".to_string()));
        assert!(got.contains(&"hidden-evil-dep".to_string()));
        assert!(!got.contains(&"should-not-appear".to_string()));
        assert!(!got.iter().any(|d| d.contains('$')));
        // inline comment text must not leak in as phantom deps
        assert!(!got.contains(&"build".to_string()));
        assert!(!got.contains(&"tool".to_string()));
    }

    #[test]
    fn valid_pkg_ident_blocks_traversal_and_flags() {
        // legitimate AUR identifiers
        for ok in ["paru", "python-pytest", "gtk3", "lib32-glibc", "a.b_c+d@e"] {
            assert!(valid_pkg_ident(ok), "{ok} should be valid");
        }
        // path traversal / absolute / flag injection / empty
        for bad in ["", ".", "..", "../evil", "/etc/passwd", "a/b", "-rf", "foo..bar", "a\0b"] {
            assert!(!valid_pkg_ident(bad), "{bad:?} should be rejected");
        }
    }
}
