mod aur;
mod cache;
mod collect;
mod config;
mod net;
mod review;
mod sources;

use anyhow::{bail, Result};
use clap::Parser;
use config::Config;
use review::Verdict;
use std::io::{IsTerminal, Write};
use std::process::Command;

/// AI-gated AUR wrapper: review every PKGBUILD in the dependency tree with
/// Claude, then hand the approved set to your AUR helper for the actual build.
#[derive(Parser)]
#[command(name = "claurde", version, about)]
struct Cli {
    /// Packages to install (AUR package names).
    packages: Vec<String>,

    /// AUR helper to hand off to (paru, yay, pikaur, trizen, aura, makepkg).
    #[arg(long)]
    helper: Option<String>,

    /// Claude model to use for review.
    #[arg(long)]
    model: Option<String>,

    /// Review and report only; never build or hand off.
    #[arg(long)]
    review_only: bool,

    /// Build even if findings are raised, without prompting (NOT recommended).
    #[arg(long)]
    yes: bool,

    /// Skip the AI review entirely and pass straight to the helper (escape hatch).
    #[arg(long)]
    no_review: bool,

    /// Emit the full verdicts as JSON to stdout (implies a quieter run).
    #[arg(long)]
    json: bool,

    /// Ignore (and don't write) the verdict cache; always re-review.
    #[arg(long)]
    no_cache: bool,

    /// Don't fetch and review upstream sources; review only the AUR repo files.
    #[arg(long)]
    no_fetch_sources: bool,
}

fn color(code: &str, s: &str) -> String {
    if std::io::stderr().is_terminal() {
        format!("\x1b[{code}m{s}\x1b[0m")
    } else {
        s.to_string()
    }
}

/// Neutralize attacker- or model-derived text before it reaches the terminal.
/// The package metadata (names/versions from the AUR) and the model's verdict
/// fields can echo attacker-controlled bytes; raw ANSI/control escapes there
/// could rewrite what the user sees and forge a clean-looking verdict. Replace
/// every control char (keeping nothing that can move the cursor or set colors)
/// so only clAURde's own fixed color() escapes ever style the output.
fn vt(s: &str) -> String {
    s.chars()
        .map(|c| if c == '\t' { ' ' } else if c.is_control() { '\u{FFFD}' } else { c })
        .collect()
}

fn print_verdict(name: &str, v: &Verdict, from_cache: bool) {
    let (c, tag) = match v.verdict.as_str() {
        "safe" => ("32", "SAFE"),
        "suspicious" => ("33", "SUSPICIOUS"),
        _ => ("31", "MALICIOUS"),
    };
    let cached = if from_cache { color("90", " (cached)") } else { String::new() };
    eprintln!(
        "\n{} {}{}  (risk {}/100)  {}",
        color(c, &format!("[{tag}]")),
        color("1", &vt(name)),
        cached,
        v.risk_score,
        vt(&v.summary)
    );
    if v.prompt_injection_detected {
        eprintln!("  {}", color("31;1", "⚠ prompt-injection attempt detected in package content"));
    }
    for f in &v.findings {
        let sc = match f.severity.as_str() {
            "critical" | "high" => "31",
            "medium" => "33",
            _ => "90",
        };
        eprintln!(
            "  {} [{}] {}{}",
            color(sc, &format!("{:>8}", vt(&f.severity))),
            vt(&f.category),
            f.location.as_deref().map(|l| format!("{}: ", vt(l))).unwrap_or_default(),
            vt(&f.description)
        );
    }
}

fn confirm(prompt: &str) -> bool {
    if !std::io::stdin().is_terminal() {
        return false;
    }
    eprint!("{prompt} [y/N] ");
    let _ = std::io::stderr().flush();
    let mut line = String::new();
    std::io::stdin().read_line(&mut line).ok();
    matches!(line.trim().to_lowercase().as_str(), "y" | "yes")
}

/// Installed version of `name`, if any (via `pacman -Q`).
fn installed_version(name: &str) -> Option<String> {
    let out = Command::new("pacman").args(["-Q", "--", name]).output().ok()?;
    if !out.status.success() {
        return None;
    }
    String::from_utf8_lossy(&out.stdout)
        .split_whitespace()
        .nth(1)
        .map(|s| s.to_string())
}

/// Build and install EXACTLY the checkouts clAURde reviewed, dependencies first.
///
/// This deliberately does NOT re-invoke `<helper> -S <name>`: that re-resolves
/// the name, re-clones the source, and can offer alternate *providers* — any of
/// which means installing a PKGBUILD that was never reviewed. Provider choice
/// has already happened (before review); here we build the reviewed bytes in
/// place, which also closes the review→build race.
///
/// `pkgs` is in dependency-discovery order (targets first); we build in reverse
/// so each package's AUR deps are installed before it. paru/yay get the whole
/// set via `-Bi` (they handle repo deps + transaction); anything else falls back
/// to `makepkg -si` per checkout.
fn handoff(cfg: &Config, pkgs: &[aur::ResolvedPkg]) -> Result<()> {
    let dirs: Vec<&std::path::Path> = pkgs.iter().rev().map(|p| p.path.as_path()).collect();

    // Only paru has a native "build this local checkout, resolving deps" mode
    // (`-Bi`). yay/pikaur/trizen/aura don't, so they use the universal makepkg
    // path below — which still installs exactly the reviewed checkout.
    if cfg.helper == "paru" {
        eprintln!(
            "\n{} paru -Bi (reviewed checkouts, deps first)",
            color("1", "Building via")
        );
        let status = Command::new("paru").arg("-Bi").args(&dirs).status()?;
        if !status.success() {
            bail!("paru -Bi exited with failure");
        }
        return Ok(());
    }

    eprintln!("\n{}", color("1", "Building reviewed checkouts with makepkg (deps first)"));
    for p in pkgs.iter().rev() {
        if installed_version(&p.info.name).as_deref() == Some(p.info.version.as_str()) {
            eprintln!("  {} {} already installed — skipping", color("90", "✓"), vt(&p.info.name));
            continue;
        }
        eprintln!("\n{} {}", color("1", "==> makepkg -si:"), vt(&p.info.name));
        let status = Command::new("makepkg")
            .arg("-si")
            .current_dir(&p.path)
            .status()?;
        if !status.success() {
            bail!(
                "build/install of '{}' failed — stopping (nothing further is installed)",
                vt(&p.info.name)
            );
        }
    }
    Ok(())
}

/// Present the provider set for an ambiguous target and let the user choose —
/// BEFORE review, so clAURde reviews and builds exactly the chosen package.
fn choose_provider(query: &str, cands: &[aur::AurPkg]) -> Result<String> {
    eprintln!(
        "\n:: There are {} providers available for {}:",
        cands.len(),
        color("1", query)
    );
    for (i, c) in cands.iter().enumerate() {
        let exact = if c.name == query { color("90", "  [exact name]") } else { String::new() };
        eprintln!(
            "    {}) {} {}  (votes {}, pop {:.2}){}",
            i + 1,
            vt(&c.name),
            vt(&c.version),
            c.votes.unwrap_or(0),
            c.popularity.unwrap_or(0.0),
            exact
        );
    }
    if !std::io::stdin().is_terminal() {
        eprintln!(":: non-interactive — choosing 1) {}", vt(&cands[0].name));
        return Ok(cands[0].name.clone());
    }
    loop {
        eprint!(":: Enter a number (default=1): ");
        let _ = std::io::stderr().flush();
        let mut line = String::new();
        if std::io::stdin().read_line(&mut line).is_err() {
            return Ok(cands[0].name.clone());
        }
        let line = line.trim();
        if line.is_empty() {
            return Ok(cands[0].name.clone());
        }
        match line.parse::<usize>() {
            Ok(n) if n >= 1 && n <= cands.len() => return Ok(cands[n - 1].name.clone()),
            _ => eprintln!("   invalid selection"),
        }
    }
}

/// Resolve each requested name to a concrete package, prompting on provider
/// ambiguity. Runs before any review or build.
fn select_targets(requested: &[String]) -> Result<Vec<String>> {
    let mut chosen = Vec::new();
    for name in requested {
        let cands = aur::providers(name)?;
        match cands.as_slice() {
            [] => bail!("'{name}' has no AUR package or provider"),
            [only] => chosen.push(only.name.clone()),
            many => chosen.push(choose_provider(name, many)?),
        }
    }
    Ok(chosen)
}

fn run() -> Result<()> {
    let cli = Cli::parse();

    // First-run onboarding: if no API key is configured and we're interactive,
    // guide the user through creating and securely storing one before anything
    // else. No-op when a key already exists or when non-interactive.
    config::ensure_api_key()?;

    if cli.packages.is_empty() {
        bail!("No packages specified. Usage: claurde <package>...");
    }
    let cfg = Config::load(cli.model, cli.helper)?;

    // Provider choice happens FIRST, before any review or build, so clAURde
    // reviews and installs exactly the package the user picked.
    let targets = select_targets(&cli.packages)?;

    eprintln!("Resolving AUR dependency tree...");
    let pkgs = aur::resolve(&targets, &cfg.cache_dir)?;

    if cli.no_review {
        eprintln!("{}", color("33", "Skipping AI review (--no-review)."));
        return handoff(&cfg, &pkgs);
    }

    eprintln!("Reviewing {} package(s) with {} ...", pkgs.len(), cfg.model);

    let mut verdicts = Vec::new();
    let mut blocked = false;
    for p in &pkgs {
        let commit = aur::head_commit(&p.path);

        // The verdict cache keys on the AUR commit, which does NOT capture
        // mutable upstream sources (moving git refs, SKIP-checksum downloads).
        // For those, never serve or store a cached verdict — always re-review,
        // so changed build inputs can't ride a stale "safe".
        let mutable = sources::has_mutable_sources(&p.path);
        let cached = if cli.no_cache || mutable {
            None
        } else {
            commit
                .as_deref()
                .and_then(|c| cache::load(&cfg.cache_dir, c, &cfg.model))
        };

        let (v, from_cache) = match cached {
            Some(v) => (v, true),
            None => {
                let ev = collect::collect(
                    &p.path,
                    &p.info.package_base,
                    commit.as_deref(),
                    &cfg.cache_dir,
                    cfg.max_diff_commits,
                    !cli.no_fetch_sources,
                )?;
                let v = review::review(&cfg.api_key, &cfg.model, &p.info, &ev)?;
                if !cli.no_cache && !mutable {
                    if let Some(c) = &commit {
                        cache::store(&cfg.cache_dir, c, &cfg.model, &v);
                    }
                }
                (v, false)
            }
        };

        if !cli.json {
            print_verdict(&p.info.name, &v, from_cache);
        }
        if !v.is_clean() {
            blocked = true;
        }
        verdicts.push((p.info.name.clone(), v));
    }

    if cli.json {
        let out: Vec<_> = verdicts
            .iter()
            .map(|(n, v)| {
                serde_json::json!({
                    "name": n, "verdict": v.verdict, "risk_score": v.risk_score,
                    "summary": v.summary, "prompt_injection_detected": v.prompt_injection_detected,
                    "findings": v.findings.iter().map(|f| serde_json::json!({
                        "severity": f.severity, "category": f.category,
                        "location": f.location, "description": f.description
                    })).collect::<Vec<_>>()
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&out)?);
    }

    if cli.review_only {
        return Ok(());
    }

    if blocked && !cli.yes {
        eprintln!("\n{}", color("31;1", "One or more packages were not cleanly approved."));
        if !confirm("Build anyway?") {
            bail!("Aborted by clAURde — review was not clean.");
        }
    } else if !blocked {
        eprintln!("\n{}", color("32", "All packages passed review."));
    }

    handoff(&cfg, &pkgs)
}

fn main() {
    if let Err(e) = run() {
        eprintln!("{} {:#}", color("31;1", "error:"), e);
        std::process::exit(1);
    }
}
