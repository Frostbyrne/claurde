//! Shared networking: HTTP agents with hard timeouts, an SSRF guard for
//! attacker-declared source downloads, and a hardened/timed git runner.
//!
//! Every network call clAURde makes is, directly or transitively, against a
//! host an attacker can choose (the source URLs in a package's .SRCINFO, the
//! git remotes it points at). ureq's defaults have no read/overall timeout and
//! git inherits an interactive terminal, so without this module a single
//! malicious package could hang the security review forever (or redirect a
//! download at an internal service). All bounds live here.

use std::ffi::OsStr;
use std::net::{IpAddr, ToSocketAddrs};
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

/// Wire identity; tracks the crate version instead of a hand-edited literal.
pub const USER_AGENT: &str = concat!("claurde/", env!("CARGO_PKG_VERSION"));

const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const READ_TIMEOUT: Duration = Duration::from_secs(60);
const WRITE_TIMEOUT: Duration = Duration::from_secs(30);
/// Overall per-request ceiling — the load-bearing bound against a server that
/// completes the handshake then trickles or never finishes the body.
const OVERALL_TIMEOUT: Duration = Duration::from_secs(300);

fn builder() -> ureq::AgentBuilder {
    ureq::AgentBuilder::new()
        .timeout_connect(CONNECT_TIMEOUT)
        .timeout_read(READ_TIMEOUT)
        .timeout_write(WRITE_TIMEOUT)
        .timeout(OVERALL_TIMEOUT)
        .user_agent(USER_AGENT)
}

/// Agent for trusted, well-behaved hosts (AUR RPC, the Anthropic API). Follows
/// a small number of redirects normally.
pub fn agent() -> ureq::Agent {
    builder().redirects(4).build()
}

/// Agent for attacker-declared source URLs: never auto-follows redirects, so
/// the caller can validate every hop's host before re-requesting.
pub fn no_redirect_agent() -> ureq::Agent {
    builder().redirects(0).build()
}

/// True only for a genuinely public, routable address. Loopback, private,
/// link-local (incl. 169.254.169.254 cloud metadata), CGNAT, ULA, and
/// unspecified addresses are rejected — these are the SSRF targets a source URL
/// must never reach.
pub fn is_public_addr(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            !(v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_documentation()
                || v4.is_unspecified()
                || v4.octets()[0] == 0
                // 100.64.0.0/10 carrier-grade NAT
                || (v4.octets()[0] == 100 && (v4.octets()[1] & 0xc0) == 64)
                // 192.0.0.0/24 IETF protocol assignments
                || (v4.octets()[0] == 192 && v4.octets()[1] == 0 && v4.octets()[2] == 0)
                // 198.18.0.0/15 benchmarking
                || (v4.octets()[0] == 198 && (v4.octets()[1] & 0xfe) == 18))
        }
        IpAddr::V6(v6) => {
            if let Some(mapped) = v6.to_ipv4_mapped() {
                return is_public_addr(IpAddr::V4(mapped));
            }
            let seg = v6.segments();
            !(v6.is_loopback()
                || v6.is_unspecified()
                // fc00::/7 unique-local
                || (seg[0] & 0xfe00) == 0xfc00
                // fe80::/10 link-local
                || (seg[0] & 0xffc0) == 0xfe80
                // ::ffff:0:0/96 handled above; 64:ff9b::/96 NAT64 maps to v4
                )
        }
    }
}

/// Resolve `host:port` and require that EVERY resolved address is public.
/// Returns Err with a human reason if the host doesn't resolve or any address
/// is non-public (fail closed — one private address blocks the request).
pub fn check_host_public(host: &str, port: u16) -> Result<(), String> {
    let addrs: Vec<_> = (host, port)
        .to_socket_addrs()
        .map_err(|e| format!("could not resolve host '{host}': {e}"))?
        .collect();
    if addrs.is_empty() {
        return Err(format!("host '{host}' resolved to no addresses"));
    }
    for sa in &addrs {
        if !is_public_addr(sa.ip()) {
            return Err(format!(
                "host '{host}' resolves to a non-public address ({}) — refusing (SSRF guard)",
                sa.ip()
            ));
        }
    }
    Ok(())
}

/// (scheme, host, port) of an absolute http(s) URL. None for anything else.
pub fn split_url(url: &str) -> Option<(&str, String, u16)> {
    let (scheme, rest) = url.split_once("://")?;
    let scheme = scheme.to_ascii_lowercase();
    let scheme = if scheme == "http" {
        "http"
    } else if scheme == "https" {
        "https"
    } else {
        return None;
    };
    // authority ends at the first '/', '?' or '#'
    let authority = rest
        .split(['/', '?', '#'])
        .next()
        .unwrap_or(rest);
    // strip userinfo
    let hostport = authority.rsplit('@').next().unwrap_or(authority);
    let (host, port) = if let Some(stripped) = hostport.strip_prefix('[') {
        // IPv6 literal [::1]:port
        let (h, after) = stripped.split_once(']')?;
        let port = after
            .strip_prefix(':')
            .and_then(|p| p.parse().ok())
            .unwrap_or(if scheme == "https" { 443 } else { 80 });
        (h.to_string(), port)
    } else if let Some((h, p)) = hostport.rsplit_once(':') {
        // only treat trailing ':NNN' as a port if it parses
        match p.parse::<u16>() {
            Ok(port) => (h.to_string(), port),
            Err(_) => (hostport.to_string(), if scheme == "https" { 443 } else { 80 }),
        }
    } else {
        (hostport.to_string(), if scheme == "https" { 443 } else { 80 })
    };
    if host.is_empty() {
        return None;
    }
    Some((scheme, host, port))
}

/// Resolve a redirect `Location` against the URL it came from. Handles absolute
/// URLs, scheme-relative `//host/...`, absolute-path `/...`, and simple relative
/// paths. Returns None if it can't be resolved to an absolute http(s) URL.
pub fn join_url(base: &str, location: &str) -> Option<String> {
    let location = location.trim();
    if location.is_empty() {
        return None;
    }
    if location.contains("://") {
        return Some(location.to_string());
    }
    let (scheme, host, port) = split_url(base)?;
    let default_port = if scheme == "https" { 443 } else { 80 };
    let authority = if port == default_port {
        host
    } else {
        format!("{host}:{port}")
    };
    if let Some(rest) = location.strip_prefix("//") {
        return Some(format!("{scheme}://{rest}"));
    }
    if location.starts_with('/') {
        return Some(format!("{scheme}://{authority}{location}"));
    }
    // relative path: resolve against the base path's directory
    let path = base
        .split_once("://")
        .and_then(|(_, r)| r.split(['?', '#']).next())
        .map(|r| r.find('/').map(|i| &r[i..]).unwrap_or("/"))
        .unwrap_or("/");
    let dir = match path.rfind('/') {
        Some(i) => &path[..=i],
        None => "/",
    };
    Some(format!("{scheme}://{authority}{dir}{location}"))
}

/// Run a git subcommand non-interactively with a wall-clock timeout. Output is
/// discarded. Returns true only on a clean exit within `secs`; a hang is killed
/// and reported as failure. The env hardening prevents a credential/host-key
/// prompt or a trickle server from blocking the review.
pub fn run_git(args: &[&OsStr], secs: u64) -> bool {
    let mut cmd = Command::new("git");
    harden_git(&mut cmd);
    cmd.args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    match cmd.spawn() {
        Ok(mut child) => wait_timeout(&mut child, secs)
            .map(|s| s.success())
            .unwrap_or(false),
        Err(_) => false,
    }
}

/// Apply non-interactive, prompt-free, trickle-resistant env to a git Command.
pub fn harden_git(cmd: &mut Command) {
    cmd.env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_ASKPASS", "/bin/true")
        .env("GIT_SSH_COMMAND", "ssh -oBatchMode=yes -oConnectTimeout=15")
        .env("GIT_HTTP_LOW_SPEED_LIMIT", "1000")
        .env("GIT_HTTP_LOW_SPEED_TIME", "30")
        .env("GIT_CONFIG_NOSYSTEM", "1");
}

/// Block until `child` exits or `secs` elapse; on timeout, kill it and return
/// None. Dependency-free (polls try_wait rather than pulling in wait-timeout).
pub fn wait_timeout(child: &mut Child, secs: u64) -> Option<ExitStatus> {
    let deadline = Instant::now() + Duration::from_secs(secs);
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Some(status),
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return None;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(_) => return None,
        }
    }
}

/// Cumulative byte size of a directory tree, short-circuiting as soon as it
/// exceeds `cap` (returns true). Used to abort a decompression bomb mid-extract
/// without ever walking an unbounded number of entries.
pub fn dir_size_exceeds(root: &Path, cap: u64) -> bool {
    let mut total: u64 = 0;
    let mut stack = vec![root.to_path_buf()];
    let mut scanned = 0usize;
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            scanned += 1;
            if scanned > 200_000 {
                return true; // absurd entry count is itself a bomb
            }
            let Ok(ft) = entry.file_type() else { continue };
            if ft.is_symlink() {
                continue;
            }
            if ft.is_dir() {
                stack.push(entry.path());
            } else if ft.is_file() {
                total = total.saturating_add(entry.metadata().map(|m| m.len()).unwrap_or(0));
                if total > cap {
                    return true;
                }
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn rejects_non_public_v4() {
        for ip in [
            "127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.1.1", "169.254.169.254",
            "100.64.0.1", "0.0.0.0", "198.18.0.5",
        ] {
            assert!(!is_public_addr(ip.parse::<Ipv4Addr>().unwrap().into()), "{ip} should be blocked");
        }
    }

    #[test]
    fn allows_public_v4() {
        for ip in ["8.8.8.8", "1.1.1.1", "140.82.121.3", "151.101.0.133"] {
            assert!(is_public_addr(ip.parse::<Ipv4Addr>().unwrap().into()), "{ip} should be allowed");
        }
    }

    #[test]
    fn rejects_non_public_v6_and_mapped() {
        for ip in ["::1", "::", "fc00::1", "fd12::1", "fe80::1", "::ffff:127.0.0.1", "::ffff:10.0.0.1"] {
            assert!(!is_public_addr(ip.parse::<Ipv6Addr>().unwrap().into()), "{ip} should be blocked");
        }
        assert!(is_public_addr("2606:4700:4700::1111".parse::<Ipv6Addr>().unwrap().into()));
    }

    #[test]
    fn split_url_parses_host_and_port() {
        assert_eq!(split_url("https://example.com/a/b").unwrap(), ("https", "example.com".into(), 443));
        assert_eq!(split_url("http://example.com:8080/x").unwrap(), ("http", "example.com".into(), 8080));
        assert_eq!(split_url("https://user:pw@host.tld/x").unwrap(), ("https", "host.tld".into(), 443));
        assert_eq!(split_url("http://[::1]:9000/x").unwrap(), ("http", "::1".into(), 9000));
        assert!(split_url("ftp://example.com/x").is_none());
        assert!(split_url("file:///etc/passwd").is_none());
    }

    #[test]
    fn join_url_resolves_redirects() {
        assert_eq!(join_url("https://a.com/x/y", "https://b.com/z").unwrap(), "https://b.com/z");
        assert_eq!(join_url("https://a.com/x/y", "/z").unwrap(), "https://a.com/z");
        assert_eq!(join_url("https://a.com:8443/x/y", "/z").unwrap(), "https://a.com:8443/z");
        assert_eq!(join_url("https://a.com/x/y", "//c.com/q").unwrap(), "https://c.com/q");
        assert_eq!(join_url("https://a.com/x/y", "z.tar").unwrap(), "https://a.com/x/z.tar");
        assert!(join_url("https://a.com/x", "").is_none());
    }
}
