//! Byte-level scanner for shell-integration OSC sequences.
//!
//! `vte`'s `osc_dispatch` only handles a fixed set of OSC codes, so `133` /
//! `633` / `7` would otherwise be dropped. Instead of forking `vte`, the event
//! loop runs this scanner over the raw PTY bytes and emits
//! [`ShellIntegrationEvent`]s.
//!
//! Supported sequences (terminated by BEL or `ESC \`):
//! - `OSC 133 ; A` prompt started
//! - `OSC 133 ; B` command started
//! - `OSC 133 ; C` command executing
//! - `OSC 133 ; D [; exit]` command ended
//! - `OSC 133 ; E [; cmd]` current command line
//! - `OSC 633 ; A/B/C` VS Code prompt/command markers
//! - `OSC 633 ; D [; exit]` VS Code command ended
//! - `OSC 633 ; E [; cmd]` VS Code command line
//! - `OSC 633 ; P ; Cwd=path` VS Code cwd property
//! - `OSC 7 ; file://host/path` cwd changed

use std::path::PathBuf;

use crate::event::ShellIntegrationEvent;

/// Max bytes retained as a partial OSC tail across reads.
const MAX_TAIL: usize = 4096;

/// Extract shell-integration events from a PTY read.
///
/// `tail` holds an incomplete trailing OSC from the previous read. It is
/// updated in place; complete events are returned.
pub fn extract(tail: &mut Vec<u8>, chunk: &[u8]) -> Vec<ShellIntegrationEvent> {
    tail.extend_from_slice(chunk);
    let mut events = Vec::new();
    let mut cursor = 0;

    while let Some(start) = find_osc_start(&tail[cursor..]) {
        let abs_start = cursor + start;
        match find_osc_end(tail, abs_start) {
            Some((content_end, term_len)) => {
                if let Some(ev) = parse_osc(&tail[abs_start..content_end]) {
                    events.extend(ev);
                }
                cursor = content_end + term_len;
            },
            None => {
                // Incomplete trailing sequence: keep it for the next read.
                if abs_start > 0 {
                    tail.drain(..abs_start);
                }
                truncate_tail(tail);
                return events;
            },
        }
    }

    tail.clear();
    events
}

fn truncate_tail(tail: &mut Vec<u8>) {
    if tail.len() > MAX_TAIL {
        let excess = tail.len() - MAX_TAIL;
        tail.drain(..excess);
    }
}

/// Find `ESC ]` relative to `buf`.
fn find_osc_start(buf: &[u8]) -> Option<usize> {
    buf.windows(2).position(|w| w[0] == 0x1b && w[1] == 0x5d)
}

/// Find the end of the OSC content starting at `start` (which points at ESC).
/// Returns `(content_end, terminator_len)`.
fn find_osc_end(buf: &[u8], start: usize) -> Option<(usize, usize)> {
    let mut i = start + 2;
    while i < buf.len() {
        if buf[i] == 0x07 {
            return Some((i, 1));
        }
        if buf[i] == 0x1b && i + 1 < buf.len() {
            if buf[i + 1] == 0x5c {
                return Some((i, 2));
            }
            // A new OSC aborts the previous incomplete one; treat as incomplete
            // only if no terminator was found — caller keeps the tail.
            if buf[i + 1] == 0x5d {
                return None;
            }
        }
        i += 1;
        // Bound single OSC length to avoid pathological scans.
        if i - start > MAX_TAIL {
            return None;
        }
    }
    None
}

fn parse_osc(content: &[u8]) -> Option<Vec<ShellIntegrationEvent>> {
    // content starts with `ESC ]`; strip it.
    let body = content.get(2..)?;
    let code_end = body.iter().position(|&b| b == b';').unwrap_or(body.len());
    let (code, rest) = body.split_at(code_end);
    let rest = rest.strip_prefix(b";").unwrap_or(b"");

    match code {
        b"133" => parse_133(rest),
        b"633" => parse_633(rest),
        b"7" => parse_7(rest).map(|p| vec![ShellIntegrationEvent::CwdChanged(p)]),
        _ => None,
    }
}

fn parse_133(rest: &[u8]) -> Option<Vec<ShellIntegrationEvent>> {
    let (kind, payload) = split_first_field(rest)?;
    match kind {
        b"A" => Some(vec![ShellIntegrationEvent::PromptStarted]),
        b"B" => Some(vec![ShellIntegrationEvent::CommandStarted]),
        b"C" => Some(vec![ShellIntegrationEvent::CommandExecuting]),
        b"D" => Some(vec![ShellIntegrationEvent::CommandEnded {
            exit_code: parse_exit_code(payload),
        }]),
        b"E" => {
            let cmd = payload.and_then(|p| std::str::from_utf8(p).ok()).unwrap_or("").to_string();
            Some(vec![ShellIntegrationEvent::CurrentCommand(cmd)])
        },
        _ => None,
    }
}

fn parse_633(rest: &[u8]) -> Option<Vec<ShellIntegrationEvent>> {
    let (kind, payload) = split_first_field(rest)?;
    match kind {
        b"A" => Some(vec![ShellIntegrationEvent::PromptStarted]),
        b"B" => Some(vec![ShellIntegrationEvent::CommandStarted]),
        b"C" => Some(vec![ShellIntegrationEvent::CommandExecuting]),
        b"D" => Some(vec![ShellIntegrationEvent::CommandEnded {
            exit_code: parse_exit_code(payload),
        }]),
        b"E" => {
            let cmd = payload.and_then(|p| std::str::from_utf8(p).ok()).unwrap_or("").to_string();
            Some(vec![ShellIntegrationEvent::CurrentCommand(cmd)])
        },
        b"P" => parse_633_property(payload),
        _ => None,
    }
}

fn parse_633_property(payload: Option<&[u8]>) -> Option<Vec<ShellIntegrationEvent>> {
    let payload = payload?;
    // Forms: `Cwd=<path>` or `Cwd=<path>;...` (take first field).
    let field_end = payload.iter().position(|&b| b == b';').unwrap_or(payload.len());
    let field = &payload[..field_end];
    let value = field.strip_prefix(b"Cwd=")?;
    let path = std::str::from_utf8(value).ok()?;
    Some(vec![ShellIntegrationEvent::CwdChanged(PathBuf::from(path))])
}

fn parse_7(rest: &[u8]) -> Option<PathBuf> {
    let uri = std::str::from_utf8(rest).ok()?.trim();
    uri_to_path(uri)
}

/// Split `field[;payload]`, returning `(field, payload)`.
fn split_first_field(buf: &[u8]) -> Option<(&[u8], Option<&[u8]>)> {
    if buf.is_empty() {
        return None;
    }
    match buf.iter().position(|&b| b == b';') {
        Some(i) => Some((&buf[..i], Some(&buf[i + 1..]))),
        None => Some((buf, None)),
    }
}

fn parse_exit_code(payload: Option<&[u8]>) -> Option<i32> {
    let payload = payload?;
    let end = payload.iter().position(|&b| b == b';').unwrap_or(payload.len());
    let s = std::str::from_utf8(&payload[..end]).ok()?.trim();
    if s.is_empty() {
        return None;
    }
    s.parse::<i32>().ok()
}

/// Convert `file://[host]/path` to a local [`PathBuf`].
fn uri_to_path(uri: &str) -> Option<PathBuf> {
    let without_scheme = uri.strip_prefix("file://")?;
    // Strip host (`localhost`, empty, or remote — we only handle local).
    let path_part = match without_scheme.find('/') {
        Some(i) => &without_scheme[i..],
        None => return None,
    };
    Some(PathBuf::from(percent_decode(path_part)))
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(h), Some(l)) = (hex(bytes[i + 1]), hex(bytes[i + 2])) {
                out.push(h << 4 | l);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(chunks: &[&[u8]]) -> Vec<ShellIntegrationEvent> {
        let mut tail = Vec::new();
        let mut out = Vec::new();
        for chunk in chunks {
            out.extend(extract(&mut tail, chunk));
        }
        out
    }

    #[test]
    fn parses_prompt_and_command_cycle() {
        let evs = run(&[b"\x1b]133;A\x07echo hi\x1b]133;B\x07\x1b]133;C\x07\x1b]133;D;0\x07"]);
        assert!(matches!(evs[0], ShellIntegrationEvent::PromptStarted));
        assert!(matches!(evs[1], ShellIntegrationEvent::CommandStarted));
        assert!(matches!(evs[2], ShellIntegrationEvent::CommandExecuting));
        assert!(matches!(
            evs[3],
            ShellIntegrationEvent::CommandEnded { exit_code: Some(0) }
        ));
    }

    #[test]
    fn handles_split_reads() {
        let evs = run(&[b"\x1b]133;A\x1b\\", b"foo\x1b]133;D;", b"2\x07"]);
        assert!(matches!(evs[0], ShellIntegrationEvent::PromptStarted));
        assert!(matches!(
            evs[1],
            ShellIntegrationEvent::CommandEnded { exit_code: Some(2) }
        ));
    }

    #[test]
    fn parses_osc7_cwd() {
        let evs = run(&[b"\x1b]7;file://host/home/user/proj\x07"]);
        match &evs[0] {
            ShellIntegrationEvent::CwdChanged(p) => assert_eq!(p.to_str().unwrap(), "/home/user/proj"),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn parses_vscode_markers() {
        let evs = run(&[b"\x1b]633;E;cargo build\x07\x1b]633;D;1\x07"]);
        assert!(matches!(evs[0], ShellIntegrationEvent::CurrentCommand(_)));
        assert!(matches!(
            evs[1],
            ShellIntegrationEvent::CommandEnded { exit_code: Some(1) }
        ));
        if let ShellIntegrationEvent::CurrentCommand(cmd) = &evs[0] {
            assert_eq!(cmd, "cargo build");
        }
    }

    #[test]
    fn ignores_other_osc() {
        let evs = run(&[b"\x1b]0;title\x07\x1b]52;c;dGVzdA==\x07"]);
        assert!(evs.is_empty());
    }
}
