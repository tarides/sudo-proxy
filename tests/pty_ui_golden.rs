#![cfg(target_os = "linux")]

//! Golden snapshots of the real TUI prompt for the UI-check plans in
//! `tests/manual/ui/*.json` (the "UI checks" table in `docs/testing.md`).
//!
//! Each plan is sent to a real daemon through a pty (`common::pty`), the
//! prompt block it draws on `/dev/tty` is captured, answered `n` (nothing
//! runs), masked for host-dependent detail and compared with
//! `tests/manual/ui/golden/<stem>.{plain,color}.txt`. Escapes are stored
//! visibly (`\e`), so a colour change shows up as a text diff.
//!
//! Regenerate after an intended prompt change, then review the diff:
//!
//! ```text
//! UPDATE_GOLDEN=1 cargo test --test pty_ui_golden
//! ```
//!
//! Independently of the goldens, the colour run asserts the escalation colours
//! directly (bright red root boundary, light red ambient root, bright yellow
//! named user), and the `NO_COLOR` run asserts that no escape is emitted.

use std::path::{Path, PathBuf};

use sudo_proxy::protocol::{Plan, Status};

mod common;

use common::pty::{visible, PtyDaemon, PtyOpts};

/// The UI-check plans and whether each is sent as a privileged request
/// (`(privileged)` vs `--no-privilege` in the `docs/testing.md` table).
const CASES: &[(&str, bool)] = &[
    ("showcase", false),
    ("escalation-a-ambient", true),
    ("escalation-b-boundary", false),
    ("escalation-c-ambient-plus-boundary", true),
    ("escalation-d-named-user", false),
    ("long-argument", true),
    ("wrappers", true),
    ("remote", true),
];

const AMBIENT_ROOT: &str = "\x1b[38;5;210m";
const ROOT_BOUNDARY: &str = "\x1b[38;5;196m";
const NAMED_USER: &str = "\x1b[38;5;226m";

fn ui_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/manual/ui")
}

#[test]
fn every_ui_plan_has_a_case() {
    let mut stems: Vec<String> = std::fs::read_dir(ui_dir())
        .expect("ui dir")
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|e| e == "json"))
        .map(|p| p.file_stem().unwrap().to_string_lossy().into_owned())
        .collect();
    stems.sort();
    let mut known: Vec<String> = CASES.iter().map(|(s, _)| s.to_string()).collect();
    known.sort();
    assert_eq!(stems, known, "tests/manual/ui/*.json and CASES disagree");
}

/// Send every case to one daemon, deny each, and return `(stem, raw block)`.
fn capture_all(color: bool) -> Vec<(&'static str, String)> {
    let mut d = PtyDaemon::spawn(PtyOpts { color, ..Default::default() });
    let mut out = Vec::new();
    for &(stem, privileged) in CASES {
        let text = std::fs::read_to_string(ui_dir().join(format!("{stem}.json"))).unwrap();
        let plan: Plan = serde_json::from_str(&text).unwrap_or_else(|e| panic!("{stem}: {e}"));
        let mut r = common::make_req(&format!("ui-{stem}"), vec![]);
        r.plan = Some(plan);
        r.reason = format!("ui golden {stem}");
        r.privileged = privileged;
        // Fixed, so the `Client:` line survives version bumps.
        r.version = "0.0.0-golden".into();

        let h = d.request_async(&r);
        // The block starts at the blank line before the header; drop anything
        // drawn earlier (there is nothing today, but a banner would leak in).
        let head = d.expect("Privilege Request");
        let start = head.rfind('\n').unwrap_or(0);
        let mut block = head[start..].to_string();
        block += &d.expect("default=N) ");
        d.answer_raw(b'n');
        block += &d.expect("→ Denied");
        block += &d.expect("━━━━━━━━━━━━━━━━━━━━━━━━━");
        block += &d.expect("\n");
        let resp = h.join().unwrap();
        assert_eq!(resp.status, Status::Denied, "{stem}: {resp:?}");
        out.push((stem, block));
    }
    assert!(d.shim_log().is_empty(), "a denied plan reached sudo: {:?}", d.shim_log());
    out
}

/// Replace host-dependent detail: the request time, and every resolved path
/// (`/usr/bin` vs `/bin`, multi-call symlinks). The binary names stay.
fn mask(block: &str) -> String {
    let mut out = String::new();
    let mut in_resolves = false;
    for line in block.split_inclusive('\n') {
        let (body, nl) = match line.strip_suffix('\n') {
            Some(b) => (b, "\n"),
            None => (line, ""),
        };
        if body.starts_with("Time:") {
            out += "Time:    <TIME>";
        } else if body == "Resolves:" {
            in_resolves = true;
            out += body;
        } else if body.starts_with("Resolves: ") {
            out += "Resolves: <PATH>";
        } else if in_resolves && body.starts_with("  ") {
            // `  name<pad>  detail`: keep the name column, mask the detail.
            let name_end = 2 + body[2..].find(' ').unwrap_or(body.len() - 2);
            let detail_start = name_end + body[name_end..].len() - body[name_end..].trim_start().len();
            out += &body[..detail_start];
            out += "<PATH>";
        } else {
            in_resolves = false;
            out += body;
        }
        out += nl;
    }
    out
}

fn check_goldens(blocks: &[(&str, String)], kind: &str) {
    let update = std::env::var_os("UPDATE_GOLDEN").is_some_and(|v| v == "1");
    let dir = ui_dir().join("golden");
    let mut failures = Vec::new();
    for (stem, block) in blocks {
        let actual = visible(mask(block).as_bytes());
        let path = dir.join(format!("{stem}.{kind}.txt"));
        if update {
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(&path, &actual).unwrap();
            continue;
        }
        match std::fs::read_to_string(&path) {
            Ok(expected) if expected == actual => {}
            Ok(expected) => failures.push(format!(
                "{} differs\n--- expected ---\n{expected}--- actual ---\n{actual}",
                path.display()
            )),
            Err(e) => failures.push(format!("{}: {e}\n--- actual ---\n{actual}", path.display())),
        }
    }
    assert!(
        failures.is_empty(),
        "{}\n\nIf the prompt change is intended: UPDATE_GOLDEN=1 cargo test --test pty_ui_golden, \
         then review the golden diff.",
        failures.join("\n")
    );
}

/// The `Steps:` line that holds `needle` (a command, uncoloured text).
fn step_line<'a>(block: &'a str, needle: &str) -> &'a str {
    let steps = &block[block.find("Steps:").expect("Steps: block")..];
    steps.lines().find(|l| l.contains(needle)).unwrap_or_else(|| panic!("no step {needle:?} in {block:?}"))
}

fn get<'a>(blocks: &'a [(&str, String)], stem: &str) -> &'a str {
    &blocks.iter().find(|(s, _)| *s == stem).unwrap().1
}

#[test]
fn ui_prompts_color() {
    let blocks = capture_all(true);

    let showcase = get(&blocks, "showcase");
    assert!(
        step_line(showcase, "id -un").contains(&format!("{ROOT_BOUNDARY}sudo id -un")),
        "showcase: sudo id -un not bright red"
    );

    let a = get(&blocks, "escalation-a-ambient");
    // Every step light red, and the `&&` between them tinted too.
    assert!(step_line(a, "sudo id -un").contains(&format!("{AMBIENT_ROOT} &&")), "a: && not tinted");
    assert!(step_line(a, "sudo id -u\x1b").contains(AMBIENT_ROOT), "a: id -u not light red");
    assert!(!a.contains(ROOT_BOUNDARY), "a: ambient root shown as a boundary");

    let b = get(&blocks, "escalation-b-boundary");
    assert!(step_line(b, "whoami").contains(&format!("{ROOT_BOUNDARY}sudo whoami")), "b: whoami not bright red");
    for plain in ["echo hi", "echo bye"] {
        assert!(!step_line(b, plain).contains("\x1b[38;5;"), "b: {plain} coloured");
    }

    let c = get(&blocks, "escalation-c-ambient-plus-boundary");
    assert!(step_line(c, "id -un").contains(&format!("{AMBIENT_ROOT}sudo id -un")), "c: id -un not light red");
    assert!(step_line(c, "id -un").contains(&format!("{AMBIENT_ROOT} &&")), "c: && not tinted");
    assert!(step_line(c, "whoami").contains(&format!("{ROOT_BOUNDARY}sudo whoami")), "c: whoami not bright red");

    let dd = get(&blocks, "escalation-d-named-user");
    assert!(
        step_line(dd, "id -un").contains(&format!("{NAMED_USER}sudo -u nobody id -un")),
        "d: id -un not bright yellow"
    );
    assert!(!step_line(dd, "echo hi").contains("\x1b[38;5;"), "d: echo hi coloured");
    assert!(!dd.contains(ROOT_BOUNDARY), "d: named user shown as root");

    check_goldens(&blocks, "color");
}

/// `s` as the terminal shows it: CSI escapes and the bell removed.
fn strip_escapes(s: &str) -> String {
    let mut out = String::new();
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\x1b' && chars.peek() == Some(&'[') {
            chars.next();
            for f in chars.by_ref() {
                if ('\x40'..='\x7e').contains(&f) {
                    break;
                }
            }
        } else if c != '\x07' {
            out.push(c);
        }
    }
    out
}

/// G4.3 / #85: a privileged request with a 900 KB argument (under the 1 MiB
/// request cap; sent over the socket, so no kernel per-argument limit) cannot
/// flood the prompt through any line: `Command:`, `Steps:` and `Resolves:` are
/// all bounded, and the question is the last line.
#[test]
fn huge_argument_prompt_is_bounded() {
    // `MAX_DISPLAY_CMD_CHARS` (1024) + the `truncate_for_display` marker
    // (≤ 64) + label and agent tag (≤ 64), see `src/tui.rs`. Every plan-block
    // line has a smaller bound.
    const META_BOUND: usize = 1024 + 64 + 64;

    let mut d = PtyDaemon::spawn(PtyOpts { color: true, ..Default::default() });
    let mut r = common::make_req("ui-huge-argument", vec![]);
    r.plan = Some(Plan::Exec { argv: vec!["echo".into(), "A".repeat(900_000)] });
    r.privileged = true;
    let h = d.request_async(&r);
    let head = d.expect("Privilege Request");
    let start = head.rfind('\n').unwrap_or(0);
    let mut block = head[start..].to_string();
    block += &d.expect("default=N) ");

    assert!(block.len() < 16 * 1024, "prompt block of {} bytes", block.len());
    let shown = strip_escapes(&block);
    for line in shown.lines() {
        assert!(line.chars().count() <= META_BOUND, "line of {} chars", line.chars().count());
    }
    assert!(shown.contains("\nCommand: "), "{shown}");
    assert!(shown.contains("\nSteps:\n"), "{shown}");
    let steps0 = shown.lines().skip_while(|l| *l != "Steps:").nth(1).expect("Steps line 0");
    assert!(steps0.starts_with("0  sudo echo AAAA") && steps0.contains("more chars hidden"), "{steps0}");
    let last = shown.lines().last().expect("a line").trim_end();
    assert!(
        last.starts_with("Execute as root? [y/N] (") && last.ends_with("s timeout, default=N)"),
        "question is not the last line: {last:?}"
    );

    d.answer_raw(b'n');
    d.expect("→ Denied");
    let resp = h.join().unwrap();
    assert_eq!(resp.status, Status::Denied, "{resp:?}");
    assert!(d.shim_log().is_empty(), "a denied plan reached sudo: {:?}", d.shim_log());
}

#[test]
fn ui_prompts_no_color() {
    let blocks = capture_all(false);
    for (stem, block) in &blocks {
        assert!(!block.contains('\x1b'), "{stem}: escape under NO_COLOR: {}", visible(block.as_bytes()));
    }
    // Without colour, escalation still reads from the `sudo` prefix.
    assert!(step_line(get(&blocks, "showcase"), "id -un").contains("sudo id -un"));
    assert!(step_line(get(&blocks, "escalation-a-ambient"), "id -un").contains("sudo id -un"));
    assert!(step_line(get(&blocks, "escalation-b-boundary"), "whoami").contains("sudo whoami"));
    assert!(!step_line(get(&blocks, "escalation-b-boundary"), "echo hi").contains("sudo"));
    assert!(step_line(get(&blocks, "escalation-c-ambient-plus-boundary"), "whoami").contains("sudo whoami"));
    assert!(step_line(get(&blocks, "escalation-d-named-user"), "id -un").contains("sudo -u nobody id -un"));

    // `mask` replaces the whole detail column, so the wrapper suffixes are
    // checked on the raw block.
    let w = get(&blocks, "wrappers");
    assert!(w.contains("opaque — resolves only the shell (run by timeout; looked up at run time)"), "{w}");
    assert!(w.contains("(run by env; looked up at run time)"), "{w}");

    // #91: plain rsync stays transparent; `rsync -e` is opaque.
    let r = get(&blocks, "remote");
    assert!(
        r.contains(
            "opaque — runs a command string remotely or through a shell (-e) \
             (run by timeout; looked up at run time)"
        ),
        "{r}"
    );
    assert_eq!(r.matches("opaque — ").count(), 1, "{r}");

    check_goldens(&blocks, "plain");
}
