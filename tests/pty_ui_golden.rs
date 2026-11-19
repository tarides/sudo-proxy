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

    check_goldens(&blocks, "plain");
}
