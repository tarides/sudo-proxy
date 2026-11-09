//! Keep the manual-test plans (`tests/manual/{log-corpus,ui}/*.json`) honest: every
//! plan must parse, validate, and compile for display exactly as the daemon does
//! before prompting. Nothing runs — this only catches drift when the plan
//! schema changes (an op rename would otherwise silently rot the corpus).

use std::collections::HashMap;
use std::path::Path;

use sudo_proxy::executor::plan_display;
use sudo_proxy::protocol::{Plan, Request, ValidatedRequest};
use sudo_proxy::tui::command_summary;

#[test]
fn log_corpus_plans_parse_validate_and_render() {
    check_dir("tests/manual/log-corpus");
}

#[test]
fn ui_check_plans_parse_validate_and_render() {
    check_dir("tests/manual/ui");
}

fn check_dir(rel: &str) {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join(rel);
    let mut files: Vec<_> = std::fs::read_dir(&dir)
        .expect("corpus dir")
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|e| e == "json"))
        .collect();
    files.sort();
    assert!(!files.is_empty(), "no corpus plans found in {}", dir.display());

    for path in &files {
        let name = path.file_name().unwrap().to_string_lossy();
        let text = std::fs::read_to_string(path).unwrap();
        let plan: Plan =
            serde_json::from_str(&text).unwrap_or_else(|e| panic!("{name}: bad plan JSON: {e}"));
        // Checked unprivileged: ambient privilege changes colouring, not structure.
        let req = Request::new_plan(
            String::new(),
            "test".into(),
            plan,
            HashMap::new(),
            format!("corpus {name}"),
            false,
            false,
        );
        let req = ValidatedRequest::validate(req)
            .unwrap_or_else(|e| panic!("{name}: rejected by validation: {e}"));
        let leaves = plan_display(&req)
            .unwrap_or_else(|e| panic!("{name}: rejected before prompting: {e}"));
        assert!(!leaves.is_empty(), "{name}: no stages");
        let line = command_summary(&req);
        assert!(!line.contains("bash -lc"), "{name}: Command line still wraps bash -lc: {line}");
    }
}
