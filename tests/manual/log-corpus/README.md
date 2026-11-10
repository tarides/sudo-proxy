# Log corpus: real `bash -lc` requests → structured plans

[← docs/testing.md](../../../docs/testing.md#replaying-a-real-approval-log)

These are the 24 requests an agent sent through `sudo-proxy-mcp` during one
real working session (a ThreadSanitizer and GC-stress campaign on a remote
bench box), before structured plans existed. Every one arrived as a single
opaque `bash -lc '…'`, so the prompt showed one resolved binary
(`/usr/bin/bash`) and a wall of nested quoting. Each `NN-*.json` file is the
same request rewritten as a structured plan, so a human reviewing the new
prompt sees what would actually run.

Use them to check the approval prompt against realistic input, not just toy
plans. They exercise every op, deep nesting, long `;` chains with `||`
fallbacks, per-stage `run-as root` / `run-as user` inside an otherwise
unprivileged request, and the opaque `shell` escape hatch.

**Don't approve them.** They refer to a project, worktrees and log files that
don't exist on your machine, and four of them change a sysctl as root. Send
each one, inspect the prompt, then press `n` (or Enter). The point is the
rendering, not the result.

`tests/manual_corpus.rs` parses, validates and display-compiles every file
here on `cargo test`, so they can't silently drift from the plan schema.

## Redaction

Machine-identifying details from the original log are replaced throughout:
the host and project name → `proj`, the user → `user` (`/home/user`),
worktrees → `wt-…`, the data config → `/mnt/data/proj.conf`.

## Translation conventions

| Shell in the original | Plan |
|---|---|
| `a; b` | `seq` |
| `a && b` | `run` |
| `a \|\| b` | `alt` |
| `a \| b` | `pipe` |
| `cd dir; …` | `chdir` around the rest |
| `cmd 2>/dev/null`, `>/dev/null` | `redirect` to `dev-null` |
| `cmd > file 2>&1` | `redirect` `both` to a file |
| `cmd 2>&1` (to the terminal) | dropped: stderr is already captured |
| `"text $(cat f)"` | `echo text` then `cat f` as separate stages |
| `echo exit $?` | dropped: the response's per-stage exit array shows it |
| `sudo -H -u user bash -lc '…'` | `run-as` `user` |
| the whole request as root | `--no-privilege`, with `run-as root` on only the stages that need it (`sysctl`, reading `/proc/sys/vm/mmap_rnd_bits`) |
| `VAR=… cmd` (`VAR` not on the env allowlist) | an explicit `env VAR=… cmd` stage: `setenv` only accepts allowlisted names |
| `nohup … & echo $!` | kept as an opaque `shell` node: there's no structured backgrounding op yet |
| `printf 'a\nb'` | unchanged: the two-character `\n` escape is passed through (a real newline in an argv is rejected) |

## Cases

## 01-verify-pipeline-launch

Log entry 1, unprivileged. Reason: *Verify pipeline launch state*

Original:

```sh
bash -lc 'ls -la /tmp/tsan_pipeline.log 2>&1; echo '\''---tail---'\''; tail -8 /tmp/tsan_pipeline.log 2>&1; echo '\''---procs---'\''; pgrep -af '\''ocaml.*tsan|opam install|dune build|switch create'\'' | head'
```

Send: `./target/release/sudo-request --socket /tmp/sp-test.sock --no-privilege --print --reason "Verify pipeline launch state" --plan-file tests/manual/log-corpus/01-verify-pipeline-launch.json`


## 02-launch-tsan-pipeline-bg

Log entry 2, unprivileged. Reason: *Launch full TSan build pipeline in background*

Original:

```sh
bash -lc 'cd ~; nohup bash -c '\''opam switch create ocaml+tsan --packages=ocaml-variants.5.4.0+options,ocaml-option-tsan --no-switch -y && git -C ~/proj-ocaml worktree remove --force ~/wt-130tsan 2>/dev/null; git -C ~/proj-ocaml worktree add -f ~/wt-130tsan _stage_130review && opam install --switch=ocaml+tsan -y ctypes ctypes-foreign domainslib alcotest qcheck qcheck-alcotest && cd ~/wt-130tsan && make -C abi clean && make abi && opam exec --switch=ocaml+tsan -- dune build && echo PIPELINE_DONE'\'' >/tmp/tsan_pipeline.log 2>&1 & echo launched pid $!'
```

Send: `./target/release/sudo-request --socket /tmp/sp-test.sock --no-privilege --print --reason "Launch full TSan build pipeline in background" --plan-file tests/manual/log-corpus/02-launch-tsan-pipeline-bg.json`

Notes: Backgrounding (`nohup … &`, `$!`) has no structured op: kept as the explicit opaque `shell` node.


## 03-confirm-pipeline-progress

Log entry 3, unprivileged. Reason: *Confirm pipeline is progressing*

Original:

```sh
bash -lc 'sleep 8; echo '\''---log size---'\''; ls -la /tmp/tsan_pipeline.log 2>&1; echo '\''---tail---'\''; tail -4 /tmp/tsan_pipeline.log 2>&1; echo '\''---switch-create proc---'\''; pgrep -af '\''switch create|opam'\'' | head -3'
```

Send: `./target/release/sudo-request --socket /tmp/sp-test.sock --no-privilege --print --reason "Confirm pipeline is progressing" --plan-file tests/manual/log-corpus/03-confirm-pipeline-progress.json`


## 04-long-poll-pipeline

Log entry 4, unprivileged. Reason: *Long-wait poll of TSan build pipeline (~8 min)*

Original:

```sh
bash -lc 'sleep 480; echo '\''=== PIPELINE_DONE present? ==='\''; grep -c PIPELINE_DONE /tmp/tsan_pipeline.log; echo '\''=== tail ==='\''; tail -6 /tmp/tsan_pipeline.log; echo '\''=== still running? ==='\''; pgrep -af '\''opam|dune build|make'\'' | grep -v pgrep | head -3 || echo '\''no build procs'\'''
```

Send: `./target/release/sudo-request --socket /tmp/sp-test.sock --no-privilege --print --reason "Long-wait poll of TSan build pipeline (~8 min)" --plan-file tests/manual/log-corpus/04-long-poll-pipeline.json`


## 05-poll-tsan-build

Log entry 5, unprivileged. Reason: *Poll TSan build (~4 min)*

Original:

```sh
bash -lc 'sleep 250; echo '\''=== PIPELINE_DONE? ==='\''; grep -c PIPELINE_DONE /tmp/tsan_pipeline.log; echo '\''=== tail ==='\''; tail -6 /tmp/tsan_pipeline.log; echo '\''=== build procs ==='\''; pgrep -af '\''opam|dune|make|ocamlopt'\'' | grep -v pgrep | head -3 || echo none'
```

Send: `./target/release/sudo-request --socket /tmp/sp-test.sock --no-privilege --print --reason "Poll TSan build (~4 min)" --plan-file tests/manual/log-corpus/05-poll-tsan-build.json`


## 06-check-mocked-under-tsan

Log entry 6, privileged (root). Reason: *Run check_mocked under TSan (data-free), set+restore sysctl*

Original:

```sh
bash -lc 'sysctl -w vm.mmap_rnd_bits=28 >/dev/null; echo "set to $(cat /proc/sys/vm/mmap_rnd_bits)"; sudo -H -u user bash -lc '\''cd ~/wt-130tsan; TSAN_OPTIONS="halt_on_error=0 exitcode=0" opam exec --switch=ocaml+tsan -- dune exec lib/proj/test_mock/check_mocked.exe > /tmp/tsan_mock.log 2>&1; echo user-exit $?'\''; sysctl -w vm.mmap_rnd_bits=32 >/dev/null; echo "restored to $(cat /proc/sys/vm/mmap_rnd_bits)"; echo '\''=== ThreadSanitizer warnings ==='\''; grep -c '\''WARNING: ThreadSanitizer'\'' /tmp/tsan_mock.log; echo '\''=== test result tail ==='\''; tail -4 /tmp/tsan_mock.log'
```

Send: `./target/release/sudo-request --socket /tmp/sp-test.sock --no-privilege --print --reason "Run check_mocked under TSan (data-free), set+restore sysctl" --plan-file tests/manual/log-corpus/06-check-mocked-under-tsan.json`

Notes: Root request. Only `sysctl` and the root-only `cat` keep `run-as root`; the nested `sudo -H -u` becomes `run-as user`. `$(cat …)` becomes its own stage, and `echo user-exit $?` is dropped (the per-stage exit array shows it). Non-allowlisted env vars go through a visible `env` stage, not `setenv`.


## 07-extract-race-headers

Log entry 7, unprivileged. Reason: *Extract TSan race headers + our-code frames*

Original:

```sh
bash -lc 'echo '\''=== distinct race header lines ==='\''; grep -nE '\''WARNING: ThreadSanitizer|SUMMARY: ThreadSanitizer'\'' /tmp/tsan_mock.log | head -40; echo; echo '\''=== any frame mentioning our code (proj.ml / Chain_ / Dproj / stubs)? ==='\''; grep -nE '\''proj|Chain_|abi_mock|requested_workers|shared_pool|iterators_active|reloading'\'' /tmp/tsan_mock.log | head -40'
```

Send: `./target/release/sudo-request --socket /tmp/sp-test.sock --no-privilege --print --reason "Extract TSan race headers + our-code frames" --plan-file tests/manual/log-corpus/07-extract-race-headers.json`


## 08-read-race-report

Log entry 8, unprivileged. Reason: *Read full TSan race report*

Original:

```sh
bash -lc 'sed -n '\''1,90p'\'' /tmp/tsan_mock.log'
```

Send: `./target/release/sudo-request --socket /tmp/sp-test.sock --no-privilege --print --reason "Read full TSan race report" --plan-file tests/manual/log-corpus/08-read-race-report.json`

Notes: The `bash -lc` wrapper hid a single command; the plan is one `exec`.


## 09-launch-concurrency-bg

Log entry 9, privileged (root). Reason: *Launch concurrency suite under TSan (background), sysctl=28*

Original:

```sh
bash -lc 'printf '\''called_from_lib:libproj\ncalled_from_lib:librocksdb\ncalled_from_lib:libboost\nrace:Saturn\nrace:Domainslib\n'\'' > /tmp/tsan.supp; chmod 644 /tmp/tsan.supp; sysctl -w vm.mmap_rnd_bits=28 >/dev/null; echo "mmap_rnd_bits=$(cat /proc/sys/vm/mmap_rnd_bits)"; sudo -H -u user bash -lc '\''cd ~/wt-130tsan; export PROJ_CONF=/mnt/data/proj.conf; nohup bash -c "TSAN_OPTIONS=\"suppressions=/tmp/tsan.supp halt_on_error=0 exitcode=0 history_size=4\" opam exec --switch=ocaml+tsan -- dune exec lib/proj/test/concurrency.exe > /tmp/tsan_conc.log 2>&1; echo CONC_DONE >> /tmp/tsan_conc.log" >/dev/null 2>&1 & echo launched-conc-pid $!'\'''
```

Send: `./target/release/sudo-request --socket /tmp/sp-test.sock --no-privilege --print --reason "Launch concurrency suite under TSan (background), sysctl=28" --plan-file tests/manual/log-corpus/09-launch-concurrency-bg.json`

Notes: Root request mixing structured stages with one opaque `shell` (the background launch) under `run-as user`. `printf` keeps the two-character `\n` escapes: a real newline in an argv is rejected.


## 10-poll-concurrency-a

Log entry 10, unprivileged. Reason: *Poll concurrency TSan run (~4 min)*

Original:

```sh
bash -lc 'sleep 250; echo '\''=== done? ==='\''; grep -c CONC_DONE /tmp/tsan_conc.log 2>/dev/null; echo '\''=== tsan warnings so far ==='\''; grep -c '\''WARNING: ThreadSanitizer'\'' /tmp/tsan_conc.log 2>/dev/null; echo '\''=== tail ==='\''; tail -8 /tmp/tsan_conc.log 2>/dev/null; echo '\''=== proc alive? ==='\''; pgrep -af concurrency.exe | grep -v pgrep | head -1 || echo '\''not running'\'''
```

Send: `./target/release/sudo-request --socket /tmp/sp-test.sock --no-privilege --print --reason "Poll concurrency TSan run (~4 min)" --plan-file tests/manual/log-corpus/10-poll-concurrency-a.json`


## 11-poll-concurrency-b

Log entry 11, unprivileged. Reason: *Poll concurrency TSan run (~4 min)*

Original:

```sh
bash -lc 'sleep 250; echo '\''=== done? ==='\''; grep -c CONC_DONE /tmp/tsan_conc.log 2>/dev/null; echo '\''=== tsan warnings ==='\''; grep -c '\''WARNING: ThreadSanitizer'\'' /tmp/tsan_conc.log 2>/dev/null; echo '\''=== tail ==='\''; tail -10 /tmp/tsan_conc.log 2>/dev/null; echo '\''=== proc alive? ==='\''; pgrep -af concurrency.exe | grep -v pgrep | head -1 || echo '\''not running'\'''
```

Send: `./target/release/sudo-request --socket /tmp/sp-test.sock --no-privilege --print --reason "Poll concurrency TSan run (~4 min)" --plan-file tests/manual/log-corpus/11-poll-concurrency-b.json`


## 12-poll-concurrency-retry

Log entry 12, unprivileged. Reason: *Poll concurrency TSan run (retry)*

Original:

```sh
bash -lc 'echo '\''=== done? ==='\''; grep -c CONC_DONE /tmp/tsan_conc.log 2>/dev/null; echo '\''=== tsan warnings ==='\''; grep -c '\''WARNING: ThreadSanitizer'\'' /tmp/tsan_conc.log 2>/dev/null; echo '\''=== tail ==='\''; tail -10 /tmp/tsan_conc.log 2>/dev/null; echo '\''=== proc alive? ==='\''; pgrep -af concurrency.exe | grep -v pgrep | head -1 || echo '\''not running'\'''
```

Send: `./target/release/sudo-request --socket /tmp/sp-test.sock --no-privilege --print --reason "Poll concurrency TSan run (retry)" --plan-file tests/manual/log-corpus/12-poll-concurrency-retry.json`


## 13-final-concurrency-restore-sysctl

Log entry 13, privileged (root). Reason: *Read final concurrency TSan result + restore sysctl=32*

Original:

```sh
bash -lc 'echo '\''=== CONC_DONE? ==='\''; grep -c CONC_DONE /tmp/tsan_conc.log 2>/dev/null; echo '\''=== total TSan warnings ==='\''; grep -c '\''WARNING: ThreadSanitizer'\'' /tmp/tsan_conc.log 2>/dev/null; echo '\''=== SUMMARY lines (race signatures) ==='\''; grep -E '\''SUMMARY: ThreadSanitizer|reported .* warnings|Test (Success|Fail)|tests run'\'' /tmp/tsan_conc.log 2>/dev/null | tail -8; echo '\''=== proc still alive? ==='\''; pgrep -af concurrency.exe | grep -v pgrep | head -1 || echo '\''not running'\''; echo '\''=== RESTORE sysctl ==='\''; sysctl -w vm.mmap_rnd_bits=32 >/dev/null; echo "mmap_rnd_bits now = $(cat /proc/sys/vm/mmap_rnd_bits)"'
```

Send: `./target/release/sudo-request --socket /tmp/sp-test.sock --no-privilege --print --reason "Read final concurrency TSan result + restore sysctl=32" --plan-file tests/manual/log-corpus/13-final-concurrency-restore-sysctl.json`

Notes: Root request where only the last two privileged stages need root.


## 14-stop-concurrency-run

Log entry 14, unprivileged. Reason: *Stop lingering concurrency run, capture progress*

Original:

```sh
bash -lc 'pkill -f concurrency.exe 2>/dev/null; pkill -f '\''dune exec lib/proj/test/concurrency'\'' 2>/dev/null; sleep 2; echo '\''=== killed; procs now ==='\''; pgrep -af concurrency.exe | grep -v pgrep || echo '\''none'\''; echo '\''=== how far did TSan concurrency get (tests OK + any warnings) ==='\''; grep -cE '\''WARNING: ThreadSanitizer'\'' /tmp/tsan_conc.log; echo '\''OK tests:'\''; grep -c '\''\[OK\]'\'' /tmp/tsan_conc.log; echo '\''=== tail ==='\''; tail -8 /tmp/tsan_conc.log'
```

Send: `./target/release/sudo-request --socket /tmp/sp-test.sock --no-privilege --print --reason "Stop lingering concurrency run, capture progress" --plan-file tests/manual/log-corpus/14-stop-concurrency-run.json`


## 15-recheck-concurrency

Log entry 15, unprivileged. Reason: *Recheck concurrency proc + log + sysctl*

Original:

```sh
bash -lc 'pgrep -af concurrency.exe | grep -v pgrep || echo '\''no concurrency proc'\''; echo '\''=== warnings ==='\''; grep -cE '\''WARNING: ThreadSanitizer'\'' /tmp/tsan_conc.log 2>/dev/null; echo '\''=== OK count ==='\''; grep -c OK /tmp/tsan_conc.log 2>/dev/null; echo '\''=== tail ==='\''; tail -6 /tmp/tsan_conc.log 2>/dev/null; echo '\''=== mmap_rnd_bits ==='\''; cat /proc/sys/vm/mmap_rnd_bits 2>/dev/null || echo '\''perm-denied(ok,root-only read)'\'''
```

Send: `./target/release/sudo-request --socket /tmp/sp-test.sock --no-privilege --print --reason "Recheck concurrency proc + log + sysctl" --plan-file tests/manual/log-corpus/15-recheck-concurrency.json`


## 16-cleanup-tsan-worktree

Log entry 16, unprivileged. Reason: *Clean up bench worktree + staging ref, keep tsan switch*

Original:

```sh
bash -lc 'cd ~/proj-ocaml; git worktree remove --force ~/wt-130tsan 2>&1; git branch -D _stage_130review 2>&1; echo '\''=== worktrees ==='\''; git worktree list; echo '\''=== tsan switch kept? ==='\''; opam switch list -s 2>/dev/null | grep tsan && echo '\''(ocaml+tsan switch retained for reuse)'\'''
```

Send: `./target/release/sudo-request --socket /tmp/sp-test.sock --no-privilege --print --reason "Clean up bench worktree + staging ref, keep tsan switch" --plan-file tests/manual/log-corpus/16-cleanup-tsan-worktree.json`

Notes: `cd dir; …` becomes a `chdir` around the whole sequence.


## 17-launch-g6-gcstress-bg

Log entry 17, unprivileged. Reason: *Build + run G6 test under GC stress (background)*

Original:

```sh
bash -lc 'cd ~; nohup bash -c '\''cd ~/proj-ocaml && git worktree add -f ~/wt-130g6 _stage_130g6 && cd ~/wt-130g6 && make -C abi clean >/dev/null 2>&1; make abi >/tmp/g6_build.log 2>&1 && opam exec -- make lib >>/tmp/g6_build.log 2>&1 && PROJ_CONF=/mnt/data/proj.conf OCAMLRUNPARAM="s=131072,o=20" MALLOC_PERTURB_=170 opam exec -- dune exec lib/proj/test/concurrency.exe -- test "Multi-domain stress" 1 >/tmp/g6_gcstress.log 2>&1; echo G6_GCSTRESS_DONE exit=$? >> /tmp/g6_gcstress.log'\'' >/dev/null 2>&1 & echo launched-g6-gcstress-pid $!'
```

Send: `./target/release/sudo-request --socket /tmp/sp-test.sock --no-privilege --print --reason "Build + run G6 test under GC stress (background)" --plan-file tests/manual/log-corpus/17-launch-g6-gcstress-bg.json`

Notes: Background launch, kept as opaque `shell`. Log entry 19 is an exact duplicate of this one and has no separate plan.


## 18-check-g6-state

Log entry 18, unprivileged. Reason: *Check G6 GC-stress job state*

Original:

```sh
bash -lc 'echo '\''=== build log ==='\''; tail -3 /tmp/g6_build.log 2>/dev/null || echo '\''no build log yet'\''; echo '\''=== gcstress log ==='\''; tail -5 /tmp/g6_gcstress.log 2>/dev/null || echo '\''no gcstress log yet'\''; echo '\''=== procs ==='\''; pgrep -af '\''make abi|dune|concurrency.exe|ocamlopt'\'' | grep -v pgrep | head -3 || echo '\''no build/run procs'\'''
```

Send: `./target/release/sudo-request --socket /tmp/sp-test.sock --no-privilege --print --reason "Check G6 GC-stress job state" --plan-file tests/manual/log-corpus/18-check-g6-state.json`


## 19-poll-g6-gcstress

Log entry 20, unprivileged. Reason: *Poll G6 GC-stress run (~3 min)*

Original:

```sh
bash -lc 'sleep 200; echo '\''=== build tail ==='\''; tail -3 /tmp/g6_build.log 2>/dev/null; echo '\''=== GCSTRESS result ==='\''; grep -c G6_GCSTRESS_DONE /tmp/g6_gcstress.log 2>/dev/null; cat /tmp/g6_gcstress.log 2>/dev/null | tail -20'
```

Send: `./target/release/sudo-request --socket /tmp/sp-test.sock --no-privilege --print --reason "Poll G6 GC-stress run (~3 min)" --plan-file tests/manual/log-corpus/19-poll-g6-gcstress.json`


## 20-build-g6-tsan-bg

Log entry 21, unprivileged. Reason: *Build G6 test under ocaml+tsan switch (background)*

Original:

```sh
bash -lc 'cd ~; nohup bash -c '\''cd ~/proj-ocaml && git worktree add -f ~/wt-130g6-tsan _stage_130g6 && cd ~/wt-130g6-tsan && make -C abi clean >/dev/null 2>&1; make abi >/tmp/g6tsan_build.log 2>&1 && opam exec --switch=ocaml+tsan -- dune build lib/proj/test/concurrency.exe >>/tmp/g6tsan_build.log 2>&1; echo G6TSAN_BUILD_DONE exit=$? >> /tmp/g6tsan_build.log'\'' >/dev/null 2>&1 & echo launched-g6tsan-build-pid $!'
```

Send: `./target/release/sudo-request --socket /tmp/sp-test.sock --no-privilege --print --reason "Build G6 test under ocaml+tsan switch (background)" --plan-file tests/manual/log-corpus/20-build-g6-tsan-bg.json`

Notes: Background launch, kept as opaque `shell`.


## 21-poll-g6-tsan-build

Log entry 22, unprivileged. Reason: *Poll TSan build of G6 test (~3 min)*

Original:

```sh
bash -lc 'sleep 180; echo '\''=== tsan build done? ==='\''; grep G6TSAN_BUILD_DONE /tmp/g6tsan_build.log 2>/dev/null || echo '\''not yet'\''; echo '\''=== build tail ==='\''; tail -4 /tmp/g6tsan_build.log 2>/dev/null; echo '\''=== exe present? ==='\''; ls -la ~/wt-130g6-tsan/_build/default/lib/proj/test/concurrency.exe 2>&1 | tail -1'
```

Send: `./target/release/sudo-request --socket /tmp/sp-test.sock --no-privilege --print --reason "Poll TSan build of G6 test (~3 min)" --plan-file tests/manual/log-corpus/21-poll-g6-tsan-build.json`


## 22-run-g6-under-tsan

Log entry 23, privileged (root). Reason: *Run G6 test under TSan, set+restore sysctl*

Original:

```sh
bash -lc 'printf '\''called_from_lib:libproj\ncalled_from_lib:librocksdb\ncalled_from_lib:libboost\nrace:Saturn\nrace:Domainslib\n'\'' > /tmp/tsan.supp; chmod 644 /tmp/tsan.supp; sysctl -w vm.mmap_rnd_bits=28 >/dev/null; echo "mmap_rnd_bits=$(cat /proc/sys/vm/mmap_rnd_bits)"; sudo -H -u user bash -lc '\''cd ~/wt-130g6-tsan; PROJ_CONF=/mnt/data/proj.conf TSAN_OPTIONS="suppressions=/tmp/tsan.supp halt_on_error=0 exitcode=0 history_size=4" opam exec --switch=ocaml+tsan -- dune exec lib/proj/test/concurrency.exe -- test "Multi-domain stress" 1 > /tmp/g6_tsan.log 2>&1; echo user-exit $?'\''; sysctl -w vm.mmap_rnd_bits=32 >/dev/null; echo "restored to $(cat /proc/sys/vm/mmap_rnd_bits)"; echo '\''=== ThreadSanitizer warnings (non-suppressed) ==='\''; grep -c '\''WARNING: ThreadSanitizer'\'' /tmp/g6_tsan.log; echo '\''=== result tail ==='\''; tail -12 /tmp/g6_tsan.log'
```

Send: `./target/release/sudo-request --socket /tmp/sp-test.sock --no-privilege --print --reason "Run G6 test under TSan, set+restore sysctl" --plan-file tests/manual/log-corpus/22-run-g6-under-tsan.json`

Notes: Root request, same shape as 06 plus the suppressions file.


## 23-cleanup-g6-worktrees

Log entry 24, unprivileged. Reason: *Clean up G6 worktrees + ref on bench*

Original:

```sh
bash -lc 'cd ~/proj-ocaml; git worktree remove --force ~/wt-130g6 2>&1; git worktree remove --force ~/wt-130g6-tsan 2>&1; git branch -D _stage_130g6 2>&1; echo '\''=== worktrees ==='\''; git worktree list; echo '\''=== tsan switch ==='\''; opam switch list -s 2>/dev/null | grep tsan && echo '\''(kept)'\''; echo '\''=== mmap_rnd_bits (should be root-only / restored) ==='\''; cat /proc/sys/vm/mmap_rnd_bits 2>&1 || echo '\''root-only read = restored'\'''
```

Send: `./target/release/sudo-request --socket /tmp/sp-test.sock --no-privilege --print --reason "Clean up G6 worktrees + ref on bench" --plan-file tests/manual/log-corpus/23-cleanup-g6-worktrees.json`

