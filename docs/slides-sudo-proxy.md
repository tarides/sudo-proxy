---
marp: true
theme: default
paginate: true
title: "sudo-proxy: a human keypress between an AI and root"
---

<!--
30-minute talk. ~24 slides. Pacing guide:
  - Part 1  The problem        (slides 2-6)   ~6 min
  - Part 2  Context & rules    (slides 7-10)  ~6 min
  - Part 3  The architecture   (slides 11-17) ~9 min
  - Part 4  Proving it         (slides 18-23) ~7 min
  - Close                      (slide 24)     ~2 min
Speaker notes are in HTML comments under each slide.
-->

# sudo-proxy

### A human keypress between an AI and `root`

A privileged-command proxy for the age of AI agents

<small>Tarides · MIT · v1.0.0</small>

<!--
One-line pitch: when you let an AI agent run commands on your machine, sudo-proxy
makes sure a human deliberately approves every privileged one — even commands the
agent was tricked into requesting. 30 minutes: the problem, the rules of the game,
how the job shapes the design, and how we convinced ourselves it actually holds.
-->

---

## The setup: AI agents now *do things*

- Coding assistants no longer just suggest — they **run commands** on your machine.
- Real work needs **privilege**: install a package, edit `/etc`, restart a service.
- The agent will happily try. The question is **who says yes**.

> An AI agent needs to act as an administrator — but you cannot trust it to act
> *unsupervised*.

<!--
Set the scene. The audience knows agents write code. The new thing is that agents
execute. And the moment execution meets privilege, you have a trust problem that
didn't exist when the tool only printed suggestions.
-->

---

## Why "just let it run sudo" is the wrong answer

Two existing options, both bad:

1. **Block all privilege.** The agent is useless for real admin work.
2. **Let it escalate freely.** One bad instruction = root on your box.

And agents *can* be fed bad instructions — **prompt injection** is the
#1 risk for LLM applications (OWASP). A web page, a file, a git commit message
can carry hidden commands the model dutifully obeys.

<!--
Frame the dilemma sharply. The interesting failure isn't "the AI is evil." It's
"the AI is gullible." Prompt injection: text from anywhere the model reads can
contain instructions. So you cannot treat the agent's request as trustworthy,
ever — not because the model is malicious, but because its input is attacker-
controllable.
-->

---

## The gap sudo-proxy fills

> sudo-proxy fills the gap when a model needs to install packages, edit system
> files, manage services, or run any other command — **with the human always in
> the loop, even when the agent runs with `--dangerously-skip-permissions`.**

The bet: keep the agent powerful, but make **one human keypress** non-negotiable
on every privileged command.

<!--
This is the thesis slide. Notice the "--dangerously-skip-permissions" detail: even
if the operator has turned off the agent's own guardrails, sudo-proxy's gate is a
separate process the agent cannot switch off. That separation is the whole idea,
and it'll come back when we talk architecture.
-->

---

## The one invariant

Everything in the project reduces to a single sentence:

# “Nothing privileged runs without a human deliberately approving the exact command shown.”

Keep this sentence in mind. Every design choice and every proof exists to defend it.

<!--
Slow down here. Read it word by word. "Nothing privileged runs" — the gate is
mandatory. "a human deliberately" — a real person, a real action, not a default.
"the exact command shown" — what you see is what runs; no bait-and-switch. This is
called G1 in the docs and it's the spine of the entire talk. If they remember one
slide, it's this one.
-->

---

## Who it's for

- An **operator** running an AI agent against **their own machine** — local, or
  remote over SSH.
- Philosophy: **consent-first** — *every call is a keypress*.
- Not a fleet/RBAC governance tool for shared services (that's *policy-first*,
  a different product).

| | Bash tool | sudo-proxy |
|---|---|---|
| Privilege escalation | impossible | sudo + approval |
| Human review | none — runs immediately | **Y/N on every command** |
| Remote hosts | unsupported | SSH tunnel |
| Environment | inherits your shell | sanitized allowlist |

<!--
Scope it honestly so nobody asks "is this Teleport?" No. It's deliberately small:
one operator, their own boxes, consent on every action. The table is the README's
own "why not just use the Bash tool" framing — it's the clearest value statement.
-->

---

## Context: where it lives

sudo-proxy plugs into the **Model Context Protocol (MCP)** — the standard way
agents like Claude Code get tools.

```
AI model ──► sudo-proxy-mcp ──► Unix socket ──► sudo-proxy ──► TUI Y/N ──► sudo
             (the shim)                         (the daemon)
                            local socket, or SSH tunnel to a remote host
```

The model is handed a tool called `execute`. Calling it *requests* a command.
A human pressing `y` is what makes it *happen*.

<!--
Introduce the two halves we'll dissect later: a thin "shim" the model talks to,
and a "daemon" that does the security-critical work. Note that requesting and
executing are deliberately split by a human keypress. Don't go deep yet — this is
the map, we tour it in Part 3.
-->

---

## The threat model, in plain terms

We assume **three kinds of attacker**:

- **A1 — the agent itself**, or whoever is injecting instructions into it.
  Controls the command, its arguments, its environment, the description shown.
- **A2 — another program running as you.** It can talk to the daemon's socket
  directly, skipping the agent entirely.
- **A3 — a network attacker** on the path to a remote host.

The design must hold even if the agent is **fully adversarial**.

<!--
Naming the adversaries makes the rest concrete. A2 is the subtle one and it drives
a key architectural decision: we can't put security checks in the shim, because an
attacker can just bypass the shim and hit the socket. So all real checks must live
in the daemon. Hold that thought.
-->

---

## Constraints we set ourselves

- **Minimal dependencies.** Core is a handful of crates; signal handling and
  peer checks use raw OS calls, not libraries. Smaller code = smaller attack
  surface = *provable*.
- **Single static binary** you can `scp` to a host. No runtime, no installer.
- **No policy engine — on purpose.** Every call is an interactive human decision.
  We *rejected* auth-caching (e.g. polkit) because silent execution defeats the
  whole point.
- **Most-restrictive defaults.** Forget a field? You get the *more* secure
  behavior, not less.

<!--
These aren't arbitrary. "Minimal deps" later pays off: the formal-verification
rungs are only tractable because the code is small and dependency-light. "No policy
engine" is a values statement — we are not building convenience that erodes consent.
"Most-restrictive defaults": on the wire, "privileged" defaults to true; the prompt
defaults to No; the timeout defaults to deny. Safe-by-omission.
-->

---

## Requirements that follow

From "the agent is untrusted" and "consent on every command," we *must* have:

1. A human approval step the agent **cannot reach or fake**.
2. The approval must show the **exact command** that will run — no substitution,
   no spoofing.
3. Security checks that **can't be bypassed** by going around the agent.
4. The daemon itself runs **unprivileged** — it borrows root per-command via
   `sudo`, it doesn't *hold* root.

These four requirements basically *dictate* the architecture. Let's see how.

<!--
This is the hinge of the talk: the requirements aren't a wishlist, they're forced
by the role. The next part shows each requirement turning into a concrete piece of
the design. "The role determines the architecture" — that's the line the brief
asked for, and slides 11-17 deliver on it.
-->

---

# How the *role* shapes the *architecture*

sudo-proxy's job is to be a **trusted gate** between something untrusted and root.

That single fact forces nearly every design decision.

<!--
Section divider. Tell them: for the next nine minutes, every architectural choice
will be traced back to "because it's a security gate." This is the heart of the
brief.
-->

---

## Decision 1 — Split the shim from the daemon

Two separate programs:

- **`sudo-proxy-mcp`** (the shim) — talks to the model. **Untrusted. Holds no power.**
- **`sudo-proxy`** (the daemon) — listens on a socket, does *all* the checking,
  owns the approval prompt.

**Why:** attacker A2 can bypass the shim and hit the socket directly. So no
security check may live in the shim — it would be optional. **Every gate lives in
the daemon**, where it's unavoidable.

<!--
This is the cleanest example of role-driven design. A naive build would validate in
the shim (it's right there next to the model). But because a same-user process can
skip the shim, shim-side checks are theater. So the trust boundary is the socket,
and the daemon re-validates everything no matter who is calling.
-->

---

## Decision 2 — Approve on a channel the AI can't touch

The Y/N prompt is shown on **`/dev/tty`** — the physical terminal — **not** through
the model's connection.

- The model can *ask*. It **cannot answer its own question**.
- The keypress comes from a human at a real keyboard, out of band.

**Why:** requirement #1 — the approval must be unreachable and unfakeable by the
agent. A separate channel is the only way.

<!--
Plain-language version: the question and the answer travel on different wires. The
agent is on one wire; the human's keyboard is on another. The agent literally has
no path to the "yes." This is what makes "human in the loop" real rather than
decorative.
-->

---

## Decision 3 — Never build a shell command

The command travels as a **structured list** — program, then arguments — and is
run *directly*. There is **no shell** on the privileged path.

- A classic attack: smuggle `; rm -rf /` inside an argument. With a shell, that's
  a second command. Here, it's just a literal string passed to one program.
- No prefix-matching, no wildcard expansion, **nothing to trick**.

**Why:** requirement #2 — what's approved is *exactly* what runs.

<!--
The "structured argv, never a shell string" point. Audiences get this with the
rm -rf example. There's no interpreter sitting between approval and execution to
reinterpret the characters. The pipeline feature (a|b) is modeled as a list of
stages, still no shell on the default sudo path.
-->

---

## Decision 4 — Make the prompt impossible to spoof

The human must trust what's on screen. So before displaying anything, the daemon
**rejects** any field containing:

- control characters, invisible/zero-width characters,
- **bidirectional-override** characters (the trick that makes text display in a
  different order than it runs).

It also shows the program's **real resolved path** (following symlinks), and caps
the displayed length so a giant argument can't push `[y/N]` off-screen.

**Why:** "approve the exact command *shown*" is only meaningful if the screen
can't lie.

<!--
This is the display-integrity control, and it's the most underappreciated. The bidi
trick is the famous "Trojan Source" class: text that reads left-to-right as
"safe-command" but executes as something else. We refuse those bytes in *every*
displayed field — argv, environment, the human-readable reason, all of it. The
"every field" consistency was itself a fixed audit finding.
-->

---

## Decision 5 — Don't trust the environment either

Environment variables can escalate privilege silently (`LD_PRELOAD`, `PATH`, …).
So the daemon uses a tiny **allowlist** (`LANG`, `TZ`, `HOME`, a few more).

- Anything dangerous is an **explicit error** — *nothing is silently stripped*.
- Requested `SSH_AUTH_SOCK` is refused; agent-forwarding is a separate, deliberate,
  unprivileged-only option.

Plus replay protection: every request has a unique id and a timestamp, and the
daemon **rejects duplicates and stale requests** so a captured "yes" can't be
re-sent.

<!--
Two things: env hardening (an allowlist that errors loudly rather than failing
silent — operators should know when something was rejected), and freshness/replay
(a one-time id plus a 60-second freshness window). Replay matters because otherwise
a previously-approved command could be replayed by A2 or A3. Notice the theme:
loud refusal over silent fixing.
-->

---

## Decision 6 — Borrow root, don't hold it

The daemon runs as **you**, the normal user. It escalates **per command** via
`sudo`, then drops back.

- It doesn't sit there owning root waiting to be abused.
- No policy or request field can *ever* pre-grant the privileged path — even an
  internal "always approve" signal is **treated as a denial** for privileged
  commands.

**Why:** least privilege. The blast radius of the daemon itself is bounded.

<!--
The privileged gate is structurally independent of any "remember this" convenience.
There is an "approve always" option, but it ONLY affects unprivileged commands and
ONLY flips on a real keypress. For anything that touches root, there is no
remembering, ever. We later prove this — it's one of the formal properties.
-->

---

## The piece that ties it together: a "validated" type

A command can only reach execution if it has passed validation — and we make that
a **compile-time guarantee**, not a hopeful runtime check.

- There's a special wrapper type. The *only* way to create it is to run the
  validator.
- The execution and prompt functions accept **only** that wrapper.

> "Reaching execution with an unvalidated request is a **compile error**, not a
> runtime gap."

<!--
For a technical audience: the typestate pattern. ValidatedRequest wraps a private
Request; the only constructor is validate(); exec_* and the prompt take only
&ValidatedRequest. So "someone added a code path that forgot to validate" can't
compile. For a non-technical audience: we wired the rules into the building's
structure so a wall can't be left out by accident. This bridges us into Part 4 —
because "we believe it's correct" isn't good enough for a security gate.
-->

---

# Proving it actually holds

A security gate that's *probably* correct isn't a security gate.

So: a **ladder of assurance** — each rung re-proves the *same* invariant with
*stronger evidence*.

<!--
Section divider for the verification story. The key message: we didn't just write
tests. We built a graduated program where the same one-sentence claim (G1) is
defended over and over, each time with harder evidence. Nothing is thrown away as
we climb.
-->

---

## The ladder — borrow the rigor, not the bureaucracy

We borrow the **Common Criteria** assurance ladder (the EAL 1→7 scale) — *without
pursuing certification* — and hold it together with a written **assurance case**
(one goal, decomposed, each leaf citing its evidence).

| Rung | What | Status |
|---|---|---|
| 0 | Threat model (STRIDE + attack trees) | ✅ |
| 1 | Code review + static analysis, in CI | ✅ |
| 2 | Property tests as written specifications | ✅ |
| 3 | Automated proofs (Kani) + the validated-type | ✅ |
| 4 | Protocol proofs (TLA+ / ProVerif) | ✅ |
| 5 | Deductive proofs of the core | planned |
| 6 | Full machine-checked refinement | aspirational |

<!--
The crucial design property: "every rung re-proves the same top-level claim with
stronger evidence, so partial progress is always useful and nothing is wasted." A
leaf that today cites a fuzz test tomorrow cites a machine-checked proof — and the
surrounding argument is unchanged. That's why it's a ladder, not a pile.
-->

---

## Rungs 0–2: model the threat, gate the build, write specs

- **Rung 0 — Threat model.** Walk every trust boundary (STRIDE) and build an
  *attack tree* whose root is "a root command runs that the human didn't approve."
  This tells us **where the higher rungs need to be load-bearing**.
- **Rung 1 — Static analysis in CI.** Lint, dependency-audit, license/ban checks
  run on every push. A regression that drops a safety check now **fails the build**
  instead of waiting for the next manual audit.
- **Rung 2 — Property tests as specs.** Five named properties read like spec
  clauses, e.g. *"an approved request has no dangerous character in any displayed
  field"* and *"privileged ⇒ a keypress happened."*

<!--
Rung 0 is the compass — it's what told us the policy-flip risk and the SSH first-
contact risk were the load-bearing ones, so that's where we aimed TLA+ and ProVerif.
Rung 2's trick: the property tests are deliberately phrased as the proof obligations
the higher rungs will discharge. "The cheap bridge to formal methods."
-->

---

## Rung 3: from *sampling* to *proof*

**Kani** is a bounded model checker — where a test *samples* inputs, Kani *proves*
a property for **every** input in range.

Three proofs, aimed where attacker-controlled parsing bit us before:

- The freshness-timestamp math is **total and panic-free** over its entire input
  space — closing a real past integer-underflow bug, for *all* inputs, not samples.
- That math is **monotone** — an older timestamp can never be judged "fresher."
- The dangerous-character scanner **matches its spec, character by character.**

<!--
Plain version: we mathematically checked the arithmetic that decides "is this
request fresh enough" can never crash or wrap around, for every possible input —
not a million random ones, all of them. We aimed it precisely at the code that had
produced real bugs (#11/#14). And we keep the clock side-effect out of the proof by
isolating the pure arithmetic. There's a documented "negative control": break a
checked-multiply and the proof correctly goes red — proving the proof has teeth.
-->

---

## Rung 4: prove the *protocol*, not just the code

Two formal tools, two questions:

- **TLA+** models the approval state machine and checks, across *every* interleaving
  of attacker forgeries and human keypresses:
  - **no execution without a `y`**, **no replay runs twice**,
  - the "remember" flag **flips only on a real keypress**, and
  - **the privileged gate never even reads that flag.**
  - It also proved our retention window is *more* conservative than needed — and
    surfaced a **new** finding (uncapped far-future timestamps), now on the backlog.
- **ProVerif** models the SSH path against a network attacker.

<!--
TLA+ checks the *dance* between attacker and operator — temporal safety over a state
machine, which is exactly its home turf. Each property has negative-control
mutations that must break it. The honesty beat: the extended model didn't just
confirm the design, it FOUND a new gap (far-future timestamps stay fresh forever)
and we wrote it down rather than hid it. That's the program working as intended.
-->

---

## Rung 4: what ProVerif tells us about SSH

It models real SSH structure (host key + client key) against a network attacker,
and **derives** — not assumes — the answers:

- ✅ **Command authenticity holds even on first contact** — an eavesdropper still
  can't forge or alter a command (it rides on client authentication).
- ✅ **Separation theorem:** breaking the SSH channel **cannot fabricate an
  approval** — the local human gate is out of a network attacker's reach.
- ⚠️ **First-contact secrecy fails *if* the host isn't pinned** — so "pin the host
  key first" becomes an **explicit, load-bearing assumption**, not a hidden one.

<!--
The valuable result is the separation theorem: even a total SSH compromise can't
manufacture a "yes." That bounds the blast radius. The ⚠️ is the honesty: rather
than claim the channel is private, the model derives the exact condition under
which it isn't (an unpinned first connection lets an attacker substitute its own
host key) — turning a vague worry into a precise, documented dependency.
-->

---

## Why bother with all this?

Because the **assurance is matched to the criticality** — we climb the ladder
*exactly where the threat model says risk concentrates:*

- Attacker-controlled **arithmetic** → strongest automatic proof (Kani).
- The **policy-flip** risk → model-checked.
- The **SSH gap** → derived and bounded, with its assumption made explicit.
- Routine hygiene stays at Rung 1.

And every artifact ships a **scope statement** and **negative controls** —
honest about what's *proven* vs. *tested*, with documented mutations that must
break each proof.

<!--
The meta-point: we didn't formally verify everything uniformly (impossible and
wasteful). We spent rigor where the attack tree said it mattered. And the
intellectual-honesty discipline — every proof states what it does NOT cover, every
proof has teeth — is itself a design principle. Residuals are characterized, not
buried.
-->

---

## Takeaways

1. **The role makes the design.** "Be a trusted gate to root" forces the
   shim/daemon split, the out-of-band keypress, the no-shell exec, the spoof-proof
   prompt.
2. **One invariant, defended everywhere:** *nothing privileged runs without a human
   approving the exact command shown.*
3. **Assurance is a ladder, not a checkbox** — same claim, stronger evidence each
   rung, rigor aimed where the threat is.
4. **Honesty is a feature:** documented residuals and proofs with teeth beat
   silent confidence.

### Thank you — questions?

<!--
Land the plane on the brief's three asks: (1) problem & why, (2) how the role
determines the architecture, (3) the security evaluation effort and its role.
If asked "is this overkill for a small tool?" — the answer is: it's a tool whose
entire job is to be trusted with root, and it's small enough that this level of
proof is actually achievable. That combination is rare and it's the point.
-->
