---
description: Run the builder↔checker fix loop until the gate is green, with stop rules that prevent token burn and faked passes
argument-hint: "[task description] [--max N] [--strict]"
allowed-tools: Task, Bash, Read, Grep, Glob
---

Orchestrate the builder and checker agents in a loop until the compliance gate
is green or a stop rule fires.

Task: $ARGUMENTS

You are the orchestrator. You do not write code and you do not run the gate
yourself — you dispatch the two subagents and enforce the stop rules. The
whole value of this command is the stop rules; a loop without them burns
tokens and eventually fakes a pass.

## Configuration

Parse from `$ARGUMENTS`:
- `--max N` — maximum cycles. **Default 5.**
- `--strict` — pass `--strict` to the gate so skipped checks count as failures.
  Use when every tool is installed and you want true full coverage.

Everything else in `$ARGUMENTS` is the task description.

## Setup — establish the baseline first

Before any building, dispatch **checker** once to capture the starting state.
Record the status of every check id. This baseline is what makes regression
detection possible: without it you cannot tell "was green, now red" from
"still red", and that distinction is the entire second stop rule.

If the task is to fix existing failures and the baseline is already
`all_green: true` with zero skips, say so and stop — there is nothing to do.

If the baseline has failures, that is the starting red set. Note it.

## The loop

For each cycle from 1 to `--max`:

1. **Dispatch `builder`** with:
   - the task description,
   - the exact failures from the most recent checker report (check id, the
     concrete error, file/address),
   - the explicit instruction not to touch checks currently passing.

2. **Dispatch `checker`** (fresh — do not reuse the builder's context).

3. **Compare the new report against the baseline and the previous cycle**,
   then apply the stop rules below.

Keep a running table across cycles: check id → status per cycle. Show it in
your final summary. It is how the human sees whether the loop was converging
or thrashing.

## Stop rules — enforce all four

**1. Green.** Every check passes and nothing skipped (`all_green: true`).
Stop, report success.

**2. Regression — halt immediately.** Any check that was `pass` in the
baseline or a previous cycle is now `fail`. Stop **at once**; do not spend the
remaining cycles. A fix that trades one green for another is not progress, and
a loop allowed to continue through regressions will oscillate between two
broken states forever. Report exactly which check regressed, in which cycle,
and what change caused it.

**3. Cycle limit.** `--max` cycles used and still red. Stop. Do not extend the
budget on your own initiative. Escalate with:
   - which checks are still failing,
   - the specific error for each,
   - what the builder tried each cycle,
   - your read on why it is stuck.

**4. No progress.** The failing set is identical for two consecutive cycles
and the builder's changes did not alter it. Stop early rather than spending
the remaining budget — the builder is guessing. Report it as stuck.

## Skips are not passes

`all_green` is false whenever any check skipped. Never declare success on a
run with skips. In the final report list skipped checks under their own
heading as **unverified**, and name the tool that would need installing:

```
UNVERIFIED — these checks did not run
  checkov   — not installed (brew install checkov)
  tflint    — not installed (brew install tflint)
```

If four of ten checks skipped, the honest summary is "6 passed, 4 never ran",
never "all checks passed".

## Watch for faked passes

Before declaring green, inspect what the builder actually changed. If a check
went from fail to pass and the diff touched any of these, treat it as a
suspected faked pass, do not report green, and escalate to the human:

- `.checkov.yaml`, `.trivyignore`, `.gitleaks.toml` — new skip/ignore entries
- inline `# checkov:skip=` or `#tfsec:ignore:` comments
- a rule removed or loosened in `policies/`
- a control entry deleted or narrowed in `controls/controls.yaml`
- a hand-edit to `CONTROLS.md` (it is generated)

A legitimate exception is possible, but it is the human's call, not the loop's.

## Final report

Always end with:

```
LOOP RESULT — <green | regression | limit | stuck>
  cycles used: <n>/<max>
  checks: <pass> passed, <fail> failed, <skip> unverified

<the per-cycle table>

<failing checks with their concrete errors, if any>
<what a human needs to decide, if the loop escalated>
```

Do not commit anything. Leave the working tree for the human to review.
