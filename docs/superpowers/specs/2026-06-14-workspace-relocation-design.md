# Workspace relocation — design (Phase 1)

- **Date:** 2026-06-14
- **Status:** Approved design, pending implementation plan
- **Scope:** Phase 1 only — relocate the existing `pkcs11-check` repo into a new
  `pkcs11-check-ws` workspace, and relocate agent memory. **No content is split out
  of the framework repo in this phase.**

## Goal

Restructure local development so `pkcs11-check` becomes the inner of a two-repo layout:

- `pkcs11-check-ws/` — a **workspace** git repo for development docs, plans, findings,
  specs, and Docker test-target / pool tooling (and, in a later phase, most Docker test
  targets).
- `pkcs11-check-ws/pkcs11-check/` — the **test framework** itself, an independent git
  repo, eventually slimmed to 2–3 Docker test targets for simplicity.

Phase 1 establishes the layout and gets agent memory landing at the right key. The
content split (which targets/docs move where) is a **separate, later spec**.

## Non-goals (Phase 1)

- Moving any docs, plans, findings, or Docker targets out of `pkcs11-check/`.
- Creating a GitHub remote for the workspace repo.
- Changing anything inside the framework repo's own history, branches, or remote.

## Decisions (with rationale)

1. **Nested independent repos, no submodule.** The workspace is its own git repo; the
   inner `pkcs11-check/` is a normal standalone repo with its own `pkcs11-check.git`
   remote, branches, and worktrees. The workspace `.gitignore`s `/pkcs11-check/` so it
   never tracks or pins a commit.
   - *Rationale (user):* easier handling than submodules; always work against whatever
     branch/worktree is live inside `pkcs11-check/`, not a pinned commit.
   - *Contrast:* the sibling `pkcs11-proxy-ng-ws` uses a submodule; we deliberately do
     **not** replicate that here.

2. **Memory home = workspace root.** All current memory + session history is copied to
   the `…-pkcs11-check-ws` project key. Sessions are opened at the workspace root going
   forward; the inner repo's memory key stays empty (matches the proxy-ws precedent).

3. **Scope = relocation first, split later.** Low-risk, reversible move now; the content
   split gets its own brainstorm → spec → plan cycle.

## Verified preconditions (2026-06-14)

- No git submodules (`third_party/pkcs11-headers` is a plain directory).
- Single worktree (the main checkout); no registered linked worktrees → whole-tree move
  is safe (git internals are path-relative).
- `.venv` is **not** portable — console-script shebangs hardcode
  `/home/user/src/m/pkcs11-check/.venv/bin/python`; must rebuild with `uv sync`.
- Convention: `pkcs11-proxy-ng-ws` workspace repo default branch is `main`.
- Memory at old key is ~212K + 345 session transcripts; `…-pkcs11-check-ws` key does
  not yet exist.

## Target layout

```
/home/user/src/m/pkcs11-check-ws/            ← NEW workspace git repo (branch: main, local-only)
├── .gitignore                               ← ignores /pkcs11-check/, .venv, caches, artifacts, .worktrees
├── README.md                                ← full workspace orientation (content below)
├── CLAUDE.md                                ← workspace agent guide (real file; content below)
├── AGENTS.md  →  CLAUDE.md                  ← symlink (mirrors inner repo's AGENTS.md → CLAUDE.md)
└── pkcs11-check/                            ← the CURRENT repo, moved wholesale, untouched & independent
                                                (own .git, own pkcs11-check.git remote, branch `dev` preserved,
                                                 all tracked/untracked/ignored files intact)
```

## Execution runbook (ordered)

The repo move does not touch `~/.claude/`, so the current session stays stable throughout.

1. **Create workspace skeleton** (paths absolute):
   - `mkdir -p /home/user/src/m/pkcs11-check-ws`
   - `git -C /home/user/src/m/pkcs11-check-ws init -b main`
   - Write `.gitignore`, `README.md`, `CLAUDE.md` (contents below); create
     `AGENTS.md` as a symlink → `CLAUDE.md`.
   - `git -C /home/user/src/m/pkcs11-check-ws add -A && git -C … commit -m "chore: init pkcs11-check workspace"`
2. **Relocate memory (copy, then clean up later):**
   - `cp -a ~/.claude/projects/-home-user-src-m-pkcs11-check/. ~/.claude/projects/-home-user-src-m-pkcs11-check-ws/`
   - Leaves the old key intact for now (live session undisturbed); it is deleted only
     after the user confirms the new location works.
3. **Move the framework repo:**
   - `mv /home/user/src/m/pkcs11-check /home/user/src/m/pkcs11-check-ws/pkcs11-check`
     (atomic rename, same filesystem).
4. **Rebuild the venv** in the new location:
   - `rm -rf /home/user/src/m/pkcs11-check-ws/pkcs11-check/.venv`
   - `cd /home/user/src/m/pkcs11-check-ws/pkcs11-check && uv sync`
   - Optionally clear path-stale caches (`.mypy_cache .ruff_cache .pytest_cache`).
5. **Fix stray absolute references:** grep the moved tree for
   `/home/user/src/m/pkcs11-check` (now `…/pkcs11-check-ws/pkcs11-check`) and update any
   real references in scripts/docs. Expected to be few.

## Verification checklist

- `git -C …/pkcs11-check-ws/pkcs11-check status` → branch `dev`, same dirty WIP as before.
- `git -C …/pkcs11-check-ws/pkcs11-check remote -v` → `pkcs11-check.git` intact.
- `git -C …/pkcs11-check-ws status` → only the workspace skeleton tracked; `pkcs11-check/` ignored.
- `ls ~/.claude/projects/-home-user-src-m-pkcs11-check-ws/memory/` → all memory files + `MEMORY.md`.
- `cd …/pkcs11-check-ws/pkcs11-check && uv run pkcs11-check version` (or `--help`) succeeds (venv rebuilt).
- `readlink …/pkcs11-check-ws/AGENTS.md` → `CLAUDE.md`.

## Post-execution

- **User restarts Claude Code from `/home/user/src/m/pkcs11-check-ws`** — that's where
  memory now lives and where work continues.
- After the user confirms, delete the orphaned old key
  `~/.claude/projects/-home-user-src-m-pkcs11-check/`.

## Rollback

Reverse step 3 (`mv … back`), `uv sync`, and remove the new workspace dir + the copied
`…-pkcs11-check-ws` memory key. Nothing in the framework repo's git state was modified.

## Out of scope → next spec (Phase 2: content split)

- Decide which 2–3 Docker test targets remain in `pkcs11-check` (the rest move to the
  workspace).
- Migrate docs / plans / findings / specs and extra Docker targets up into the workspace
  repo; update cross-references, CI, and `docs/` pointers.

---

## File contents to create in the workspace

### `pkcs11-check-ws/README.md`

````markdown
# pkcs11-check-ws

Development **workspace** for the [`pkcs11-check`](pkcs11-check/) PKCS#11 test framework.

This repository holds the *development context* around the framework — design docs,
plans, findings, specs, and Docker test-target / pool tooling — while the framework
itself lives in a separate, independent git repo nested under [`pkcs11-check/`](pkcs11-check/).

## Why two repos

The framework (`pkcs11-check`) is a publishable, self-contained PKCS#11 conformance and
bug-finding suite. The day-to-day work around it — research notes, multi-step plans,
provider findings, and the Docker matrix that exercises a dozen+ PKCS#11 providers —
adds a lot of weight that does not belong in the shipped framework. Splitting them keeps
`pkcs11-check` simple (a test framework with a small number of Docker targets) and gives
the heavier development material its own home here.

## Repository layout

```
pkcs11-check-ws/                  ← this workspace repo (git, branch: main)
├── README.md                     ← you are here
├── CLAUDE.md / AGENTS.md         ← agent orientation for sessions opened at the workspace
└── pkcs11-check/                 ← the test framework — an INDEPENDENT git repo
                                     (remote: github.com/mingulov/pkcs11-check)
```

Planned (later phase): workspace-level `docs/`, `plans/`, `findings/`, and most Docker
test targets move up here, leaving `pkcs11-check` with only 2–3 Docker targets.

### How the two repos relate

- **Nested, independent, no submodule.** `pkcs11-check/` is a normal git repo you use
  directly — check out any branch, create worktrees, commit, push — exactly as before.
- The workspace repo **ignores** `pkcs11-check/` (see `.gitignore`); it never tracks or
  pins a commit of the framework. You always work against the *live* checkout inside it.
- To update the framework: `cd pkcs11-check && git …`. To update workspace material:
  work at the workspace root.

## Working here

- **Open Claude Code / agent sessions at the workspace root** (`pkcs11-check-ws/`).
  Agent memory for this project lives at the workspace key, so it is found here.
- **Run the framework:**
  ```bash
  cd pkcs11-check
  uv sync
  uv run pkcs11-check doctor --module /path/to/module.so --slot 0 --pin <pin>
  uv run pkcs11-check test   --module /path/to/module.so --slot 0 --pin <pin>
  ```
- **Docker provider matrix** (currently still under `pkcs11-check/docker/`):
  ```bash
  cd pkcs11-check/docker
  ./test-all.sh              # or test-parallel.sh / test_pool.py
  ```

## Status

- **Phase 1 (done):** framework relocated into this workspace; agent memory consolidated
  at the workspace key.
- **Phase 2 (planned):** split content — keep 2–3 Docker targets in `pkcs11-check`, move
  docs / plans / findings / remaining targets up into this workspace. Tracked in its own
  design spec.

## Pointers

- Framework overview & usage: [`pkcs11-check/README.md`](pkcs11-check/README.md)
- Framework architecture: [`pkcs11-check/docs/architecture.md`](pkcs11-check/docs/architecture.md)
- Framework agent rules: [`pkcs11-check/CLAUDE.md`](pkcs11-check/CLAUDE.md)
````

### `pkcs11-check-ws/CLAUDE.md`

````markdown
# pkcs11-check-ws — agent guide

This is the **workspace** wrapping the `pkcs11-check` PKCS#11 test framework. Read this
when a session is opened at the workspace root.

## Layout

- `pkcs11-check/` — the test framework, an **independent git repo** (remote
  `github.com/mingulov/pkcs11-check`). It is **gitignored** by this workspace and is
  **not** a submodule. Work against its live checkout (any branch / worktree).
- This workspace repo (branch `main`, local-only for now) holds development docs, plans,
  findings, specs, and Docker test-target / pool tooling.

## Rules

- **Never add `pkcs11-check/` to this workspace's git index.** It is a separate repo; it
  stays ignored. Commit framework changes from inside `pkcs11-check/`, workspace material
  from the workspace root.
- **Framework coding rules live in [`pkcs11-check/CLAUDE.md`](pkcs11-check/CLAUDE.md).**
  When working inside the framework, that file governs (test-classification model, error
  handling, git workflow — `dev` is the framework's development branch, never merge to
  `main` directly, etc.). Do not duplicate or contradict it here.
- **Memory** for this project lives at the workspace key
  (`~/.claude/projects/-home-user-src-m-pkcs11-check-ws/memory/`). Maintain it per the
  standard memory protocol.

## Two-repo split (in progress)

- Phase 1 (done): relocation + memory consolidation.
- Phase 2 (planned): keep 2–3 Docker targets in `pkcs11-check`; move docs / plans /
  findings / remaining Docker targets into this workspace. See the workspace-relocation
  and (forthcoming) content-split design specs.
````

### `pkcs11-check-ws/.gitignore`

```gitignore
# The framework is an independent, nested git repo — never tracked here.
/pkcs11-check/

# Workspace-local artifacts & caches
.venv/
__pycache__/
*.pyc
.worktrees/
/artifacts/
/artifacts*/
.mypy_cache/
.ruff_cache/
.pytest_cache/
.hypothesis/
.DS_Store
```

### `pkcs11-check-ws/AGENTS.md`

Symlink → `CLAUDE.md` (created with `ln -s CLAUDE.md AGENTS.md`).
