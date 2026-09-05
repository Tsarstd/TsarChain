# Agent Instructions & Workflow Rules

## Read first to understand the monorepo project architecture

- `.agents/skills/graffiti-protocol/SKILL.md` → Graffiti Protocol Main Skill & Code Style
- `docs/ARCHITECTURE.md` → TsarChain Architecture
- `docs/API.md` → API's documentation summary
   - `src/tsarchain/network/rpc/docs/MINER_RPC.MD` → Miner RPC Docs
   - `src/tsarchain/network/rpc/docs/STORAGE_RPC.MD` → Storage RPC Docs
   - `src/tsarchain/network/rpc/docs/USER_RPC.MD` → User RPC Docs
- `tsarcore_native\README.md` → Rust Native

## Where code lives

- `apps/` — Main apps (wallet, node, archivist & web backend)
- `src/archivist/` — Archivist Domain
- `src/tsarchain/` — Tsarchain (Network, Consensus, Graffiti, Node & Config)
- `src/kremlin/` — Kremlin Desktop Wallet
- `src/web/Backend/` — Web Backend
- `src/web/Frontend/` — Web Frontend
- `tsarcore_native/` — Rust Native
- `tests/` & `tsarcore_native/tests` — Unit tests
- `benchmarks/` , `tools/` & `scripts/` — Development Tools

## STRICT POLICY: ZERO GIT OPERATIONS

1. **NEVER touch git commands**:
   - DO NOT run `git checkout`, `git branch`, `git worktree`, `git commit`, `git merge`, `git push`, `git reset`, or `git rebase`.
   - DO NOT create new branches or worktrees under any circumstances.

2. **Work In-Place Locally**:
   - All tasks, features, refactors, and bugfixes must be executed directly on the local files in the active workspace.
   - Run tests and verifications locally without committing.

3. **Git is Strictly Human-Controlled**:
   - The user curates and maintains their own git commit history to keep it clean, intentional, and uncluttered.
   - When implementation and local tests are complete, summarize the verified changes and hand over to the user so they can review, stage, commit, and push themselves.
