---
name: using-git-worktrees
description: Strict rule against touching git, branching, or creating worktrees. Always work directly in the local workspace in place.
---

# Local In-Place Workspace (Git Prohibition Rule)

## HARD RULE: NEVER TOUCH GIT, NEVER CREATE BRANCHES OR WORKTREES

> **STRICT USER POLICY**:
> The AI agent is strictly forbidden from performing git branch operations, git worktree operations, git checkouts, or git commits.
> The Git domain is exclusively reserved for the human user so they can curate and maintain a clean, intentional commit history.

## Guidelines

1. **Work In-Place Locally**:
   - Always perform code edits, file creations, refactorings, and test runs directly in the current local project directory.
   - Do NOT run `git worktree add`, `git checkout -b`, `git branch`, or any other branch creation/switching command.

2. **No Git Isolation Needed**:
   - Do not attempt to isolate tasks using git branches or git worktrees.
   - Simply verify that the local codebase is working and proceed with the task in the active workspace.

3. **Leave Git to the User**:
   - Once your local code changes are implemented and verified, present the completed changes to the user.
   - The user will personally handle git staging (`git add`), committing (`git commit`), branching, and pushing (`git push`).
