---
name: finishing-a-development-branch
description: Use when implementation is complete and verified - summarizes changes locally and hands over git control to the user
---

# Finishing Development Work

## HARD RULE: DO NOT TOUCH GIT

> **STRICT USER POLICY**:
> The AI agent MUST NOT run any git merge, git commit, git push, git branch, or git checkout commands.
> Git history and repository actions are strictly managed by the human user.

## Overview

When all tasks are implemented and verified:
1. **Run Full Verification**: Run the project test suite (`flutter test`, `npm test`, `cargo test`, or appropriate test runner) and static analysis to ensure 0 errors.
2. **Summarize Work Locally**: Present a concise walkthrough of:
   - What files were created or modified
   - What was tested and the test results
   - Verification evidence
3. **Hand Over to the User**:
   - Inform the user that all changes exist cleanly in the local workspace.
   - Do NOT attempt to commit, merge, or push.
   - Leave git staging, committing, and pushing entirely to the user.
