# Security Policy

Subskribinto handles private keys and signs transactions, so we take security reports seriously.

## Reporting a vulnerability

**Please don't report security issues through public GitHub issues, discussions or pull requests.**

Report them privately through GitHub's
[private vulnerability reporting](https://github.com/virto-network/subskribinto/security/advisories/new),
or by email to **contact@virto.team** with `[subskribinto security]` in the subject.

Please include:

- what the issue is and what an attacker could do with it,
- the steps or a proof of concept to reproduce it,
- the version or commit you tested.

Never include real secrets (mnemonics, seeds, key files or passwords) in a report. Use throwaway accounts.

## What to expect

- We acknowledge reports within **3 working days**.
- We keep you updated while we investigate, and agree on a disclosure date with you before publishing a fix.
- We credit reporters in the advisory unless you ask us not to.

## Supported versions

Only the latest commit on `main` and the latest release receive security fixes.

## Scope

In scope: anything in this repository, including how keys are decrypted, stored, held in memory and used to
sign; and how transactions are built, checked against policies and submitted.

Out of scope: vulnerabilities in the chains you connect to, in third-party wallets that export keys, and in
upstream dependencies (please report those upstream; we track their advisories in CI with `cargo deny`).
