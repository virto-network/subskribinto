# Releasing Subskribinto

This is the maintainer side of the process. For PR titles and how the changelog is written, see
[CONTRIBUTING.md](./CONTRIBUTING.md). The setup matches the other Virto crates
([frame-contrib](https://github.com/virto-network/frame-contrib),
[pass-authenticators](https://github.com/virto-network/pass-authenticators)).

| Change | Bump (from 1.0) | Bump (0.x) |
| --- | --- | --- |
| Breaking: a removed or renamed flag or subcommand, or an incompatible policy or keystore format | **major** | minor |
| New feature, backwards compatible | minor | patch |
| Fix, dependency or metadata update | patch | patch |

The bump is computed from the PR titles on `main` (`!` → breaking, `feat` → feature, anything
else → patch). `cargo-semver-checks` is off (see `release-plz.toml`).

## Tags

`vX.Y.Z`, one per release, created by release-plz. Users should install from crates.io
(`cargo install subskribinto`) rather than from git.

## Cutting a release

1. Merge PRs into `main` as usual (squash merges; the PR title becomes the commit title).
2. [release-plz](https://release-plz.dev) keeps a `chore: release vX.Y.Z` PR open with the
   computed version, and the `Release` workflow writes that version's `CHANGELOG.md` section onto
   it with git-cliff (`cliff.toml`).
3. **Curate the changelog section right before merging.** Reword entries for users, and add
   upgrade notes under breaking changes, taking them from each PR's description. Any new push to
   `main` rebuilds the release PR and discards manual edits. If you push a hand-written section,
   the workflow leaves it alone.
4. Merge the release PR. The `Release` workflow publishes the crate to crates.io, pushes
   `vX.Y.Z`, and creates a GitHub release whose notes are the curated section.

## One-time setup (repository settings)

- Secret `CARGO_REGISTRY_TOKEN`: a crates.io API token with the `publish-new` and
  `publish-update` scopes.
- `CRATES_IO_PUBLISH` = `true`, as a repository **variable or secret**: enables publishing. Until
  it is set, only the release PR is maintained.
- The org's GitHub App (KreivoPs): variable `KREIVOPS_APP_ID` and secret
  `KREIVOPS_APP_PRIVATE_KEY`. PRs opened and commits pushed with the default `GITHUB_TOKEN` don't
  trigger CI, so without the app the release PR never gets its checks. A `RELEASE_PLZ_TOKEN`
  secret (fine-grained PAT with `contents` and `pull-requests` write access) works as a fallback.
- Settings → General → Pull Requests: squash merges only, with **Pull request title** as the
  default commit message. With "Default to commit title", a single-commit PR takes the commit's
  title, and a `!` that is only on the PR title is lost.
- A `release` label, which release-plz puts on its PRs.

## First publish

`0.2.0` is set by hand in `Cargo.toml` and has a hand-written changelog section; `0.1.0` was never
published. Once the one-time setup is done, the next push to `main` (or a manual run of the
`Release` workflow) publishes `0.2.0`, tags `v0.2.0` and creates its GitHub release. Turn on
`CRATES_IO_PUBLISH` only once everything meant for `0.2.0` has landed on `main`.
