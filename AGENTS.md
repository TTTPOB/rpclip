# Repository Instructions

## Git Hooks

- This repository stores hooks in `.githooks`.
- Configure a new clone with `git config core.hooksPath .githooks`.
- The pre-commit hook requires `cargo fmt --all -- --check` to pass.

## Version Bumps and Releases

- Keep version bumps in a separate commit after the related feature or fix commits.
- Update `package.version` in `Cargo.toml`, then run `cargo check` so `Cargo.lock` records the same package version.
- Match the existing version commit message: `bump: new version`.
- Use a tag that exactly matches the package version with a `v` prefix, for example `v0.2.1` for package version `0.2.1`.
- The tag-triggered workflow in `.github/workflows/release.yaml` builds the release artifacts and creates the GitHub release.
- Do not create or push a release tag unless the user explicitly requests a release.
- Do not push commits unless the user explicitly requests it.

Typical release sequence:

```bash
# After all feature and fix commits are complete
# Edit Cargo.toml package.version
git add Cargo.toml Cargo.lock
git commit -m "bump: new version"
git tag vX.Y.Z
git push origin master
git push origin vX.Y.Z
```
