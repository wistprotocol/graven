# Releasing

1. Bump `version` in `crates/graven/Cargo.toml` and `npm/package.json` to
   the same value.
2. `git tag v<version> && git push --tags` — triggers the `cargo-dist`
   release workflow, which builds the 6 target archives, checksums, and
   publishes the GitHub release.
3. Wait for the GitHub release to finish uploading all artifacts.
4. Publish to npm:

```sh
cd npm
npm publish
```

`npm publish` runs manually with a token holding publish rights on
`wist-graven`; it is not part of CI.

## Regenerating release.yml

`cargo-dist`'s `github-build-setup` config injects the `wist-core` sibling
clone only into the `build-local-artifacts` job. The `plan`,
`build-global-artifacts`, and `host` jobs also run `dist` against the
checked-out workspace (`cargo metadata` fails without the sibling present),
so each carries the same clone step after its checkout step;
`allow-dirty = ["ci"]` in `dist-workspace.toml` keeps `dist plan`/`dist
host` from rejecting the resulting drift from a clean `dist generate`.
Running `dist generate` (e.g. after changing targets or installers)
rewrites `release.yml` from scratch and drops those clone steps — re-add
them to `plan`, `build-local-artifacts`, `build-global-artifacts`, and
`host` after any regenerate.
