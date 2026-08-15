# wist-graven

WIST protocol consumer: verified sync + local MCP search over publisher-signed web records.

## Install

```sh
npm install -g wist-graven
```

or run without installing:

```sh
npx wist-graven sync <args>
```

`postinstall` downloads the prebuilt `graven` binary for your platform from the matching GitHub release (`wistprotocol/graven`) and verifies it against the published `.sha256` checksum. Supported platforms: linux-x64, linux-arm64, darwin-x64, darwin-arm64, win32-x64, win32-arm64.

## Release flow (maintainers)

1. Bump `version` in `crates/graven/Cargo.toml` and `npm/package.json` to the same value.
2. `git tag v<version> && git push --tags` — triggers the `cargo-dist` release workflow, which builds the 6 target archives, checksums, and publishes the GitHub release.
3. Wait for the GitHub release to finish uploading all artifacts.
4. Publish to npm manually (not automated):

```sh
cd npm
npm publish
```

`npm publish` requires an npm auth token with publish rights on `wist-graven`; it is never run in CI.
