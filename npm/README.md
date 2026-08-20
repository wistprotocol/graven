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

The maintainer release flow is documented in
[`RELEASING.md`](https://github.com/wistprotocol/graven/blob/main/RELEASING.md).
