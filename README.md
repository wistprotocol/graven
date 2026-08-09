# graven

WIST Protocol consumer and MCP server. Graven cold-syncs a verified snapshot from an
aggregator's log (checking the chain, checkpoint signature, and every Merkle
proof before trusting a byte of it), then follows the block stream to stay
current, applying each new delta to a local SQLite index. A `serve` command
exposes that index to an LLM agent over MCP (`search`, `get_record`) — every
returned record carries the provenance an agent needs to judge trust for
itself, never a bare claim.

Subcommands: `sync` (cold snapshot sync, then continuous block-stream
sync), `serve` (MCP server over stdio against a synced store).

## Build & test

```bash
cargo build
cargo test
```

Conformance tests read the spec repo's schemas/vectors from `../spec`
(sibling checkout) by default, or from `WIST_SPEC_DIR` if set. Building also
resolves `wist-core` from `../core`. The `e2e` workspace member additionally
drives real `spake` and `clave` binaries end to end, so `../spake` and
`../clave` must also be sibling checkouts (`SPAKE_BIN`/`CLAVE_BIN` override
the binary paths; it validates artifacts against the spec's schemas via
`WIST_SPEC_DIR`, requiring `jsonschema`, `rfc8785`, and `cryptography` on
`PATH`'s python3 — set `CI=1` to hard-fail instead of skipping when they're
missing).

## Verification

```bash
cargo fmt --all --check
cargo clippy --all-targets -- -D warnings
cargo test --workspace
cargo deny check
```

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option.

## Spec

Protocol definitions live in the sibling [spec repo](../spec) — Graven is a
consumer of all three: WIST-1 deltas, WIST-2 site publication, and WIST-3
logbook & distribution (sync, snapshots, proofs).
