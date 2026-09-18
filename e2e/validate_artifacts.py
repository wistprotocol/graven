#!/usr/bin/env python3
"""Validate every artifact the e2e run produced against $WIST_SPEC_DIR/schemas/.

Crypto is never reimplemented here: delta_id/root_hash/state_digest use the
same rfc8785+hashlib primitives $WIST_SPEC_DIR/tools/validate_examples.py uses
inline for the same computations, and every signature/commitment/merkle-root
recompute calls that module's own functions directly (imported below). That
module runs its whole example-suite as top-level code and calls sys.exit() at
the end, so it is loaded via importlib with SystemExit caught around
exec_module rather than a plain `import` (which CPython would otherwise evict
from sys.modules on the raised SystemExit, making the module's functions
unreachable).

Usage: validate_artifacts.py <site_dir> <clave_data_dir>
Exit 0 iff every check below passes.
"""
import contextlib
import hashlib
import importlib.util
import io
import json
import os
import pathlib
import sqlite3
import sys


def load_validate_examples(spec_dir: pathlib.Path):
    sys.path.insert(0, str(spec_dir / "tools"))
    path = spec_dir / "tools" / "validate_examples.py"
    spec = importlib.util.spec_from_file_location("validate_examples", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules["validate_examples"] = module
    with contextlib.redirect_stdout(io.StringIO()):
        try:
            spec.loader.exec_module(module)
        except SystemExit:
            pass
    return module


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: validate_artifacts.py <site_dir> <clave_data_dir>", file=sys.stderr)
        return 2
    site_dir = pathlib.Path(sys.argv[1]).resolve()
    clave_dir = pathlib.Path(sys.argv[2]).resolve()
    spec_dir = pathlib.Path(os.environ["WIST_SPEC_DIR"]).resolve()

    ve = load_validate_examples(spec_dir)
    if ve.failures:
        print(
            f"warning: {len(ve.failures)} pre-existing spec example-suite checks "
            f"failed (unrelated to this e2e run): {ve.failures}",
            file=sys.stderr,
        )

    import rfc8785
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from jsonschema import Draft202012Validator

    failures = []
    total = 0

    def check(label, fn):
        nonlocal total
        total += 1
        try:
            fn()
            print(f"PASS {label}")
        except Exception as e:
            failures.append(label)
            print(f"FAIL {label}: {e}")

    schemas_dir = spec_dir / "schemas"

    def schema_validate(name, doc):
        schema = json.loads((schemas_dir / f"{name}.schema.json").read_text())
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(doc)

    def read_json(path):
        return json.loads(path.read_bytes())

    def sha256_hex(data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()

    def delta_id_of(delta) -> str:
        return "sha256:" + sha256_hex(rfc8785.dumps(delta))

    def state_digest_of(entries) -> str:
        return "sha256:" + sha256_hex(b"".join(sorted(rfc8785.dumps(e) for e in entries)))

    wk = site_dir / ".well-known" / "wist"

    publisher_doc = read_json(wk / "publisher.json")

    def _publisher():
        schema_validate("publisher", publisher_doc)
        signer = next(
            key for key in publisher_doc["publisher"]["keys"]
            if key["kid"] == publisher_doc["sig"]["key_id"]
        )
        ve.verify_envelope(publisher_doc, "publisher", ve.b64u_decode(signer["x"]))

    check("publisher.json", _publisher)

    def spake_key(doc):
        return ve.b64u_decode(next(
            key["x"] for key in publisher_doc["publisher"]["keys"]
            if key["kid"] == doc["sig"]["key_id"]
        ))

    def _feed():
        doc = read_json(wk / "feed.json")
        schema_validate("feed", doc)
        ve.verify_envelope(doc, "feed", spake_key(doc))

    check("feed.json", _feed)

    delta_files = sorted((wk / "deltas").glob("*.json"))
    if not delta_files:
        failures.append("deltas:none-found")
        print("FAIL deltas:none-found")

    for delta_path in delta_files:

        def _delta(delta_path=delta_path):
            doc = read_json(delta_path)
            schema_validate("delta", doc)
            ve.verify_envelope(doc, "delta", spake_key(doc))
            expected_id = delta_id_of(doc["delta"])
            assert delta_path.stem == expected_id.removeprefix("sha256:"), (
                f"filename {delta_path.name} does not match recomputed "
                f"delta_id {expected_id}"
            )

        check(f"delta:{delta_path.name}", _delta)

        commitment = read_json(delta_path)["delta"].get("payload")
        if commitment is None:
            continue
        payload_path = wk / "payloads" / delta_path.name

        def _payload(payload_path=payload_path, commitment=commitment):
            payload_doc = read_json(payload_path)
            schema_validate("payload", payload_doc)
            expected = ve._commit(payload_doc["salt"], payload_doc["content"])
            assert expected == commitment["commitment"], (
                "payload does not reproduce the delta's commitment"
            )

        check(f"payload:{delta_path.name}", _payload)

    anchor_doc = read_json(clave_dir / "anchor.json")

    def _anchor():
        schema_validate("log-anchor", anchor_doc)
        pub = anchor_doc["anchor"]["genesis_key"]["public_key"]
        ve.verify_envelope(anchor_doc, "anchor", ve.b64u_decode(pub))

    check("anchor.json", _anchor)
    pub_log = ve.b64u_decode(anchor_doc["anchor"]["genesis_key"]["public_key"])

    log_id = anchor_doc["anchor"]["log_id"]

    head_text = (clave_dir / "checkpoint").read_text()
    head = {}

    def _head():
        head.update(ve.verify_checkpoint(head_text, log_id, {log_id: pub_log}))

    check("checkpoint", _head)

    archive = sorted((clave_dir / "log" / "checkpoints").glob("[0-9]" * 9))
    if not archive:
        failures.append("log/checkpoints:none-found")
        print("FAIL log/checkpoints:none-found")

    archived = {}
    for note_path in archive:

        def _archived(note_path=note_path):
            parsed = ve.verify_checkpoint(
                note_path.read_text(), log_id, {log_id: pub_log}
            )
            assert parsed["epoch_number"] == int(note_path.name), (
                "the archived Checkpoint's epoch_number is not the path's number"
            )
            archived[parsed["epoch_number"]] = parsed

        check(f"log/checkpoints/{note_path.name}", _archived)

    def decode_entry_bundle(data: bytes):
        entries = []
        position = 0
        while position < len(data):
            length = int.from_bytes(data[position : position + 2], "big")
            body = data[position + 2 : position + 2 + length]
            assert len(body) == length, "an entry bundle ends inside an Entry"
            entries.append(body)
            position += 2 + length
        return entries

    leaf_data = []
    pinned = set()

    def _entry_bundles():
        index = 0
        while True:
            full = clave_dir / "tile" / "entries" / f"{index:03d}"
            partial = sorted((clave_dir / "tile" / "entries").glob(f"{index:03d}.p/*"))
            if full.exists():
                data = full.read_bytes()
            elif partial:
                data = max(partial, key=lambda p: int(p.name)).read_bytes()
            else:
                break
            assert len(data) <= 16_777_472, "an entry bundle over its format size"
            leaf_data.extend(decode_entry_bundle(data))
            index += 1
        assert leaf_data, "the Log serves no Entry"

    check("tile/entries", _entry_bundles)

    ENTRY_SCHEMAS = {
        "publisher_delta": "delta",
        "publisher_declaration": "publisher",
        "registry_update": "registry-update",
        "label": "label",
        "dispute": "dispute",
    }

    def _entries():
        for octets in leaf_data:
            assert len(octets) <= 65_535, "an Entry over 65 535 octets"
            entry = json.loads(octets)
            assert rfc8785.dumps(entry) == octets, (
                "an Entry's leaf data is not its JCS serialization"
            )
            assert set(entry) == {"type", "body"}, "malformed Epoch Entry envelope"
            schema_validate(ENTRY_SCHEMAS[entry["type"]], entry["body"])
            update = entry.get("body", {}).get("update", {})
            if entry["type"] != "registry_update" or update.get("action") != "suffix_list_update":
                continue
            identifier = update["details"]["sha256"]
            served = clave_dir / "log" / "suffix-lists" / (identifier.split(":", 1)[1] + ".dat")
            data = served.read_bytes()
            assert "sha256:" + sha256_hex(data) == identifier, "suffix-list file does not hash to its name"
            assert len(data) == update["details"]["bytes"], "suffix-list act bytes disagree with the file"
            pinned.add(identifier)

    check("tile/entries:entries", _entries)

    def _head_states_the_served_tree():
        assert head, "the head Checkpoint did not verify"
        assert len(leaf_data) == head["tree_size"], (
            "the Entries served are not the tree size the head Checkpoint states"
        )
        leaves = [ve.leaf_hash(octets) for octets in leaf_data]
        expected = ve.merkle_root(leaves) if leaves else hashlib.sha256(b"").digest()
        assert expected == head["root"], (
            "the served Entries do not reproduce the root the head Checkpoint states"
        )
        for index in range(0, len(leaves), 256):
            group = leaves[index : index + 256]
            tile = clave_dir / "tile" / "0" / f"{index // 256:03d}"
            if not tile.exists():
                partials = sorted((clave_dir / "tile" / "0").glob(f"{index // 256:03d}.p/*"))
                assert partials, "the tree's level-0 tile is not served"
                tile = max(partials, key=lambda p: int(p.name))
            served = tile.read_bytes()
            assert len(served) <= 8192, "a tile over its format size"
            assert served == b"".join(group), (
                "a level-0 tile does not carry the leaf hashes of its Entries"
            )

    check("checkpoint:states-the-served-tree", _head_states_the_served_tree)

    def _archive_holds_the_head():
        assert head["epoch_number"] in archived, (
            "the head Checkpoint's Epoch is not in the archive"
        )
        held = archived[head["epoch_number"]]
        assert held["root"] == head["root"] and held["tree_size"] == head["tree_size"], (
            "the archived Checkpoint states another tree than the head"
        )

    check("log/checkpoints:holds-the-head", _archive_holds_the_head)

    index_doc = read_json(clave_dir / "snapshots" / "index.json")

    def _index():
        schema_validate("snapshot-index", index_doc)
        ve.verify_envelope(index_doc, "index", pub_log)
        assert index_doc["index"]["snapshots"], "snapshot index lists no snapshot"

    check("snapshots/index.json", _index)

    for entry in index_doc["index"].get("snapshots", []):
        manifest_path = clave_dir / entry["manifest_url"].lstrip("/")
        manifest_doc = read_json(manifest_path)

        def _manifest(manifest_doc=manifest_doc, manifest_path=manifest_path):
            schema_validate("snapshot-manifest", manifest_doc)
            ve.verify_envelope(manifest_doc, "manifest", pub_log)
            manifest = manifest_doc["manifest"]
            snap_dir = manifest_path.parent
            for f in manifest["files"]:
                data = (snap_dir / f["path"]).read_bytes()
                assert len(data) == f["bytes"], f"{f['path']}: byte length mismatch"
                assert sha256_hex(data) == f["sha256"], f"{f['path']}: sha256 mismatch"
            state_data = (snap_dir / manifest["state"]["path"]).read_bytes()
            assert len(state_data) == manifest["state"]["bytes"], (
                "state.json: byte length mismatch"
            )
            assert sha256_hex(state_data) == manifest["state"]["sha256"], (
                "state.json: sha256 mismatch"
            )

        check(f"manifest:{entry['snapshot_date']}", _manifest)

        state_path = manifest_path.parent / manifest_doc["manifest"]["state"]["path"]
        state_doc = read_json(state_path)

        def _state(state_doc=state_doc, manifest_doc=manifest_doc):
            schema_validate("snapshot-state", state_doc)
            ve.verify_envelope(state_doc, "state", pub_log)
            digest = state_digest_of(state_doc["state"]["entries"])
            assert digest == manifest_doc["manifest"]["state"]["state_digest"], (
                "recomputed state_digest does not match the manifest"
            )
            if pinned:
                tuples = state_doc["state"]["entries"]
                assert any(t[0] == "suffix_list" and t[1] in pinned for t in tuples), (
                    "state carries no suffix_list tuple for a pinned snapshot"
                )

        check(f"state:{entry['snapshot_date']}", _state)

        def _content_digest(manifest_doc=manifest_doc, snap_dir=manifest_path.parent):
            sqlite_path = snap_dir / "tier0" / "index.sqlite"
            conn = sqlite3.connect(f"file:{sqlite_path}?mode=ro", uri=True)
            try:
                rows = conn.execute(
                    "SELECT url, publisher, delta_id, observed_at FROM records"
                ).fetchall()
            finally:
                conn.close()
            records = [
                {
                    "url": r[0],
                    "publisher": r[1],
                    "delta_id": r[2],
                    "observed_at": r[3],
                }
                for r in rows
            ]
            digest = ve._content_digest(records)
            assert digest == manifest_doc["manifest"]["content_digest"], (
                "recomputed content_digest does not match the manifest"
            )

        check(f"content_digest:{entry['snapshot_date']}", _content_digest)

    if failures:
        print(f"\n{len(failures)}/{total} FAILED: {failures}", file=sys.stderr)
        return 1
    print(f"\nall {total} artifact checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
