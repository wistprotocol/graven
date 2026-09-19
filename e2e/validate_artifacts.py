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

    def no_duplicate_members(pairs):
        """WIST-1 §4, applied to every file this reads from its octets:
        "parsing MUST reject duplicate decoded member names, including
        inside nested objects" (WIST-4 §5.1)."""
        seen = set()
        for name, _ in pairs:
            if name in seen:
                raise ValueError(f"duplicate decoded member name {name!r}")
            seen.add(name)
        return dict(pairs)

    def parse_octets(data: bytes):
        return json.loads(data, object_pairs_hook=no_duplicate_members)

    def read_json(path):
        return parse_octets(path.read_bytes())

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
    genesis_key = anchor_doc["anchor"]["genesis_key"]

    log_id = anchor_doc["anchor"]["log_id"]

    # WIST-3 §5: a Checkpoint is verified under the Aggregator keys valid
    # at its own height, which the Snapshot's tuples and the key acts
    # above them fix, so every note is parsed first and authenticated once
    # that key set is known.
    head_text = (clave_dir / "checkpoint").read_text()
    head = {}

    def _head():
        head.update(ve.parse_checkpoint(head_text))
        assert head["origin"] == log_id, (
            "the head Checkpoint's origin line is not the Log's log_id"
        )

    check("checkpoint", _head)

    archive = sorted((clave_dir / "log" / "checkpoints").glob("[0-9]" * 9))
    if not archive:
        failures.append("log/checkpoints:none-found")
        print("FAIL log/checkpoints:none-found")

    archived = {}
    for note_path in archive:

        def _archived(note_path=note_path):
            parsed = ve.parse_checkpoint(note_path.read_text())
            assert parsed["origin"] == log_id, (
                "an archived Checkpoint's origin line is not the Log's log_id"
            )
            assert parsed["epoch_number"] == int(note_path.name), (
                "the archived Checkpoint's epoch_number is not the path's number"
            )
            archived[parsed["epoch_number"]] = (parsed, note_path.read_text())

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
            entry = parse_octets(octets)
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
        held = archived[head["epoch_number"]][0]
        assert held["root"] == head["root"] and held["tree_size"] == head["tree_size"], (
            "the archived Checkpoint states another tree than the head"
        )

    check("log/checkpoints:holds-the-head", _archive_holds_the_head)

    def key_tuples(state_doc):
        return [t for t in state_doc["state"]["entries"] if t[0] == "aggregator_key"]

    def valid_at(registry, height):
        """WIST-3 §7: a tuple's key is valid at height h ≥ 0 iff its added
        height ≤ h and its removed height is null or greater than h; the
        set valid at −1 is the Anchor's genesis key alone (§3.4)."""
        if height < 0:
            return {
                key_id: record
                for key_id, record in registry.items()
                if key_id == genesis_key["key_id"]
            }
        return {
            key_id: record
            for key_id, record in registry.items()
            if record["added"] <= height
            and (record["removed"] is None or record["removed"] > height)
        }

    def log_instant(value):
        """WIST-3 §3.1: a timestamp denoting a real instant, at whole-second
        precision with a literal trailing Z. A leap second, a date no
        calendar carries and year zero denote no instant (WIST-4 §5.1)."""
        assert value[:4] != "0000", "a timestamp in year zero denotes no instant"
        ve.log_seconds(value)

    def field_validation(act):
        """WIST-4 §5.1's field validation of a Registry Update, which §7
        rules 3 and 4 require of a carried key act and §3.4 requires before
        a walked one is accepted. The schema fixes each member's shape;
        these are the rules it cannot express. `update` admits no member
        beyond the five the schema names, so `effective_at` is the only
        timestamp the Envelope carries."""
        schema_validate("registry-update", act)
        update = act["update"]
        major = update["wist_version"].split(".")[0]
        assert major == "1", f"wist_version major {major} is not 1"
        log_instant(update["effective_at"])
        if update["action"] in ("aggregator_key_add", "aggregator_key_remove"):
            assert update["subject"] == update["details"]["key_id"], (
                "a key act's subject is not its details.key_id"
            )

    def act_names(act, action, key_id, public_key):
        """WIST-3 §7 rules 3 and 4: the act a tuple carries passes WIST-4
        §5.1's field validation and names the tuple's key."""
        field_validation(act)
        update = act["update"]
        assert update["action"] == action, f"the act is not an {action}"
        assert update["details"]["key_id"] == key_id, (
            "the act does not name its tuple's key_id"
        )
        if public_key is not None:
            assert update["details"]["public_key"] == public_key, (
                "the adding act does not name its tuple's public_key"
            )

    def authenticate_key_tuples(tuples, epoch_number):
        """WIST-3 §7's five rules, which chain every key act to the
        Anchor's genesis key by induction on height. Returns the registry
        the tuples state."""
        registry = {}
        note_ids = set()
        for _, key_id, public_key, added, removed, adding, removing in tuples:
            note_id = ve.note_key_id(log_id, ve.b64u_decode(public_key))
            assert key_id not in registry and note_id not in note_ids, (
                "rule 1: two tuples carry one key_id or keys with one note key ID"
            )
            note_ids.add(note_id)
            registry[key_id] = {
                "public_key": public_key,
                "added": added,
                "removed": removed,
                "adding": adding,
                "removing": removing,
            }

        rootless = [key_id for key_id, r in registry.items() if r["adding"] is None]
        assert len(rootless) == 1, "rule 2: not exactly one tuple has a null adding act"
        root = registry[rootless[0]]
        assert (
            rootless[0] == genesis_key["key_id"]
            and root["public_key"] == genesis_key["public_key"]
            and root["added"] == 0
        ), "rule 2: the tuple with no adding act is not the Anchor's genesis key at height 0"

        for key_id, record in registry.items():
            if record["adding"] is not None:
                act_names(
                    record["adding"],
                    "aggregator_key_add",
                    key_id,
                    record["public_key"],
                )
                assert 0 <= record["added"] <= epoch_number, (
                    "rule 3: the added height is outside 0 through the Snapshot's Epoch"
                )
            assert (record["removing"] is None) == (record["removed"] is None), (
                "rule 4: the removing act is not null exactly when the removed height is"
            )
            if record["removed"] is not None:
                act_names(record["removing"], "aggregator_key_remove", key_id, None)
                floor = 0 if record["adding"] is None else record["added"] + 1
                assert floor <= record["removed"] <= epoch_number, (
                    "rule 4: the removed height is not above the added height and at "
                    "most the Snapshot's Epoch"
                )

        for key_id, record in registry.items():
            for act, height in (
                (record["adding"], record["added"]),
                (record["removing"], record["removed"]),
            ):
                if act is None:
                    continue
                signer = act["sig"]["key_id"]
                below = valid_at(registry, height - 1)
                assert signer in below, (
                    "rule 5: no tuple holds the act's signer valid at the height "
                    "below the act's own"
                )
                ve.verify_envelope(
                    act, "update", ve.b64u_decode(below[signer]["public_key"])
                )
        return registry

    def _field_validation_rejects_what_the_schema_admits():
        """WIST-4 §5.1's field rules that `registry-update.schema.json`
        cannot express, exercised against an act the schema accepts."""
        well_formed = {
            "update": {
                "wist_version": "1.0.0",
                "action": "aggregator_key_add",
                "subject": "second",
                "details": {
                    "key_id": "second",
                    "alg": "Ed25519",
                    "public_key": genesis_key["public_key"],
                },
                "effective_at": "2026-02-28T00:00:00Z",
            },
            "sig": {
                "key_id": genesis_key["key_id"],
                "alg": "Ed25519",
                "value": "A" * 85 + "A",
            },
        }
        field_validation(well_formed)
        for member, value, why in (
            ("subject", "other", "a subject that is not the act's details.key_id"),
            ("wist_version", "2.0.0", "a wist_version major other than 1"),
            (
                "effective_at",
                "2026-02-30T00:00:00Z",
                "an effective_at denoting no instant",
            ),
        ):
            broken = json.loads(json.dumps(well_formed))
            broken["update"][member] = value
            schema_validate("registry-update", broken)
            try:
                field_validation(broken)
            except Exception:
                continue
            raise AssertionError(f"field validation admits {why}")
        try:
            parse_octets(b'{"update":{},"update":{}}')
        except ValueError:
            return
        raise AssertionError("parsing admits a duplicate decoded member name")

    check(
        "registry-update:field-validation",
        _field_validation_rejects_what_the_schema_admits,
    )

    index_doc = read_json(clave_dir / "snapshots" / "index.json")

    def _index():
        schema_validate("snapshot-index", index_doc)
        assert index_doc["index"]["snapshots"], "snapshot index lists no snapshot"

    check("snapshots/index.json", _index)

    states = {}
    for entry in index_doc["index"].get("snapshots", []):
        manifest_path = clave_dir / entry["manifest_url"].lstrip("/")
        manifest_doc = read_json(manifest_path)

        def _manifest(manifest_doc=manifest_doc, manifest_path=manifest_path):
            schema_validate("snapshot-manifest", manifest_doc)
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
        states[entry["snapshot_date"]] = (manifest_doc, state_doc)

        def _state(state_doc=state_doc, manifest_doc=manifest_doc):
            schema_validate("snapshot-state", state_doc)
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

        def _tuples(state_doc=state_doc, manifest_doc=manifest_doc):
            authenticate_key_tuples(
                key_tuples(state_doc), manifest_doc["manifest"]["epoch_number"]
            )

        check(f"state:{entry['snapshot_date']}:key-tuples", _tuples)

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

    # WIST-3 §6: the index lists Snapshots newest first, so its first entry
    # carries the key state closest to the head; §3.4's key acts in the
    # Epochs above it amend that state, each authenticated under the keys
    # valid at the Epoch below its own.
    registry = {}
    newest = (index_doc["index"].get("snapshots") or [{}])[0].get("snapshot_date")

    def epoch_entries(number):
        below = archived[number - 1][0]["tree_size"] if number else 0
        here = archived[number][0]["tree_size"]
        return [parse_octets(octets) for octets in leaf_data[below:here]]

    def apply_key_acts(registry, number):
        """WIST-3 §3.4: an Epoch's key acts apply in canonical Entry index
        order under the keys valid at the Epoch below it, are accepted only
        when they pass WIST-4 §5.1's field validation, and an act that
        fails changes nothing."""
        below = valid_at(registry, number - 1)
        for entry in epoch_entries(number):
            if entry["type"] != "registry_update":
                continue
            act = entry["body"]
            update = act["update"]
            if update["action"] not in ("aggregator_key_add", "aggregator_key_remove"):
                continue
            try:
                field_validation(act)
            except Exception:
                continue
            signer = act["sig"]["key_id"]
            if signer not in below:
                continue
            try:
                ve.verify_envelope(
                    act, "update", ve.b64u_decode(below[signer]["public_key"])
                )
            except Exception:
                continue
            subject = update["details"]["key_id"]
            if update["action"] == "aggregator_key_add":
                public_key = update["details"]["public_key"]
                note_id = ve.note_key_id(log_id, ve.b64u_decode(public_key))
                collides = any(
                    ve.note_key_id(log_id, ve.b64u_decode(r["public_key"])) == note_id
                    for r in registry.values()
                )
                if subject in registry or collides:
                    continue
                registry[subject] = {
                    "public_key": public_key,
                    "added": number,
                    "removed": None,
                }
            elif subject in below and registry[subject]["removed"] is None:
                registry[subject]["removed"] = number

    def _key_set_at_the_head():
        assert newest, "the snapshot index lists no Snapshot to resume from"
        manifest_doc, state_doc = states[newest]
        epoch_number = manifest_doc["manifest"]["epoch_number"]
        registry.update(
            authenticate_key_tuples(key_tuples(state_doc), epoch_number)
        )
        for number in range(epoch_number + 1, head["epoch_number"] + 1):
            apply_key_acts(registry, number)
        assert valid_at(registry, head["epoch_number"]), (
            "no Aggregator key is valid at the head, so Checkpoint N has no signer"
        )

    check("aggregator-keys:at-the-head", _key_set_at_the_head)

    NO_KNOWN_SIGNER = "no verifying signature under a known key"

    def verify_note(text, height, label):
        """WIST-3 §5: a Checkpoint carries a verifying signature under a key
        valid at its own height, and "a line naming a known key ... that
        fails to verify also rejects the whole Checkpoint". The reference
        validator keys its Aggregator map by signer name, and every key of
        one Log shares that name, so each key valid at the height is
        offered in turn and every one of them is asked: a key that signed
        no line leaves the note unjudged, a key whose line fails rejects
        it, and at least one must verify."""
        verified = None
        for record in valid_at(registry, height).values():
            keys = {log_id: ve.b64u_decode(record["public_key"])}
            try:
                verified = ve.verify_checkpoint(text, log_id, keys)
            except ValueError as e:
                if NO_KNOWN_SIGNER not in str(e):
                    raise AssertionError(f"{label}: {e}")
        assert verified is not None, (
            f"{label} carries no signature under a key valid at height {height}"
        )
        return verified

    def _head_signature():
        verify_note(head_text, head["epoch_number"], "the head Checkpoint")

    check("checkpoint:signed-at-its-own-height", _head_signature)

    for number in sorted(archived):

        def _archived_signature(number=number):
            verify_note(archived[number][1], number, f"Checkpoint {number}")

        check(f"log/checkpoints/{number:09d}:signed-at-its-own-height", _archived_signature)

    # WIST-3 §3.4: an Aggregator-signed document that no tree commits to
    # verifies under the keys valid at the height of the Checkpoint a
    # Consumer adopts, which against a served Log is its head.
    def verify_unsealed(doc, inner_key, label):
        at_head = valid_at(registry, head["epoch_number"])
        signer = doc["sig"]["key_id"]
        assert signer in at_head, (
            f"{label} is signed by {signer!r}, which is not valid at the head"
        )
        ve.verify_envelope(doc, inner_key, ve.b64u_decode(at_head[signer]["public_key"]))

    check(
        "snapshots/index.json:signed-at-the-head",
        lambda: verify_unsealed(index_doc, "index", "the Snapshot index"),
    )
    for snapshot_date, (manifest_doc, state_doc) in states.items():
        check(
            f"manifest:{snapshot_date}:signed-at-the-head",
            lambda m=manifest_doc, d=snapshot_date: verify_unsealed(
                m, "manifest", f"the {d} Snapshot manifest"
            ),
        )
        check(
            f"state:{snapshot_date}:signed-at-the-head",
            lambda s=state_doc, d=snapshot_date: verify_unsealed(
                s, "state", f"the {d} Snapshot state file"
            ),
        )

    mirrors_path = clave_dir / "log" / "mirrors.json"
    if mirrors_path.exists():
        mirrors_doc = read_json(mirrors_path)

        def _mirrors():
            schema_validate("mirrors", mirrors_doc)
            verify_unsealed(mirrors_doc, "mirrors", "the Mirror list")

        check("log/mirrors.json:signed-at-the-head", _mirrors)

    if failures:
        print(f"\n{len(failures)}/{total} FAILED: {failures}", file=sys.stderr)
        return 1
    print(f"\nall {total} artifact checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
