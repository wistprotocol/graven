use super::source::Sources;
use crate::error::{Error, Result};
use rusqlite::Connection;
use serde_json::Value;
use std::collections::BTreeMap;
use wist_core::epoch::parse_entries;
use wist_core::tiles::{
    check_entry_bundle, decode_entry_bundle_at, decode_tile_at, entry_bundles_for_range,
    required_tiles, tiles_for_range, EntryBundle, Tile, TileSet, ENTRY_BUNDLE_MAX_BYTES,
    TILE_MAX_BYTES, TILE_WIDTH,
};

pub const CREATE_TREE_TILES: &str = "CREATE TABLE IF NOT EXISTS tree_tiles(level INTEGER NOT NULL, idx INTEGER NOT NULL, hashes BLOB NOT NULL, PRIMARY KEY(level, idx))";

fn invalid(message: &str) -> Error {
    Error::Verify(format!("WIST3-E03 {message}"))
}

/// WIST-3 §6.
#[derive(Clone, Default)]
pub struct Tree {
    raw: BTreeMap<(u8, u64), Vec<u8>>,
    set: TileSet,
}

impl Tree {
    pub fn new() -> Self {
        Tree::default()
    }

    pub fn load(conn: &Connection) -> Result<Self> {
        conn.execute_batch(CREATE_TREE_TILES)?;
        let mut tree = Tree::new();
        let mut stmt = conn.prepare("SELECT level, idx, hashes FROM tree_tiles")?;
        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, i64>(0)? as u8,
                    row.get::<_, i64>(1)? as u64,
                    row.get::<_, Vec<u8>>(2)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        for (level, index, bytes) in rows {
            tree.insert(level, index, &bytes)?;
        }
        Ok(tree)
    }

    pub fn save(&self, conn: &Connection) -> Result<()> {
        conn.execute_batch(CREATE_TREE_TILES)?;
        for ((level, index), bytes) in &self.raw {
            conn.execute(
                "INSERT INTO tree_tiles(level, idx, hashes) VALUES (?1, ?2, ?3)
                 ON CONFLICT(level, idx) DO UPDATE SET hashes = excluded.hashes",
                (i64::from(*level), *index as i64, bytes),
            )?;
        }
        Ok(())
    }

    pub fn insert(&mut self, level: u8, index: u64, bytes: &[u8]) -> Result<()> {
        self.set.insert_bytes(level, index, bytes)?;
        self.raw.insert((level, index), bytes.to_vec());
        Ok(())
    }

    pub fn reader(&self) -> &TileSet {
        &self.set
    }

    pub fn tiles(&self) -> &BTreeMap<(u8, u64), Vec<u8>> {
        &self.raw
    }
}

/// WIST-3 §6: 256 hashes at a full path, `W` at `.p/<W>`; any other form is `WIST3-E03`.
fn tile_form(path: &str, bytes: &[u8]) -> Result<()> {
    decode_tile_at(path, bytes)?;
    Ok(())
}

/// WIST-3 §6: partial only at the width a Checkpoint's size requires; the full tile is the
/// fallback.
fn tile_bytes(sources: &Sources, at: usize, tile: &Tile) -> Result<Vec<u8>> {
    let want = tile.width as usize * 32;
    let path = tile.path();
    let exact = sources.at(&path, TILE_MAX_BYTES, at, |bytes| tile_form(&path, bytes));
    match exact {
        Ok(bytes) => Ok(bytes),
        Err(error) if tile.width < TILE_WIDTH => {
            let full = Tile {
                width: TILE_WIDTH,
                ..*tile
            };
            let full_path = full.path();
            match sources.at(&full_path, TILE_MAX_BYTES, at, |bytes| {
                tile_form(&full_path, bytes)
            }) {
                Ok(bytes) => Ok(bytes[..want].to_vec()),
                Err(_) => Err(error),
            }
        }
        Err(error) => Err(error),
    }
}

fn fetch_tiles(sources: &Sources, tree: &Tree, wanted: &[Tile], at: usize) -> Result<Tree> {
    let mut candidate = tree.clone();
    for tile in wanted {
        let bytes = tile_bytes(sources, at, tile)?;
        candidate.insert(tile.level, tile.index, &bytes)?;
    }
    Ok(candidate)
}

/// WIST-3 §6.
fn adopt_tiles(
    sources: &Sources,
    tree: &mut Tree,
    wanted: &[Tile],
    tree_size: u64,
    root: &[u8; 32],
) -> Result<()> {
    let mut last: Option<Error> = None;
    for at in 0..sources.count() {
        let candidate = match fetch_tiles(sources, tree, wanted, at) {
            Ok(candidate) => candidate,
            Err(error) => {
                last = Some(error);
                continue;
            }
        };
        match wist_core::tiles::check_tree(candidate.reader(), tree_size, root) {
            Ok(()) => {
                *tree = candidate;
                return Ok(());
            }
            Err(error) => last = Some(error.into()),
        }
    }
    Err(last.unwrap_or_else(|| Error::Fetch("WIST3-E01 no source holds the tree's tiles".into())))
}

/// WIST-3 §4: no party holds a tile at size 0, so the root is compared, never skipped
/// (`WIST3-E02`).
fn check_empty_tree(root: &[u8; 32]) -> Result<()> {
    if *root != wist_core::merkle::EMPTY_ROOT {
        return Err(Error::Verify(
            "WIST3-E02 a Checkpoint states tree size 0 with another root than the empty tree's"
                .into(),
        ));
    }
    Ok(())
}

/// WIST-3 §8 step 5.
pub fn seed(sources: &Sources, tree: &mut Tree, tree_size: u64, root: &[u8; 32]) -> Result<()> {
    if tree_size == 0 {
        return check_empty_tree(root);
    }
    adopt_tiles(sources, tree, &required_tiles(tree_size), tree_size, root)
}

/// Kept only where the whole tree reproduces Checkpoint N's root.
pub fn extend(
    sources: &Sources,
    tree: &mut Tree,
    from: u64,
    to: u64,
    root: &[u8; 32],
) -> Result<()> {
    if to == 0 {
        return check_empty_tree(root);
    }
    let wanted = tiles_for_range(from, to, to);
    adopt_tiles(sources, tree, &wanted, to, root)
}

/// Built beside the verified tiles, never over them, so a fork is never mixed into the tree the
/// Consumer holds.
pub fn offered_tree(sources: &Sources, tree_size: u64, root: &[u8; 32]) -> Result<Option<Tree>> {
    if tree_size == 0 {
        return Ok(None);
    }
    let wanted = required_tiles(tree_size);
    for at in 0..sources.count() {
        let Ok(candidate) = fetch_tiles(sources, &Tree::new(), &wanted, at) else {
            continue;
        };
        if wist_core::tiles::check_tree(candidate.reader(), tree_size, root).is_ok() {
            return Ok(Some(candidate));
        }
    }
    Ok(None)
}

fn bundle_bytes(sources: &Sources, tree: &Tree, bundle: &EntryBundle) -> Result<Vec<u8>> {
    let (start, _) = bundle.leaf_range();
    let width = bundle.width as usize;
    let path = bundle.path();
    let check = |bytes: &[u8]| -> Result<()> {
        let entries = decode_entry_bundle_at(&path, bytes)?;
        check_entry_bundle(&entries, start, tree.reader())?;
        Ok(())
    };
    match sources.cached(&path, ENTRY_BUNDLE_MAX_BYTES, check) {
        Ok(bytes) => Ok(bytes),
        Err(error) if bundle.width < TILE_WIDTH => {
            let full = EntryBundle {
                index: bundle.index,
                width: TILE_WIDTH,
            };
            let full_path = full.path();
            let truncate = |bytes: &[u8]| -> Result<Vec<u8>> {
                let entries = decode_entry_bundle_at(&full_path, bytes)?;
                let held = entries[..width].to_vec();
                check_entry_bundle(&held, start, tree.reader())?;
                wist_core::tiles::encode_entry_bundle(&held).map_err(Into::into)
            };
            for at in 0..sources.count() {
                let fetched = sources
                    .at(&full_path, ENTRY_BUNDLE_MAX_BYTES, at, |_| Ok(()))
                    .and_then(|bytes| truncate(&bytes));
                if let Ok(bytes) = fetched {
                    return Ok(bytes);
                }
            }
            Err(error)
        }
        Err(error) => Err(error),
    }
}

/// WIST-3 §3.1 and §6: held to leaves `size(N-1)` through `size(N) - 1` and stopped at the prefix's
/// transport bound.
pub fn epoch_entries(
    sources: &Sources,
    tree: &Tree,
    from: u64,
    to: u64,
    transport_bound: u64,
) -> Result<Vec<Value>> {
    if from >= to {
        return Ok(Vec::new());
    }
    let over = || invalid("the Epoch's Entries exceed the transport bound of its prefix");
    let mut leaf_data: Vec<Vec<u8>> = Vec::new();
    let mut leaf_indexes: Vec<u64> = Vec::new();
    let mut octets: u64 = 0;
    for bundle in entry_bundles_for_range(from, to, to) {
        if octets > transport_bound {
            return Err(over());
        }
        let path = bundle.path();
        let bytes = bundle_bytes(sources, tree, &bundle)?;
        let (start, _) = bundle.leaf_range();
        for (offset, entry) in decode_entry_bundle_at(&path, &bytes)?
            .into_iter()
            .enumerate()
        {
            let index = start + offset as u64;
            if index < from || index >= to {
                continue;
            }
            octets += entry.len() as u64 + 2;
            if octets > transport_bound {
                return Err(over());
            }
            leaf_indexes.push(index);
            leaf_data.push(entry);
        }
    }
    wist_core::epoch::check_leaf_range(from, to, &leaf_indexes)?;
    Ok(parse_entries(&leaf_data)?)
}
