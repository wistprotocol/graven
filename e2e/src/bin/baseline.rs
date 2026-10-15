use e2e::{
    after_this_second, consumer_report, consumer_state, copy_dir, dir_bytes, free_loopback_addr,
    graven_bin, grid_instant, host_name, log_tree_size, merge, now_rfc3339, page, peak_rss_kb,
    ping_until_admitted, reports_since, reset_peak_rss, resolve_sibling_bin, revisions,
    round_report, run, run_measured, s, seal_epoch, sealed_stage, serve_sites_counted,
    snapshot_report, spawn_clave_serve_with, storage_bytes, sync_args, timed, wait_all_pulled,
    wait_until_after, write_pages, RequestLog, SealStage, Site,
};
use graven::sync::SyncState;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UpdateBy {
    Chain,
    Walk,
}

impl UpdateBy {
    fn parse(value: &str) -> Self {
        match value {
            "chain" => UpdateBy::Chain,
            "walk" => UpdateBy::Walk,
            other => panic!("--update-by takes chain or walk, not {other}"),
        }
    }

    fn name(self) -> &'static str {
        match self {
            UpdateBy::Chain => "chain",
            UpdateBy::Walk => "walk",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CatchUpBy {
    Walk,
    Snapshot,
    Both,
}

impl CatchUpBy {
    fn parse(value: &str) -> Self {
        match value {
            "walk" => CatchUpBy::Walk,
            "snapshot" => CatchUpBy::Snapshot,
            "both" => CatchUpBy::Both,
            other => panic!("--catch-up-by takes walk, snapshot or both, not {other}"),
        }
    }

    fn name(self) -> &'static str {
        match self {
            CatchUpBy::Walk => "walk",
            CatchUpBy::Snapshot => "snapshot",
            CatchUpBy::Both => "both",
        }
    }

    fn walks(self) -> bool {
        self != CatchUpBy::Snapshot
    }

    fn snapshots(self) -> bool {
        self != CatchUpBy::Walk
    }
}

fn same_head(a: &SyncState, b: &SyncState) -> bool {
    (a.epoch_number, a.tree_size, &a.root) == (b.epoch_number, b.tree_size, &b.root)
}

struct Args {
    domains: usize,
    pages: usize,
    large_domains: usize,
    large_pages: usize,
    changed_percent: usize,
    body_words: usize,
    tier1: bool,
    extra_empty_seals: usize,
    snapshot_shards: Option<i64>,
    skip_consumer: bool,
    compare_rebuild: bool,
    withdraw: bool,
    update_by: UpdateBy,
    catch_up_by: CatchUpBy,
    tree_bound: bool,
    tree_bound_items: usize,
    work_dir: Option<PathBuf>,
    keep: bool,
    out: Option<PathBuf>,
}

fn args() -> Args {
    let mut args = Args {
        domains: 10,
        pages: 20,
        large_domains: 0,
        large_pages: 0,
        changed_percent: 10,
        body_words: 200,
        tier1: true,
        extra_empty_seals: 0,
        snapshot_shards: None,
        skip_consumer: false,
        compare_rebuild: false,
        withdraw: false,
        update_by: UpdateBy::Chain,
        catch_up_by: CatchUpBy::Both,
        tree_bound: false,
        tree_bound_items: 1024,
        work_dir: None,
        keep: false,
        out: None,
    };
    let mut it = std::env::args().skip(1);
    while let Some(flag) = it.next() {
        let mut value = || it.next().unwrap_or_else(|| panic!("{flag} needs a value"));
        match flag.as_str() {
            "--domains" => args.domains = value().parse().expect("--domains"),
            "--pages" => args.pages = value().parse().expect("--pages"),
            "--large-domains" => args.large_domains = value().parse().expect("--large-domains"),
            "--large-pages" => args.large_pages = value().parse().expect("--large-pages"),
            "--changed-percent" => {
                args.changed_percent = value().parse().expect("--changed-percent")
            }
            "--body-words" => args.body_words = value().parse().expect("--body-words"),
            "--no-tier1" => args.tier1 = false,
            "--skip-consumer" => args.skip_consumer = true,
            "--extra-empty-seals" => {
                args.extra_empty_seals = value().parse().expect("--extra-empty-seals")
            }
            "--snapshot-shards" => {
                args.snapshot_shards = Some(value().parse().expect("--snapshot-shards"))
            }
            "--compare-rebuild" => args.compare_rebuild = true,
            "--withdraw" => args.withdraw = true,
            "--update-by" => args.update_by = UpdateBy::parse(&value()),
            "--catch-up-by" => args.catch_up_by = CatchUpBy::parse(&value()),
            "--tree-bound" => args.tree_bound = true,
            "--tree-bound-items" => {
                args.tree_bound_items = value().parse().expect("--tree-bound-items")
            }
            "--work-dir" => args.work_dir = Some(PathBuf::from(value())),
            "--keep" => args.keep = true,
            "--out" => args.out = Some(PathBuf::from(value())),
            other => panic!("unknown flag {other}"),
        }
    }
    args
}

struct Round<'a> {
    small: (&'a [String], usize),
    large: (&'a [String], usize),
}

impl Round<'_> {
    fn report(&self, log: &RequestLog, pulled: &BTreeMap<String, f64>) -> Value {
        let requests = log.requests();
        let all: Vec<String> = self.small.0.iter().chain(self.large.0).cloned().collect();
        let mut report = round_report(&requests, &all, self.small.1 + self.large.1, pulled);
        if !self.large.0.is_empty() {
            report["small_domains"] = round_report(&requests, self.small.0, self.small.1, pulled);
            report["large_domains"] = round_report(&requests, self.large.0, self.large.1, pulled);
        }
        report
    }
}

fn delete_change_lists(site: &Site) -> usize {
    let Ok(entries) = std::fs::read_dir(site.collection_dir().join("changes")) else {
        return 0;
    };
    let mut deleted = 0;
    for entry in entries.flatten() {
        std::fs::remove_file(entry.path()).expect("delete a change list");
        deleted += 1;
    }
    deleted
}

fn nibble(key: &[u8; 32], position: usize) -> u8 {
    let byte = key[position / 2];
    if position.is_multiple_of(2) {
        byte >> 4
    } else {
        byte & 0x0f
    }
}

const DEEP_FIRST_DIGITS: u8 = 8;

#[derive(Default)]
struct TreeFiles {
    files: BTreeMap<String, Vec<u8>>,
    inner: usize,
    buckets: usize,
    deepest: u64,
}

impl TreeFiles {
    fn store(&mut self, file: Value, level: u64) -> String {
        let octets = wist_core::jcs::canonicalize(&file).expect("canonicalize a tree file");
        let hex = wist_core::crypto::hex_encode(&Sha256::digest(&octets));
        self.deepest = self.deepest.max(level);
        self.files.insert(hex.clone(), octets);
        format!("sha256:{hex}")
    }

    fn bucket(&mut self, keyed: &[([u8; 32], Value)], level: u64) -> String {
        self.buckets += 1;
        let items: Vec<&Value> = keyed.iter().map(|(_, item)| item).collect();
        self.store(json!({ "items": items }), level)
    }

    fn chain(
        &mut self,
        keyed: &[([u8; 32], Value)],
        prefix: &str,
        level: u64,
        depth_max: u64,
    ) -> String {
        if level >= depth_max {
            return self.bucket(keyed, level);
        }
        let mut children = Vec::new();
        for group in keyed.chunk_by(|(left, _), (right, _)| {
            nibble(left, prefix.len()) == nibble(right, prefix.len())
        }) {
            let child = format!("{prefix}{:x}", nibble(&group[0].0, prefix.len()));
            let file = self.chain(group, &child, level + 1, depth_max);
            children.push(json!({ "prefix": child, "count": group.len(), "file": file }));
        }
        self.inner += 1;
        self.store(json!({ "children": children }), level)
    }
}

struct BoundTree {
    list: Vec<Value>,
    built: wist_core::tree::Built,
    shape: Value,
}

fn bound_tree(template: &Value, host: &str, deep_items: usize) -> BoundTree {
    let bounds = wist_core::tree::TreeBounds::suite();
    let cap = bounds.tree_file_cap_bytes() as usize;
    let depth_max = bounds.tree_depth_max();
    let deep_items = deep_items.max(1);
    let slots = usize::from(16 - DEEP_FIRST_DIGITS);
    let mut deep = Vec::new();
    let mut full: Vec<Vec<([u8; 32], Value)>> = vec![Vec::new(); slots];
    let mut full_octets = vec![r#"{"items":[]}"#.len(); slots];
    let mut closed = vec![false; slots];
    let candidates = std::iter::once(template.clone()).chain((0u64..).map(|n| {
        let mut item = template.clone();
        item["url"] = json!(format!("https://{host}/bound/{n}.html"));
        item
    }));
    for item in candidates {
        if deep.len() >= deep_items && closed.iter().all(|closed| *closed) {
            break;
        }
        let key = wist_core::item::key(item["url"].as_str().expect("an Item's url"));
        let first = nibble(&key, 0);
        if first < DEEP_FIRST_DIGITS {
            if deep.len() < deep_items {
                deep.push((key, item));
            }
            continue;
        }
        let slot = usize::from(first - DEEP_FIRST_DIGITS);
        if closed[slot] {
            continue;
        }
        let added = wist_core::jcs::canonicalize(&item)
            .expect("canonicalize an Item")
            .len()
            + usize::from(!full[slot].is_empty());
        if full_octets[slot] + added > cap {
            closed[slot] = true;
            continue;
        }
        full_octets[slot] += added;
        full[slot].push((key, item));
    }
    let deep_count = deep.len();
    let full_counts: Vec<usize> = full.iter().map(Vec::len).collect();
    let mut keyed: Vec<([u8; 32], Value)> =
        deep.into_iter().chain(full.into_iter().flatten()).collect();
    keyed.sort_by_key(|(key, _)| *key);
    let mut files = TreeFiles::default();
    let mut children = Vec::new();
    for group in keyed.chunk_by(|(left, _), (right, _)| nibble(left, 0) == nibble(right, 0)) {
        let digit = nibble(&group[0].0, 0);
        let prefix = format!("{digit:x}");
        let file = if digit < DEEP_FIRST_DIGITS {
            files.chain(group, &prefix, 2, depth_max)
        } else {
            files.bucket(group, 2)
        };
        children.push(json!({ "prefix": prefix, "count": group.len(), "file": file }));
    }
    files.inner += 1;
    let tree = files.store(json!({ "children": children }), 1);
    let sizes: Vec<usize> = files.files.values().map(Vec::len).collect();
    let shape = json!({
        "items": keyed.len(),
        "deep_items": deep_count,
        "full_bucket_items": full_counts,
        "full_bucket_octets": full_octets,
        "tree_files": files.files.len(),
        "inner_files": files.inner,
        "bucket_files": files.buckets,
        "levels": files.deepest,
        "tree_depth_max": depth_max,
        "largest_file_octets": sizes.iter().max(),
        "tree_file_cap_bytes": cap,
        "tree_octets": sizes.iter().sum::<usize>(),
    });
    BoundTree {
        list: keyed.into_iter().map(|(_, item)| item).collect(),
        built: wist_core::tree::Built {
            tree,
            files: files.files,
        },
        shape,
    }
}

fn main() {
    let args = args();
    let spake = resolve_sibling_bin("SPAKE_BIN", "spake");
    let clave = resolve_sibling_bin("CLAVE_BIN", "clave");
    let graven = graven_bin();
    let mut report = json!({
        "domains": args.domains,
        "pages_per_domain": args.pages,
        "large_domains": args.large_domains,
        "large_pages_per_domain": args.large_pages,
        "body_words": args.body_words,
        "changed_percent": args.changed_percent,
        "tier1": args.tier1,
        "snapshot_shards": args.snapshot_shards,
        "skip_consumer": args.skip_consumer,
        "update_by": args.update_by.name(),
        "catch_up_by": args.catch_up_by.name(),
        "tree_bound": args.tree_bound,
        "tree_bound_items": args.tree_bound.then_some(args.tree_bound_items),
        "build_profile": e2e::build_profile(),
        "revisions": revisions(),
        "stages": {},
    });
    let tmp = match &args.work_dir {
        Some(dir) => tempfile::Builder::new().tempdir_in(dir),
        None => tempfile::tempdir(),
    }
    .expect("tempdir");
    let (_tmp_guard, root) = if args.keep {
        let root = tmp.keep();
        eprintln!("work directory: {}", root.display());
        (None, root)
    } else {
        let root = tmp.path().to_path_buf();
        (Some(tmp), root)
    };
    let domain_count = args.domains + args.large_domains;
    let hosts: Vec<String> = (0..domain_count).map(host_name).collect();
    let (small_hosts, large_hosts) = hosts.split_at(args.domains);
    let page_counts: Vec<usize> = (0..domain_count)
        .map(|i| {
            if i < args.domains {
                args.pages
            } else {
                args.large_pages
            }
        })
        .collect();
    let small_items = args.domains * args.pages;
    let large_items = args.large_domains * args.large_pages;
    let sites: Vec<Site> = hosts
        .iter()
        .map(|host| Site::new(&root, host, "default"))
        .collect();
    for (site, pages) in sites.iter().zip(&page_counts) {
        write_pages(site, *pages, args.body_words, 1);
    }
    let tree_site = args
        .tree_bound
        .then(|| Site::new(&root, &host_name(domain_count), "default"));
    let (proxy_addr, _counters, requests) = serve_sites_counted(
        sites
            .iter()
            .chain(&tree_site)
            .map(|site| (site.host.clone(), site.out.clone()))
            .collect::<BTreeMap<_, _>>(),
    );

    let ((), publish_s) = timed(|| {
        for site in &sites {
            site.init(&spake);
            site.publish(&spake);
        }
    });
    let published_bytes: u64 = sites
        .iter()
        .map(|site| dir_bytes(&site.out.join(".well-known")))
        .sum();
    report["stages"]["publish"] = json!({
        "seconds": publish_s,
        "items": small_items + large_items,
        "well_known_bytes": published_bytes,
    });

    let clave_data = root.join("clave-data");
    let clave_host = free_loopback_addr();
    run(
        &clave,
        &["init", "--log-id", &clave_host, "--data", s(&clave_data)],
    );
    if let Some(shards) = args.snapshot_shards {
        rusqlite::Connection::open(clave_data.join("clave.sqlite"))
            .expect("open the aggregator store")
            .execute(
                "INSERT INTO params(name, value) VALUES ('snapshot_shard_count', ?1) ON CONFLICT(name) DO UPDATE SET value = excluded.value",
                [shards],
            )
            .expect("set snapshot_shard_count");
    }
    let (clave_child, _, _clave_stderr) = spawn_clave_serve_with(
        &clave,
        &clave_data,
        &clave_host,
        Some(&format!("http://{proxy_addr}")),
    );
    let clave_pid = clave_child.0.id();
    let clave_base = format!("http://{clave_host}");
    let http = reqwest::blocking::Client::new();

    requests.clear();
    reset_peak_rss(clave_pid);
    let since = after_this_second();
    let mut refused = 0u64;
    let ((), ping_s) = timed(|| {
        for host in &hosts {
            refused += ping_until_admitted(&spake, &clave_base, host);
        }
    });
    let pulled = wait_all_pulled(
        &http,
        &clave_base,
        &hosts,
        &since,
        Duration::from_secs(3600),
    );
    let ingest = Round {
        small: (small_hosts, small_items),
        large: (large_hosts, large_items),
    };
    let mut ingest_report = ingest.report(&requests, &pulled);
    merge(
        &mut ingest_report,
        json!({
            "ping_seconds": ping_s,
            "pings_refused": refused,
            "aggregator_peak_rss_kb": peak_rss_kb(clave_pid),
            "wist2_e08_reports": reports_since(&http, &clave_base, &hosts, &since, "WIST2-E08"),
        }),
    );
    report["stages"]["ingest"] = ingest_report;

    let mut sealed = 0u64;
    report["stages"]["seal_1"] = sealed_stage(
        &clave,
        &clave_data,
        &grid_instant(0),
        args.compare_rebuild,
        &mut sealed,
    );

    let gdir = root.join("graven-store");
    let anchor = clave_data.join("anchor.json");
    if !args.skip_consumer {
        let cold = run_measured(&graven, &sync_args(&anchor, &clave_base, &gdir, args.tier1));
        report["stages"]["consumer_cold_start"] = consumer_report(&cold, &gdir);
    }

    let changed: Vec<usize> = page_counts
        .iter()
        .map(|pages| (pages * args.changed_percent).div_ceil(100))
        .collect();
    for (site, changed) in sites.iter().zip(&changed) {
        for j in 0..*changed {
            site.write_page(
                &format!("p{j}.html"),
                &page(&site.host, j, args.body_words, 2),
            );
        }
    }
    let small_changed: usize = changed[..args.domains].iter().sum();
    let large_changed: usize = changed[args.domains..].iter().sum();
    requests.clear();
    reset_peak_rss(clave_pid);
    let since = after_this_second();
    let mut update_refused = 0u64;
    let mut change_lists_deleted = 0usize;
    let ((), republish_s) = timed(|| {
        for site in &sites {
            site.publish(&spake);
            if args.update_by == UpdateBy::Walk {
                change_lists_deleted += delete_change_lists(site);
            }
            update_refused += ping_until_admitted(&spake, &clave_base, &site.host);
        }
    });
    let pulled = wait_all_pulled(
        &http,
        &clave_base,
        &hosts,
        &since,
        Duration::from_secs(3600),
    );
    let update = Round {
        small: (small_hosts, small_changed),
        large: (large_hosts, large_changed),
    };
    let mut update_report = update.report(&requests, &pulled);
    merge(
        &mut update_report,
        json!({
            "update_by": args.update_by.name(),
            "changed_items": small_changed + large_changed,
            "change_lists_deleted": change_lists_deleted,
            "republish_and_ping_seconds": republish_s,
            "pings_refused": update_refused,
            "aggregator_peak_rss_kb": peak_rss_kb(clave_pid),
            "wist2_e08_reports": reports_since(&http, &clave_base, &hosts, &since, "WIST2-E08"),
        }),
    );
    report["stages"]["update"] = update_report;

    report["stages"]["seal_2"] = sealed_stage(
        &clave,
        &clave_data,
        &grid_instant(1),
        args.compare_rebuild,
        &mut sealed,
    );
    report["stages"]["seal_3_empty"] = sealed_stage(
        &clave,
        &clave_data,
        &grid_instant(2),
        args.compare_rebuild,
        &mut sealed,
    );

    let extra: Vec<SealStage> = (0..args.extra_empty_seals)
        .map(|k| {
            let at = grid_instant(3 + k as i64);
            SealStage::run(&clave, &clave_data, &at, args.compare_rebuild)
        })
        .collect();
    sealed = log_tree_size(&clave_data);
    let epochs = 3 + args.extra_empty_seals;
    let mut extra_report = json!({
        "count": args.extra_empty_seals,
        "seconds_each": extra.iter().map(|st| st.seal.seconds + st.snapshot.seconds).collect::<Vec<_>>(),
        "seal_seconds_each": extra.iter().map(SealStage::seal_seconds).collect::<Vec<_>>(),
        "seal_peak_rss_kb_each": extra.iter().map(|st| st.seal.peak_rss_kb).collect::<Vec<_>>(),
        "snapshot_seconds_each": extra.iter().map(|st| st.snapshot.seconds).collect::<Vec<_>>(),
        "snapshot_each": extra.iter().map(|st| snapshot_report(&st.snapshot)).collect::<Vec<_>>(),
        "snapshot_rebuild_each": extra.iter().map(SealStage::rebuild_report).collect::<Vec<_>>(),
        "log_bytes": dir_bytes(&clave_data.join("log")),
    });
    let mut last_storage = storage_bytes(&clave_data);
    last_storage
        .as_object_mut()
        .expect("storage bytes object")
        .remove("snapshot_build_bytes");
    merge(&mut extra_report, last_storage);
    report["stages"]["extra_empty_seals"] = extra_report;

    let ((), verify_s) = timed(|| {
        run(&clave, &["verify-history", "--data", s(&clave_data)]);
    });
    report["stages"]["verify_history"] = json!({ "seconds": verify_s, "epochs": epochs });

    let gdir_by_snapshot = root.join("graven-store-by-snapshot");
    let by_snapshot = !args.skip_consumer && args.catch_up_by.snapshots();
    if by_snapshot {
        copy_dir(&gdir, &gdir_by_snapshot);
    }
    let mut walked = None;
    if !args.skip_consumer && args.catch_up_by.walks() {
        let catch_up = run_measured(&graven, &["sync", "--dir", s(&gdir), "--allow-http"]);
        report["stages"]["consumer_catch_up"] = consumer_report(&catch_up, &gdir);
        if by_snapshot {
            walked = Some(consumer_state(&gdir));
        }
    }
    if by_snapshot {
        let before = consumer_state(&gdir_by_snapshot);
        let mut sync = sync_args(&anchor, &clave_base, &gdir_by_snapshot, args.tier1);
        sync.extend(["--catch-up-epochs", "0"]);
        let catch_up = run_measured(&graven, &sync);
        let after = consumer_state(&gdir_by_snapshot);
        let mut stage = consumer_report(&catch_up, &gdir_by_snapshot);
        merge(
            &mut stage,
            json!({
                "head_epoch": after.epoch_number,
                "tree_size": after.tree_size,
                "root": after.root,
                "snapshot_installed": after.walk_floor != before.walk_floor,
                "walk_floor_before": before.walk_floor,
                "walk_floor_after": after.walk_floor,
                "same_head_as_walk": walked.as_ref().map(|walked| same_head(walked, &after)),
            }),
        );
        if let Some(walked) = &walked {
            assert!(
                same_head(walked, &after),
                "the walking consumer ends at epoch {} (tree size {}, root {}) and the Snapshot one at epoch {} (tree size {}, root {})",
                walked.epoch_number,
                walked.tree_size,
                walked.root,
                after.epoch_number,
                after.tree_size,
                after.root
            );
        }
        report["stages"]["consumer_catch_up_by_snapshot"] = stage;
    }
    let gdir2 = root.join("graven-store-2");
    if !args.skip_consumer {
        let cold = run_measured(
            &graven,
            &sync_args(&anchor, &clave_base, &gdir2, args.tier1),
        );
        let mut cold_report = consumer_report(&cold, &gdir2);
        cold_report["epochs"] = json!(epochs);
        report["stages"]["consumer_cold_start_after_all_seals"] = cold_report;
    }

    let mut next_seal = 3 + args.extra_empty_seals as i64;
    if args.withdraw {
        let site = &sites[0];
        let item_id = site.item_id(&site.url("p0.html"));
        let before = storage_bytes(&clave_data);
        run(
            &clave,
            &[
                "withdraw",
                "--data",
                s(&clave_data),
                "--domain",
                &site.host,
                "--item-id",
                &item_id,
                "--legal-basis",
                "test",
                "--jurisdiction",
                "test",
            ],
        );
        let mut withdrawal = sealed_stage(
            &clave,
            &clave_data,
            &grid_instant(next_seal),
            args.compare_rebuild,
            &mut sealed,
        );
        next_seal += 1;
        merge(
            &mut withdrawal,
            json!({ "items_withdrawn": 1, "before": before }),
        );
        report["stages"]["withdrawal"] = withdrawal;
    }

    if let Some(site) = &tree_site {
        write_pages(site, 1, args.body_words, 1);
        site.init(&spake);
        site.publish(&spake);
        let tree_hosts = [site.host.clone()];
        let since = after_this_second();
        ping_until_admitted(&spake, &clave_base, &site.host);
        wait_all_pulled(
            &http,
            &clave_base,
            &tree_hosts,
            &since,
            Duration::from_secs(600),
        );
        seal_epoch(&clave, &clave_data, &grid_instant(next_seal));
        next_seal += 1;
        sealed = log_tree_size(&clave_data);
        if !args.skip_consumer {
            run(&graven, &["sync", "--dir", s(&gdir), "--allow-http"]);
        }

        let template = site
            .served_list()
            .into_iter()
            .next()
            .expect("the served list holds the template page's Item");
        let (bound, build_s) = timed(|| bound_tree(&template, &site.host, args.tree_bound_items));
        for item in bound.list.iter().filter(|item| **item != template) {
            site.serve_payload_as(&template, item);
        }
        let served = site.catalog();
        let kid = served["sig"]["key_id"]
            .as_str()
            .expect("the served Catalog names its key")
            .to_string();
        wait_until_after(
            served["catalog"]["generated_at"]
                .as_str()
                .expect("the served Catalog's generated_at"),
        );
        site.serve_catalog_with_tree(
            &bound.list,
            &bound.built,
            &now_rfc3339(),
            &kid,
            &site.signing_key(&kid),
        );
        let deleted = delete_change_lists(site);
        assert_eq!(
            site.served_list().len(),
            bound.list.len(),
            "the bound tree does not walk to its list"
        );

        requests.clear();
        reset_peak_rss(clave_pid);
        let since = after_this_second();
        ping_until_admitted(&spake, &clave_base, &site.host);
        let pulled = wait_all_pulled(
            &http,
            &clave_base,
            &tree_hosts,
            &since,
            Duration::from_secs(3600),
        );
        let mut walk = round_report(&requests.requests(), &tree_hosts, bound.list.len(), &pulled);
        merge(
            &mut walk,
            json!({
                "aggregator_peak_rss_kb": peak_rss_kb(clave_pid),
                "change_lists_deleted": deleted,
                "wist2_e08_reports": reports_since(&http, &clave_base, &tree_hosts, &since, "WIST2-E08"),
            }),
        );
        let seal = sealed_stage(
            &clave,
            &clave_data,
            &grid_instant(next_seal),
            args.compare_rebuild,
            &mut sealed,
        );
        let mut tree_report = json!({
            "shape": bound.shape,
            "build_seconds": build_s,
            "walk": walk,
            "seal": seal,
        });
        if !args.skip_consumer {
            let catch_up = run_measured(&graven, &["sync", "--dir", s(&gdir), "--allow-http"]);
            tree_report["consumer_catch_up"] = consumer_report(&catch_up, &gdir);
        }
        report["stages"]["tree_bound"] = tree_report;
    }

    let text = serde_json::to_string_pretty(&report).expect("report");
    println!("{text}");
    if let Some(out) = args.out {
        std::fs::write(out, text).expect("write report");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn update_by_parses_chain_and_walk() {
        assert_eq!(UpdateBy::parse("chain"), UpdateBy::Chain);
        assert_eq!(UpdateBy::parse("walk"), UpdateBy::Walk);
        assert_eq!(UpdateBy::Walk.name(), "walk");
    }

    #[test]
    #[should_panic(expected = "--update-by takes chain or walk")]
    fn update_by_refuses_another_mode() {
        UpdateBy::parse("tree");
    }

    #[test]
    fn catch_up_by_parses_walk_snapshot_and_both() {
        assert_eq!(CatchUpBy::parse("walk"), CatchUpBy::Walk);
        assert_eq!(CatchUpBy::parse("snapshot"), CatchUpBy::Snapshot);
        assert_eq!(CatchUpBy::parse("both"), CatchUpBy::Both);
        assert_eq!(CatchUpBy::Snapshot.name(), "snapshot");
    }

    #[test]
    #[should_panic(expected = "--catch-up-by takes walk, snapshot or both")]
    fn catch_up_by_refuses_another_path() {
        CatchUpBy::parse("chain");
    }

    #[test]
    fn catch_up_by_walk_runs_no_snapshot_catch_up_and_snapshot_no_walk() {
        assert!(CatchUpBy::Walk.walks() && !CatchUpBy::Walk.snapshots());
        assert!(!CatchUpBy::Snapshot.walks() && CatchUpBy::Snapshot.snapshots());
        assert!(CatchUpBy::Both.walks() && CatchUpBy::Both.snapshots());
    }

    fn state(epoch_number: u64, tree_size: u64, root: &str, walk_floor: Option<u64>) -> SyncState {
        SyncState {
            format: 7,
            tree_size,
            epoch_number,
            root: root.into(),
            unwitnessed: false,
            content_digest: None,
            snapshot_tree_size: None,
            schedule_first_s: None,
            prior_sealed_at_s: None,
            largest_epoch_bytes: 0,
            walk_floor,
            rejected_epochs: Vec::new(),
        }
    }

    #[test]
    fn same_head_compares_epoch_tree_size_and_root_but_not_the_walk_floor() {
        let walked = state(5, 40, "sha256:aa", Some(0));
        assert!(same_head(&walked, &state(5, 40, "sha256:aa", Some(4))));
        assert!(!same_head(&walked, &state(4, 40, "sha256:aa", Some(0))));
        assert!(!same_head(&walked, &state(5, 41, "sha256:aa", Some(0))));
        assert!(!same_head(&walked, &state(5, 40, "sha256:bb", Some(0))));
    }

    #[test]
    fn delete_change_lists_removes_every_served_change_list() {
        let root = tempfile::tempdir().expect("tempdir");
        let site = Site::new(root.path(), "127.0.9.9", "default");
        assert_eq!(delete_change_lists(&site), 0);
        let changes = site.collection_dir().join("changes");
        std::fs::create_dir_all(&changes).expect("changes directory");
        for name in ["aa.json", "bb.json"] {
            std::fs::write(changes.join(name), "{}").expect("change list");
        }
        assert_eq!(delete_change_lists(&site), 2);
        assert_eq!(std::fs::read_dir(&changes).expect("list").count(), 0);
    }

    #[test]
    fn bound_tree_walks_to_its_list_at_the_depth_bound_with_buckets_filled_to_the_cap() {
        let template = json!({
            "publisher": "127.0.9.9",
            "url": "https://127.0.9.9/p0.html",
            "observed_at": "2026-10-01T00:00:00Z",
            "payload": {
                "alg": "HMAC-SHA256",
                "bytes": 1584,
                "commitment": format!("hmac-sha256:{}", "0".repeat(64)),
            },
            "meta": { "lang": "en" },
        });
        let bound = bound_tree(&template, "127.0.9.9", 12);
        let bounds = wist_core::tree::TreeBounds::suite();
        assert!(bound.list.contains(&template));
        assert_eq!(bound.shape["deep_items"], 12);
        assert_eq!(bound.shape["levels"], bounds.tree_depth_max());
        let cap = bounds.tree_file_cap_bytes();
        let item_octets = wist_core::jcs::canonicalize(&bound.list[0])
            .expect("jcs")
            .len() as u64;
        for octets in bound.shape["full_bucket_octets"]
            .as_array()
            .expect("octets")
        {
            let octets = octets.as_u64().expect("octets");
            assert!(octets <= cap && octets + item_octets + 1 > cap, "{octets}");
        }
        let catalog: wist_core::objects::Catalog = serde_json::from_value(json!({
            "wist_version": "1.0.0",
            "publisher": "127.0.9.9",
            "collection": "default",
            "generated_at": "2026-10-01T00:00:00Z",
            "size": bound.list.len(),
            "root": format!(
                "sha256:{}",
                wist_core::crypto::hex_encode(&wist_core::item::root(&bound.list).expect("root"))
            ),
            "tree": bound.built.tree,
        }))
        .expect("Catalog form");
        let walked =
            wist_core::tree::walk(&catalog, &bounds, |hex| match bound.built.files.get(hex) {
                Some(octets) => wist_core::tree::TreeFetch::Octets(octets.clone()),
                None => wist_core::tree::TreeFetch::Failed,
            });
        let wist_core::tree::Walk::Listed(listed) = walked else {
            panic!("the bound tree does not walk: {walked:?}");
        };
        assert_eq!(listed.len(), bound.list.len());
    }
}
