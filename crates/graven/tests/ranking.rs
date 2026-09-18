mod common;

use graven::ranking::{active_profile_name, list_profiles, load_profile, set_active_profile};
use graven::store::{save_subscriptions, MultiStore};
use serde_json::{json, Value};
use wist_core::envelope::sign_envelope;

fn append_block(fx: &common::Fixture, entries: &[Value]) -> u64 {
    let sealed_at = common::next_instant(fx);
    common::seal_next(fx, &sealed_at, entries)
}

struct Site {
    signer: common::Signer,
    domain: &'static str,
}

fn site(seed: u8, domain: &'static str) -> Site {
    Site {
        signer: common::Signer::new([seed; 32]),
        domain,
    }
}

fn declaration(site: &Site) -> Value {
    json!({"type": "publisher_declaration", "body": common::build_declaration(&site.signer, site.domain)})
}

fn page(
    fx: &common::Fixture,
    site: &Site,
    path: &str,
    title: &str,
    extract: &str,
    links: &[&str],
) -> Value {
    let url = format!("https://{}/{path}", site.domain);
    let (id, envelope, payload) =
        common::build_delta_with_links(&site.signer, &url, title, None, extract, links, None);
    common::write_payload(fx.dir.path(), id.strip_prefix("sha256:").unwrap(), &payload);
    json!({"type": "publisher_delta", "body": envelope})
}

fn sync(fx: &common::Fixture, target: &std::path::Path) {
    graven::sync::run(
        fx.anchor_path().to_str().unwrap(),
        &fx.base_url,
        target,
        true,
        true,
    )
    .unwrap();
}

/// A seed-cited page ranks above a farm-cited page under the default
/// profile and below it under text-only, from the same index.
#[test]
fn a_profile_and_a_height_reproduce_a_ranking() {
    let fx = common::build_fixture_with_tier1();
    let target = tempfile::tempdir().unwrap();
    sync(&fx, target.path());

    let labeler = site(21, "labels.example");
    let seed = site(22, "seed.example");
    let cited = site(23, "cited.example");
    let farmed = site(24, "farmed.example");
    let farm: Vec<Site> = [(25u8, "f1.example"), (26, "f2.example"), (27, "f3.example")]
        .into_iter()
        .map(|(s, d)| site(s, d))
        .collect();
    let mut entries = vec![
        declaration(&labeler),
        declaration(&seed),
        declaration(&cited),
        declaration(&farmed),
    ];
    entries.extend(farm.iter().map(declaration));
    entries.push(page(
        &fx,
        &cited,
        "notes",
        "Cited orchard notes",
        "The orchard is mentioned once among many other words about apples and pears.",
        &[],
    ));
    entries.push(page(
        &fx,
        &farmed,
        "farmed",
        "Orchard orchard orchard",
        "orchard orchard orchard orchard orchard orchard orchard orchard",
        &[],
    ));
    entries.push(page(
        &fx,
        &seed,
        "home",
        "Seed home",
        "A curated page of trustworthy sources.",
        &["https://cited.example/notes"],
    ));
    for (n, f) in farm.iter().enumerate() {
        entries.push(page(
            &fx,
            f,
            "x",
            &format!("Farm page {n}"),
            "boosting the farmed page",
            &["https://farmed.example/farmed"],
        ));
    }
    let label = json!({"wist_version": "1.0.0", "labeler": "labels.example", "subject": "seed.example", "name": "wist:trust-seed", "asserted_at": "2026-08-09T12:30:00Z"});
    entries.push(json!({"type": "label", "body": sign_envelope(&label, "label", &labeler.signer.kid(), &labeler.signer.sk).unwrap()}));
    let height = append_block(&fx, &entries);
    sync(&fx, target.path());
    let mut subscriptions = std::collections::BTreeSet::new();
    subscriptions.insert("labels.example".to_string());
    save_subscriptions(target.path(), &subscriptions).unwrap();

    let store = MultiStore::open_read_only(target.path()).unwrap();
    let default = load_profile(target.path(), "default").unwrap();
    let ranked = store.search_ranked("orchard", 10, &default).unwrap();
    let order: Vec<&str> = ranked.iter().map(|h| h.url.as_str()).collect();
    assert_eq!(
        order,
        [
            "https://cited.example/notes",
            "https://farmed.example/farmed"
        ],
        "{ranked:?}"
    );
    let cited_hit = &ranked[0];
    assert!(cited_hit.signals.trust > 0.5, "{:?}", cited_hit.signals);
    assert!(cited_hit.signals.relevance < ranked[1].signals.relevance);
    assert_eq!(ranked[1].signals.trust, 0.0);
    assert!(ranked[1].signals.inlinks > 0.0 && ranked[1].signals.inlink_growth > 0.0);
    assert_eq!(cited_hit.signals.age_blocks, Some(0));
    assert!(cited_hit
        .explanation
        .iter()
        .any(|line| line.contains("trust")));
    assert_eq!(cited_hit.provenance[0].synced_height, height);

    let text_only = load_profile(target.path(), "text-only").unwrap();
    let ranked = store.search_ranked("orchard", 10, &text_only).unwrap();
    let order: Vec<&str> = ranked.iter().map(|h| h.url.as_str()).collect();
    assert_eq!(
        order,
        [
            "https://farmed.example/farmed",
            "https://cited.example/notes"
        ],
        "{ranked:?}"
    );
    assert_eq!(ranked[0].signals.trust, 0.0);

    let strict = load_profile(target.path(), "strict-trusted-graph").unwrap();
    let ranked = store.search_ranked("orchard", 10, &strict).unwrap();
    let order: Vec<&str> = ranked.iter().map(|h| h.url.as_str()).collect();
    assert_eq!(order, ["https://cited.example/notes"], "{ranked:?}");

    let again = store.search_ranked("orchard", 10, &default).unwrap();
    assert_eq!(
        again.iter().map(|h| h.score).collect::<Vec<_>>(),
        store
            .search_ranked("orchard", 10, &default)
            .unwrap()
            .iter()
            .map(|h| h.score)
            .collect::<Vec<_>>()
    );
}

#[test]
fn profiles_are_listed_selected_and_overridden() {
    let dir = tempfile::tempdir().unwrap();
    let listed = list_profiles(dir.path()).unwrap();
    let names: Vec<&str> = listed.iter().map(|p| p.name.as_str()).collect();
    assert_eq!(
        names,
        [
            "default",
            "personal-seeds",
            "strict-trusted-graph",
            "text-only"
        ]
    );
    assert!(listed.iter().all(|p| p.shipped && !p.license.is_empty()));
    assert!(listed.iter().find(|p| p.name == "default").unwrap().active);
    assert_eq!(active_profile_name(dir.path()).unwrap(), "default");
    set_active_profile(dir.path(), "text-only").unwrap();
    assert_eq!(active_profile_name(dir.path()).unwrap(), "text-only");
    assert!(set_active_profile(dir.path(), "missing").is_err());
    assert!(load_profile(dir.path(), "../default").is_err());

    let mut personal = load_profile(dir.path(), "personal-seeds").unwrap();
    personal.seeds.push("mine.example".into());
    std::fs::create_dir_all(dir.path().join("profiles")).unwrap();
    std::fs::write(
        dir.path().join("profiles/personal-seeds.json"),
        serde_json::to_vec(&personal).unwrap(),
    )
    .unwrap();
    let loaded = load_profile(dir.path(), "personal-seeds").unwrap();
    assert_eq!(loaded.seeds, vec!["mine.example".to_string()]);
    assert!(loaded.personalization);
    assert!(
        !list_profiles(dir.path())
            .unwrap()
            .iter()
            .find(|p| p.name == "personal-seeds")
            .unwrap()
            .shipped
    );
}

/// Reports the cost of deriving a profile's domain state for a synced log
/// (the batch a snapshot pays once) and of one personal-seed query on top
/// of it, over a graph of one hundred linked domains.
#[test]
fn ranking_costs_are_measured() {
    let fx = common::build_fixture_with_tier1();
    let target = tempfile::tempdir().unwrap();
    sync(&fx, target.path());
    let sites: Vec<Site> = (0..100u8)
        .map(|n| {
            let domain: &'static str = Box::leak(format!("d{n}.example").into_boxed_str());
            Site {
                signer: common::Signer::new([n.wrapping_add(40); 32]),
                domain,
            }
        })
        .collect();
    let mut entries: Vec<Value> = sites.iter().map(declaration).collect();
    for (n, s) in sites.iter().enumerate() {
        let targets: Vec<String> = (1..=3)
            .map(|k| format!("https://d{}.example/p", (n + k * 7) % 100))
            .collect();
        let refs: Vec<&str> = targets.iter().map(String::as_str).collect();
        entries.push(page(
            &fx,
            s,
            "p",
            &format!("Orchard page {n}"),
            "orchard notes and links to neighbours",
            &refs,
        ));
    }
    append_block(&fx, &entries);
    sync(&fx, target.path());
    let store = MultiStore::open_read_only(target.path()).unwrap();
    let mut personal = load_profile(target.path(), "personal-seeds").unwrap();
    personal.seeds = vec!["d0.example".into(), "d50.example".into()];
    let default = load_profile(target.path(), "default").unwrap();
    let started = std::time::Instant::now();
    let ranked = store.search_ranked("orchard", 100, &default).unwrap();
    let default_query = started.elapsed();
    let started = std::time::Instant::now();
    let ranked_personal = store.search_ranked("orchard", 100, &personal).unwrap();
    let personal_query = started.elapsed();
    assert_eq!(ranked.len(), 100);
    assert!(ranked_personal[0].signals.trust > 0.0);
    eprintln!(
        "ranking cost: 100 domains, 300 links; default query {:?}; personal-seed query {:?}",
        default_query, personal_query
    );
}
