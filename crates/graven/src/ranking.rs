//! Consumer ranking profiles: a profile is a file that names the signals a
//! ranking reads from the local index — text relevance, trust propagated
//! from seed domains along the signed link graph, distrust propagated
//! backward from bad seeds, in-link counts with age decay and growth
//! damping, domain age and record freshness — and how it combines them.
//! A profile and a synced height reproduce a ranking; every rank comes
//! with the signals behind it. Nothing here leaves the Consumer (ADR-0008).
use crate::error::{Error, Result};
use crate::store::{table_exists, RecordHit};
use rmcp::schemars;
use rusqlite::{Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::Path;

pub const SHIPPED: &[(&str, &str)] = &[
    ("default", include_str!("../profiles/default.json")),
    ("text-only", include_str!("../profiles/text-only.json")),
    (
        "personal-seeds",
        include_str!("../profiles/personal-seeds.json"),
    ),
    (
        "strict-trusted-graph",
        include_str!("../profiles/strict-trusted-graph.json"),
    ),
];

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Weights {
    /// The trust a domain outside the trusted graph still scores with.
    pub trust_floor: f64,
    pub trust: f64,
    pub inlinks: f64,
    pub freshness: f64,
    pub distrust: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Filters {
    /// Drop a record whose domain's propagated distrust reaches this.
    pub distrust_above: Option<f64>,
    /// Drop a record its Labelers mark as spam, by URL or by domain.
    pub spam: bool,
    /// Drop a record whose domain's first sealed Entry is younger than this.
    pub min_age_blocks: u64,
    /// Drop a record whose domain no trust reaches.
    pub trusted_graph_only: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Propagation {
    pub alpha: f64,
    pub iterations: u32,
    pub decay_per_block: f64,
    pub growth_window_blocks: u64,
    pub growth_damping: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Profile {
    pub name: String,
    pub description: String,
    pub author: String,
    pub license: String,
    pub issues_url: String,
    pub superseded_by: Option<String>,
    /// The Labelers whose Labels this profile reads; empty means the
    /// index's subscription list.
    pub labelers: Vec<String>,
    /// How many of those Labelers must agree before a Label applies.
    pub agreement_k: usize,
    pub seeds: Vec<String>,
    pub distrust_seeds: Vec<String>,
    pub weights: Weights,
    pub filters: Filters,
    pub propagation: Propagation,
    pub personalization: bool,
}

#[derive(Debug, Clone, Serialize, schemars::JsonSchema)]
pub struct ProfileSummary {
    pub name: String,
    pub description: String,
    pub author: String,
    pub license: String,
    pub superseded_by: Option<String>,
    pub shipped: bool,
    pub active: bool,
}

fn profiles_dir(dir: &Path) -> std::path::PathBuf {
    dir.join("profiles")
}

/// Loads a profile: a file under `<dir>/profiles/<name>.json` first, then
/// the shipped profile of that name.
pub fn load_profile(dir: &Path, name: &str) -> Result<Profile> {
    if name.contains('/') || name.contains('\\') || name.starts_with('.') {
        return Err(Error::Verify(format!(
            "profile name {name:?} is not a name"
        )));
    }
    let local = profiles_dir(dir).join(format!("{name}.json"));
    let text = match std::fs::read_to_string(&local) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => SHIPPED
            .iter()
            .find(|(shipped, _)| *shipped == name)
            .map(|(_, text)| text.to_string())
            .ok_or_else(|| Error::Verify(format!("no profile named {name}")))?,
        Err(e) => return Err(e.into()),
    };
    let profile: Profile =
        serde_json::from_str(&text).map_err(|e| Error::Verify(format!("profile {name}: {e}")))?;
    if profile.agreement_k == 0 {
        return Err(Error::Verify(format!(
            "profile {name}: agreement_k must be at least 1"
        )));
    }
    Ok(profile)
}

/// The profile a query uses when it names none: `<dir>/profile.json`'s
/// `active`, else `default`.
pub fn active_profile_name(dir: &Path) -> Result<String> {
    match std::fs::read(dir.join("profile.json")) {
        Ok(bytes) => {
            let doc: serde_json::Value = serde_json::from_slice(&bytes)?;
            Ok(doc["active"].as_str().unwrap_or("default").to_string())
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok("default".into()),
        Err(e) => Err(e.into()),
    }
}

pub fn set_active_profile(dir: &Path, name: &str) -> Result<()> {
    load_profile(dir, name)?;
    std::fs::create_dir_all(dir)?;
    std::fs::write(
        dir.join("profile.json"),
        serde_json::to_vec_pretty(&serde_json::json!({"active": name}))?,
    )?;
    Ok(())
}

/// Every profile available: the shipped ones and the files under
/// `<dir>/profiles/`, a file of a shipped name replacing it.
pub fn list_profiles(dir: &Path) -> Result<Vec<ProfileSummary>> {
    let active = active_profile_name(dir)?;
    let mut names: BTreeMap<String, bool> = SHIPPED
        .iter()
        .map(|(name, _)| (name.to_string(), true))
        .collect();
    if let Ok(entries) = std::fs::read_dir(profiles_dir(dir)) {
        for entry in entries.flatten() {
            let file = entry.file_name().to_string_lossy().to_string();
            if let Some(name) = file.strip_suffix(".json") {
                names.insert(name.to_string(), false);
            }
        }
    }
    names
        .into_iter()
        .map(|(name, shipped)| {
            let profile = load_profile(dir, &name)?;
            Ok(ProfileSummary {
                active: name == active,
                name,
                description: profile.description,
                author: profile.author,
                license: profile.license,
                superseded_by: profile.superseded_by,
                shipped,
            })
        })
        .collect()
}

/// The signals behind one rank, each in `[0, 1]` unless noted.
#[derive(Debug, Clone, Serialize, PartialEq, schemars::JsonSchema)]
pub struct Signals {
    pub relevance: f64,
    pub trust: f64,
    pub distrust: f64,
    pub spam: bool,
    /// Blocks since the domain's first sealed Declaration, none when the
    /// index holds no Declaration for it.
    pub age_blocks: Option<u64>,
    pub freshness: f64,
    /// Age-decayed in-links to the record's domain, normalized.
    pub inlinks: f64,
    /// In-links gained within the growth window as a share of all.
    pub inlink_growth: f64,
    pub inlink_death: f64,
}

#[derive(Debug, Clone, Serialize, schemars::JsonSchema)]
pub struct Ranked {
    #[serde(skip)]
    pub hit: RecordHit,
    pub score: f64,
    pub signals: Signals,
    pub explanation: Vec<String>,
}

/// The per-domain state a profile derives from the index at a height,
/// computed once per query set.
pub struct DomainState {
    pub trust: HashMap<String, f64>,
    pub distrust: HashMap<String, f64>,
    pub spam_hosts: BTreeSet<String>,
    pub spam_urls: BTreeSet<String>,
    pub first_height: HashMap<String, u64>,
    pub inlinks: HashMap<String, f64>,
    pub growth: HashMap<String, (f64, f64)>,
    pub max_inlinks: f64,
    pub head_height: u64,
    pub unit_of: Box<dyn Fn(&str) -> String>,
}

fn host_of(url: &str) -> String {
    url.strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .map_or(url, |rest| rest.split('/').next().unwrap_or(rest))
        .to_string()
}

fn suffix_list_in_force(conn: &Connection) -> Result<Option<wist_core::suffix_list::SuffixList>> {
    if !table_exists(conn, "suffix_list_acts")? {
        return Ok(None);
    }
    let identifier: Option<String> = conn
        .query_row(
            "SELECT sha256 FROM suffix_list_acts ORDER BY seq DESC LIMIT 1",
            [],
            |row| row.get(0),
        )
        .optional()?;
    let Some(identifier) = identifier else {
        return Ok(None);
    };
    let octets: Option<Vec<u8>> = conn
        .query_row(
            "SELECT octets FROM suffix_lists WHERE sha256 = ?1",
            [&identifier],
            |row| row.get(0),
        )
        .optional()?;
    Ok(octets.and_then(|octets| wist_core::suffix_list::SuffixList::parse(&octets).ok()))
}

/// The hosts (or URLs) at least `k` of `labelers` currently label with
/// `name`, unretracted and unexpired at `head_sealed_at`.
fn agreed_subjects(
    conn: &Connection,
    labelers: &BTreeSet<String>,
    name: &str,
    k: usize,
    head_sealed_at: Option<&str>,
) -> Result<BTreeSet<String>> {
    if labelers.is_empty() || !table_exists(conn, "label_current")? {
        return Ok(BTreeSet::new());
    }
    let mut stmt = conn.prepare(
        "SELECT labeler, subject, expires_at FROM label_current WHERE name = ?1 AND retracted = 0",
    )?;
    let mut votes: HashMap<String, BTreeSet<String>> = HashMap::new();
    for row in stmt.query_map([name], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, Option<String>>(2)?,
        ))
    })? {
        let (labeler, subject, expires_at) = row?;
        if !labelers.contains(&labeler) {
            continue;
        }
        if let (Some(expiry), Some(head)) = (expires_at.as_deref(), head_sealed_at) {
            if wist_core::publisher_time::compare(expiry, head) != Some(std::cmp::Ordering::Greater)
            {
                continue;
            }
        }
        votes.entry(subject).or_default().insert(labeler);
    }
    Ok(votes
        .into_iter()
        .filter(|(_, voters)| voters.len() >= k)
        .map(|(subject, _)| subject)
        .collect())
}

impl DomainState {
    /// Derives the profile's domain state from the index at its synced
    /// head: the trusted and distrusted graph, the spam set, domain ages
    /// and in-link figures.
    pub fn derive(
        conn: &Connection,
        profile: &Profile,
        subscriptions: &BTreeSet<String>,
        head_height: u64,
        head_sealed_at: Option<&str>,
    ) -> Result<DomainState> {
        let labelers: BTreeSet<String> = if profile.labelers.is_empty() {
            subscriptions.clone()
        } else {
            profile.labelers.iter().cloned().collect()
        };
        let list = suffix_list_in_force(conn)?;
        let unit_of: Box<dyn Fn(&str) -> String> = Box::new(move |host: &str| {
            wist_core::suffix_list::registrable_domain(host, list.as_ref()).domain
        });
        let k = profile.agreement_k;
        let mut seeds: BTreeSet<String> =
            agreed_subjects(conn, &labelers, "wist:trust-seed", k, head_sealed_at)?
                .into_iter()
                .map(|s| unit_of(&host_of(&s)))
                .collect();
        seeds.extend(profile.seeds.iter().map(|s| unit_of(s)));
        let mut bad: BTreeSet<String> =
            agreed_subjects(conn, &labelers, "wist:distrust-seed", k, head_sealed_at)?
                .into_iter()
                .map(|s| unit_of(&host_of(&s)))
                .collect();
        bad.extend(profile.distrust_seeds.iter().map(|s| unit_of(s)));
        let spam = agreed_subjects(conn, &labelers, "wist:spam", k, head_sealed_at)?;
        let mut spam_hosts = BTreeSet::new();
        let mut spam_urls = BTreeSet::new();
        for subject in spam {
            if subject.starts_with("https://") {
                spam_urls.insert(subject);
            } else {
                spam_hosts.insert(unit_of(&subject));
            }
        }

        // The signed link graph between units, each edge weighted by its
        // age at the head.
        let mut out: HashMap<String, HashMap<String, f64>> = HashMap::new();
        let mut inlinks: HashMap<String, f64> = HashMap::new();
        if table_exists(conn, "inlinks")? {
            let mut stmt = conn.prepare("SELECT source_host, target_host, height FROM inlinks")?;
            for row in stmt.query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            })? {
                let (source, target, height) = row?;
                let (source, target) = (unit_of(&source), unit_of(&target));
                if source == target {
                    continue;
                }
                let age = head_height.saturating_sub(height.max(0) as u64);
                let weight = profile
                    .propagation
                    .decay_per_block
                    .powi(age.min(i32::MAX as u64) as i32);
                *out.entry(source)
                    .or_default()
                    .entry(target.clone())
                    .or_insert(0.0) += weight;
                *inlinks.entry(target).or_insert(0.0) += weight;
            }
        }
        let mut growth: HashMap<String, (f64, f64)> = HashMap::new();
        if table_exists(conn, "link_changes")? {
            let window_start = head_height.saturating_sub(profile.propagation.growth_window_blocks);
            let mut stmt = conn.prepare(
                "SELECT target_host, SUM(added), SUM(removed) FROM link_changes WHERE height >= ?1 GROUP BY target_host",
            )?;
            for row in stmt.query_map([window_start as i64], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            })? {
                let (host, added, removed) = row?;
                let entry = growth.entry(unit_of(&host)).or_insert((0.0, 0.0));
                entry.0 += added.max(0) as f64;
                entry.1 += removed.max(0) as f64;
            }
        }
        let max_inlinks = inlinks.values().copied().fold(0.0, f64::max);

        // WIST-4 §6: a seed that links to a distrusted or spam-labeled
        // domain vouches for less; its seed mass is scaled by the share
        // of its links that stay clean.
        let mut seed_mass: HashMap<String, f64> = HashMap::new();
        for seed in &seeds {
            let mass = match out.get(seed) {
                Some(targets) if !targets.is_empty() => {
                    let total: f64 = targets.values().sum();
                    let dirty: f64 = targets
                        .iter()
                        .filter(|(target, _)| bad.contains(*target) || spam_hosts.contains(*target))
                        .map(|(_, weight)| weight)
                        .sum();
                    (total - dirty) / total
                }
                _ => 1.0,
            };
            seed_mass.insert(seed.clone(), mass);
        }
        let trust = propagate(&out, &seed_mass, &profile.propagation, false);
        let bad_mass: HashMap<String, f64> = bad.iter().map(|b| (b.clone(), 1.0)).collect();
        let distrust = propagate(&out, &bad_mass, &profile.propagation, true);

        let mut first_height = HashMap::new();
        if table_exists(conn, "declarations")? {
            let mut stmt =
                conn.prepare("SELECT domain, MIN(height) FROM declarations GROUP BY domain")?;
            for row in stmt.query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
            })? {
                let (domain, height) = row?;
                first_height.insert(domain, height.max(0) as u64);
            }
        }
        Ok(DomainState {
            trust,
            distrust,
            spam_hosts,
            spam_urls,
            first_height,
            inlinks,
            growth,
            max_inlinks,
            head_height,
            unit_of,
        })
    }
}

/// TrustRank-style propagation: `alpha` of the mass stays with the seeds
/// each round and the rest flows along out-links, split evenly; with
/// `backward` the flow runs against the links, so a domain that links to
/// a bad seed inherits its distrust. Values are normalized to the largest.
fn propagate(
    out: &HashMap<String, HashMap<String, f64>>,
    seeds: &HashMap<String, f64>,
    propagation: &Propagation,
    backward: bool,
) -> HashMap<String, f64> {
    if seeds.is_empty() {
        return HashMap::new();
    }
    let mut edges: HashMap<&str, Vec<(&str, f64)>> = HashMap::new();
    for (source, targets) in out {
        let total: f64 = targets.values().sum();
        if total <= 0.0 {
            continue;
        }
        for (target, weight) in targets {
            let share = weight / total;
            if backward {
                edges.entry(target).or_default().push((source, share));
            } else {
                edges.entry(source).or_default().push((target, share));
            }
        }
    }
    let seed_total: f64 = seeds.values().sum();
    let base: HashMap<&str, f64> = seeds
        .iter()
        .map(|(host, mass)| (host.as_str(), mass / seed_total.max(f64::MIN_POSITIVE)))
        .collect();
    let mut current: HashMap<&str, f64> = base.clone();
    for _ in 0..propagation.iterations {
        let mut next: HashMap<&str, f64> = base
            .iter()
            .map(|(host, mass)| (*host, propagation.alpha * mass))
            .collect();
        for (host, mass) in &current {
            if let Some(targets) = edges.get(host) {
                for (target, share) in targets {
                    *next.entry(target).or_insert(0.0) += (1.0 - propagation.alpha) * mass * share;
                }
            }
        }
        current = next;
    }
    let max = current.values().copied().fold(0.0, f64::max);
    current
        .into_iter()
        .filter(|(_, v)| *v > 0.0)
        .map(|(host, v)| (host.to_string(), if max > 0.0 { v / max } else { 0.0 }))
        .collect()
}

/// Ranks hits under a profile. `hits` carry their text relevance in
/// `(0, 1]`; the record's seal height comes from the index.
pub fn rank(
    conn: &Connection,
    profile: &Profile,
    state: &DomainState,
    hits: Vec<(RecordHit, f64)>,
) -> Result<Vec<Ranked>> {
    let heights_known = table_exists(conn, "record_heights")?;
    let mut ranked = Vec::with_capacity(hits.len());
    for (hit, relevance) in hits {
        let host = host_of(&hit.url);
        let unit = (state.unit_of)(&hit.publisher);
        let target_unit = (state.unit_of)(&host);
        let trust = state.trust.get(&unit).copied().unwrap_or(0.0);
        let distrust = state.distrust.get(&unit).copied().unwrap_or(0.0);
        let spam = state.spam_urls.contains(&hit.url)
            || state.spam_hosts.contains(&unit)
            || state.spam_hosts.contains(&target_unit);
        let age_blocks = state
            .first_height
            .get(&hit.publisher)
            .map(|first| state.head_height.saturating_sub(*first));
        let height: Option<u64> = if heights_known {
            conn.query_row(
                "SELECT height FROM record_heights WHERE url = ?1 AND publisher = ?2",
                (&hit.url, &hit.publisher),
                |row| row.get::<_, i64>(0),
            )
            .optional()?
            .map(|h| h.max(0) as u64)
        } else {
            None
        };
        let freshness = height.map_or(1.0, |h| {
            profile
                .propagation
                .decay_per_block
                .powi(state.head_height.saturating_sub(h).min(i32::MAX as u64) as i32)
        });
        let raw_inlinks = state.inlinks.get(&target_unit).copied().unwrap_or(0.0);
        let (added, removed) = state
            .growth
            .get(&target_unit)
            .copied()
            .unwrap_or((0.0, 0.0));
        let all = raw_inlinks.max(added).max(1.0);
        let inlink_growth = (added / all).min(1.0);
        let inlink_death = (removed / all).min(1.0);
        let damping = 1.0 / (1.0 + profile.propagation.growth_damping * inlink_growth);
        let inlinks = if state.max_inlinks > 0.0 {
            (raw_inlinks.ln_1p() / state.max_inlinks.ln_1p()) * damping
        } else {
            0.0
        };
        let signals = Signals {
            relevance,
            trust,
            distrust,
            spam,
            age_blocks,
            freshness,
            inlinks,
            inlink_growth,
            inlink_death,
        };
        let mut explanation = Vec::new();
        if let Some(limit) = profile.filters.distrust_above {
            if distrust >= limit {
                continue;
            }
        }
        if profile.filters.spam && spam {
            continue;
        }
        if age_blocks.is_some_and(|age| age < profile.filters.min_age_blocks) {
            continue;
        }
        if profile.filters.trusted_graph_only && trust <= 0.0 {
            continue;
        }
        let w = &profile.weights;
        let trust_factor = w.trust_floor + w.trust * trust;
        let inlink_factor = 1.0 + w.inlinks * inlinks;
        let freshness_factor = 1.0 - w.freshness * (1.0 - freshness);
        let distrust_factor = 1.0 - w.distrust * distrust;
        let score = relevance * trust_factor * inlink_factor * freshness_factor * distrust_factor;
        explanation.push(format!("relevance {relevance:.3}"));
        if w.trust > 0.0 {
            explanation.push(format!(
                "trust {trust:.3} reaching {unit} from the seeds, scaled to {trust_factor:.3}"
            ));
        }
        if w.inlinks > 0.0 {
            explanation.push(format!(
                "in-links {inlinks:.3} to {target_unit} after age decay and growth damping (growth {inlink_growth:.2}, death {inlink_death:.2}), factor {inlink_factor:.3}"
            ));
        }
        if w.freshness > 0.0 {
            explanation.push(format!(
                "freshness {freshness:.3} at height {}, factor {freshness_factor:.3}",
                height.map_or("unknown".to_string(), |h| h.to_string())
            ));
        }
        if w.distrust > 0.0 && distrust > 0.0 {
            explanation.push(format!(
                "distrust {distrust:.3}, factor {distrust_factor:.3}"
            ));
        }
        if let Some(age) = age_blocks {
            explanation.push(format!("domain first sealed {age} blocks before the head"));
        }
        ranked.push(Ranked {
            hit,
            score,
            signals,
            explanation,
        });
    }
    ranked.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.hit.url.cmp(&b.hit.url))
    });
    Ok(ranked)
}
