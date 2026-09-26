//! Image admission policy generation (#1533 P2-3).
//!
//! From the signers kguardian observed on running images (the supplychain
//! component's verified results, [`crate::attestation`]), generate:
//!
//! | format | document | audit mode |
//! |---|---|---|
//! | `kyverno` | Kyverno `ImageValidatingPolicy` (`policies.kyverno.io/v1beta1`) | `validationActions: [Audit]` |
//! | `policy-controller` | Sigstore policy-controller `ClusterImagePolicy` (`policy.sigstore.dev/v1beta1`) | `mode: warn` (it has no audit mode: admits and warns) |
//! | `kguardian` | kguardian `ImageTrustPolicy` / `ClusterImageTrustPolicy` | always report-only (evaluator) |
//!
//! Report and generate only: kguardian never applies anything.
//!
//! # What is generated
//!
//! Images are grouped by repository. A repository is covered only when
//! every running digest of it verified; its authorities are the signers
//! seen (union across digests). Anything else (unsigned, invalid, signed
//! with a key kguardian does not hold, not checked, unknown) is listed in
//! the header as not covered: a policy for it would deny what runs today,
//! and inventing a signer is not an option. SLSA provenance is required
//! when every digest of the repository has it, verified and signed by one
//! of the authorities. Repositories with the same authorities and
//! requirements share one policy.
//!
//! A GitHub Actions keyless subject pinned to a tag
//! (`.../release.yaml@refs/tags/v1.2.3`) is widened to any tag of the
//! same workflow, or the next release would fail. Every other subject is
//! kept exact. Regular expressions are anchored (`^...$`) for every
//! engine.
//!
//! Engine specifics, checked against their sources (Kyverno v1.19.1,
//! policy-controller v0.15.1): Kyverno matches the image string as written
//! in the pod spec with a glob whose `*` crosses `/`, and only images a
//! policy's `matchImageReferences` select reach its validations;
//! policy-controller matches the normalised name (`index.docker.io/...`,
//! tag `latest` when none), requires every matching policy to pass, and
//! checks only attestations for an authority that lists attestations, so
//! a provenance requirement becomes a second ClusterImagePolicy.

use crate::attestation::RunningImage;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

pub const FORMATS: [&str; 3] = ["kyverno", "policy-controller", "kguardian"];

const SLSA_V1: &str = "https://slsa.dev/provenance/v1";
const SLSA_V02: &str = "https://slsa.dev/provenance/v0.2";
const GITHUB_ISSUER: &str = "https://token.actions.githubusercontent.com";

/// A trusted signer as it appears in a policy.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Authority {
    Keyless {
        issuer: String,
        /// Exact subject, or an anchored regexp when `regexp`.
        subject: String,
        regexp: bool,
    },
    Key {
        fingerprint: String,
        pem: String,
    },
}

/// One generated policy: repositories that share authorities and
/// requirements.
#[derive(Debug, Clone, PartialEq)]
pub struct Group {
    pub repositories: Vec<Repo>,
    pub authorities: Vec<Authority>,
    /// Predicate types every digest carries, signed by an authority.
    pub predicates: Vec<String>,
}

/// A repository and the image names pods use for it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Repo {
    /// Normalised (`docker.io/library/nginx`).
    pub repository: String,
    /// As written in pod specs, tag and digest removed (`nginx`).
    pub spec_names: BTreeSet<String>,
}

/// What generation found.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Plan {
    pub groups: Vec<Group>,
    /// Every identity a policy trusts, with the (repository, digest) pairs
    /// it was seen verifying: observed, not vetted, so listed for review.
    pub evidence: BTreeMap<Authority, BTreeSet<(String, String)>>,
    /// Repository -> why it is not covered.
    pub uncovered: BTreeMap<String, String>,
}

/// Image name without tag or digest.
pub fn strip_ref(r: &str) -> &str {
    let r = r.split('@').next().unwrap_or(r);
    match (r.rfind(':'), r.rfind('/')) {
        (Some(c), Some(s)) if c > s => &r[..c],
        (Some(c), None) => &r[..c],
        _ => r,
    }
}

fn regex_escape(s: &str) -> String {
    let mut o = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        if "\\.+*?()|[]{}^$".contains(c) {
            o.push('\\');
        }
        o.push(c);
    }
    o
}

/// The policy authority for an observed signer, or `None` when it cannot
/// be expressed (a key signer without its public key).
pub fn authority_of(s: &Value) -> Option<Authority> {
    let kind = s
        .get("signerKind")
        .and_then(Value::as_str)
        .unwrap_or("keyless");
    if kind == "key" {
        let fp = s.get("keyFingerprint")?.as_str()?.to_string();
        let pem = s.get("keyPem")?.as_str()?.trim().to_string();
        return Some(Authority::Key {
            fingerprint: fp,
            pem,
        });
    }
    let issuer = s.get("issuer")?.as_str()?.to_string();
    let san = s.get("san")?.as_str()?.to_string();
    if issuer == GITHUB_ISSUER {
        // https://github.com/<owner>/<repo>/<path>@refs/tags/<tag>
        if let Some((wf, tag)) = san.split_once("@refs/tags/") {
            if wf.starts_with("https://github.com/") && !tag.is_empty() && !wf.contains('@') {
                return Some(Authority::Keyless {
                    issuer,
                    subject: format!("^{}@refs/tags/.+$", regex_escape(wf)),
                    regexp: true,
                });
            }
        }
    }
    Some(Authority::Keyless {
        issuer,
        subject: san,
        regexp: false,
    })
}

fn signed_by_any(att: &Value, auths: &BTreeSet<Authority>) -> bool {
    authority_of(att).is_some_and(|a| auths.contains(&a))
}

/// Groups running containers into policies. Pure.
pub fn plan(rows: &[RunningImage]) -> Plan {
    struct Seen {
        verdict: Option<String>,
        signers: Vec<Value>,
        attestations: Vec<Value>,
    }
    struct Acc {
        spec_names: BTreeSet<String>,
        digests: BTreeMap<String, Seen>,
        malformed: bool,
    }
    let mut by_repo: BTreeMap<String, Acc> = BTreeMap::new();
    for r in rows {
        let repo = r
            .repository
            .clone()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| strip_ref(&r.image_ref).to_string());
        let acc = by_repo.entry(repo).or_insert_with(|| Acc {
            spec_names: BTreeSet::new(),
            digests: BTreeMap::new(),
            malformed: false,
        });
        if r.image_ref == crate::image_inventory::MALFORMED_REFERENCE {
            // The pod's reference could not be read: no glob can be
            // written for it, and it is never silently left out.
            acc.malformed = true;
        } else {
            acc.spec_names.insert(strip_ref(&r.image_ref).to_string());
        }
        let arr = |v: &Value| v.as_array().cloned().unwrap_or_default();
        acc.digests.insert(
            r.digest.clone(),
            Seen {
                verdict: r.verdict.clone(),
                signers: arr(&r.signers),
                attestations: arr(&r.attestations),
            },
        );
    }

    let mut out = Plan::default();
    let mut groups: BTreeMap<(Vec<Authority>, Vec<String>), Vec<Repo>> = BTreeMap::new();
    'repo: for (repo, acc) in by_repo {
        let mut auths = BTreeSet::new();
        if acc.malformed {
            out.uncovered.insert(
                repo.clone(),
                "a pod's image reference is malformed_reference (not a valid reference)".into(),
            );
            continue 'repo;
        }
        let mut seen: Vec<(Authority, String)> = Vec::new();
        for (
            digest,
            Seen {
                verdict, signers, ..
            },
        ) in &acc.digests
        {
            match verdict.as_deref() {
                Some("verified") => {}
                Some(v) => {
                    out.uncovered
                        .insert(repo.clone(), format!("a running digest is {v}"));
                    continue 'repo;
                }
                None => {
                    out.uncovered
                        .insert(repo.clone(), "a running digest has not been checked".into());
                    continue 'repo;
                }
            }
            let mine: Vec<Authority> = signers.iter().filter_map(authority_of).collect();
            seen.extend(mine.iter().map(|a| (a.clone(), digest.clone())));
            if mine.is_empty() {
                out.uncovered.insert(
                    repo.clone(),
                    "signed only by a key whose public key kguardian was not given".into(),
                );
                continue 'repo;
            }
            auths.extend(mine);
        }
        let mut predicates = Vec::new();
        for p in [SLSA_V1, SLSA_V02] {
            let all = acc.digests.values().all(|d| {
                d.attestations.iter().any(|a| {
                    a.get("predicateType").and_then(Value::as_str) == Some(p)
                        && signed_by_any(a, &auths)
                })
            });
            if all {
                predicates.push(p.to_string());
                break;
            }
        }
        for (a, d) in seen {
            out.evidence.entry(a).or_default().insert((repo.clone(), d));
        }
        groups
            .entry((auths.into_iter().collect(), predicates))
            .or_default()
            .push(Repo {
                repository: repo,
                spec_names: acc.spec_names,
            });
    }
    out.groups = groups
        .into_iter()
        .map(|((authorities, predicates), repositories)| Group {
            repositories,
            authorities,
            predicates,
        })
        .collect();
    out
}

/// Stable DNS-1123 name for a group.
fn group_name(prefix: &str, g: &Group) -> String {
    // FNV-1a over the repositories: stable across builds and Rust
    // versions, so regenerating gives the same names.
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for r in &g.repositories {
        for b in r.repository.bytes().chain(std::iter::once(0)) {
            h ^= u64::from(b);
            h = h.wrapping_mul(0x0100_0000_01b3);
        }
    }
    let hex = format!("{:08x}", h >> 32);
    let base = g
        .repositories
        .first()
        .map(|r| r.repository.rsplit('/').next().unwrap_or("images"))
        .unwrap_or("images");
    let mut n: String = format!("{prefix}-{base}")
        .to_ascii_lowercase()
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' {
                c
            } else {
                '-'
            }
        })
        .collect();
    n.truncate(48);
    let n = n.trim_end_matches('-').to_string();
    format!("{n}-{hex}")
}

fn annotations(extra: &[(&str, String)]) -> Value {
    let mut m = serde_json::Map::new();
    m.insert(
        "kguardian.dev/generated-by".into(),
        json!(format!("kguardian-broker/{}", env!("CARGO_PKG_VERSION"))),
    );
    m.insert(
        "kguardian.dev/source".into(),
        json!("observed verified image signers"),
    );
    for (k, v) in extra {
        m.insert(format!("kguardian.dev/{k}"), json!(v));
    }
    Value::Object(m)
}

/// Options for [`render`].
#[derive(Debug, Clone)]
pub struct Options<'a> {
    pub format: &'a str,
    /// Enforcing variant instead of audit.
    pub enforce: bool,
    pub name_prefix: &'a str,
    /// For `kguardian`: a namespaced ImageTrustPolicy in this namespace;
    /// `None` = ClusterImageTrustPolicy.
    pub namespace: Option<&'a str>,
}

/// Documents (as JSON values, rendered to YAML by the caller) for a plan.
pub fn documents(p: &Plan, o: &Options) -> Vec<Value> {
    let mut docs = Vec::new();
    for g in &p.groups {
        let name = group_name(o.name_prefix, g);
        match o.format {
            "kyverno" => docs.push(kyverno(g, &name, o.enforce)),
            "policy-controller" => docs.extend(policy_controller(g, &name, o.enforce)),
            _ => docs.push(kguardian(g, &name, o.namespace)),
        }
    }
    docs
}

fn kyverno(g: &Group, name: &str, enforce: bool) -> Value {
    // Kyverno matches the image string as the pod spec writes it, so every
    // spelling of the repository must be listed or an image escapes the
    // policy: bare (no tag, i.e. :latest), with any tag, with a digest.
    // "*" crosses "/" in Kyverno globs; the ":" / "@" pin the name.
    let mut names = BTreeSet::new();
    for r in &g.repositories {
        names.extend(spellings(&r.repository));
        names.extend(r.spec_names.iter().cloned());
    }
    let mut globs = Vec::new();
    for n in &names {
        globs.push(json!({"glob": n}));
        globs.push(json!({"glob": format!("{n}:*")}));
        globs.push(json!({"glob": format!("{n}@*")}));
    }
    let mut attestors = Vec::new();
    let mut refs = Vec::new();
    for (i, a) in g.authorities.iter().enumerate() {
        let n = format!("a{i}");
        refs.push(format!("attestors.{n}"));
        let cosign = match a {
            Authority::Keyless {
                issuer,
                subject,
                regexp,
            } => {
                let id = if *regexp {
                    json!({"issuer": issuer, "subjectRegExp": subject})
                } else {
                    json!({"issuer": issuer, "subject": subject})
                };
                json!({"keyless": {"identities": [id]}})
            }
            Authority::Key { pem, .. } => json!({"key": {"data": pem}}),
        };
        attestors.push(json!({"name": n, "cosign": cosign}));
    }
    let list = refs.join(", ");
    let each = |cat: &str, call: &str| {
        format!("!has(images.{cat}) || images.{cat}.map(image, {call}).all(e, e > 0)")
    };
    let mut validations = Vec::new();
    for cat in ["containers", "initContainers", "ephemeralContainers"] {
        validations.push(json!({
            "expression": each(cat, &format!("verifyImageSignatures(image, [{list}])")),
            "message": format!("{cat}: image is not signed by a signer kguardian observed for it"),
        }));
    }
    let mut spec = json!({
        "validationActions": [if enforce { "Deny" } else { "Audit" }],
        "matchConstraints": {"resourceRules": [{
            "apiGroups": [""], "apiVersions": ["v1"],
            "operations": ["CREATE", "UPDATE"], "resources": ["pods"],
        }]},
        "matchImageReferences": globs,
        // Audit never changes a pod: Kyverno's default mutateDigest would
        // rewrite image tags to digests even when only auditing, and
        // verifyDigest would fail every tag reference. Enforce keeps
        // Kyverno's pinning.
        "validationConfigurations": if enforce {
            json!({"mutateDigest": true, "verifyDigest": true})
        } else {
            json!({"mutateDigest": false, "verifyDigest": false})
        },
        "attestors": attestors,
    });
    if !g.predicates.is_empty() {
        let atts: Vec<Value> = g
            .predicates
            .iter()
            .enumerate()
            .map(|(i, p)| json!({"name": format!("p{i}"), "intoto": {"type": p}}))
            .collect();
        for i in 0..atts.len() {
            for cat in ["containers", "initContainers", "ephemeralContainers"] {
                validations.push(json!({
                    "expression": each(cat, &format!("verifyAttestationSignatures(image, attestations.p{i}, [{list}])")),
                    "message": format!("{cat}: required attestation {} is missing or not signed by an observed signer", g.predicates[i]),
                }));
            }
        }
        spec["attestations"] = Value::Array(atts);
    }
    spec["validations"] = Value::Array(validations);
    json!({
        "apiVersion": "policies.kyverno.io/v1beta1",
        "kind": "ImageValidatingPolicy",
        "metadata": {"name": name, "annotations": annotations(&[])},
        "spec": spec,
    })
}

/// Every way a pod spec can name `repository` (normalised, as the
/// inventory stores it). Docker Hub has several: `nginx`, `library/nginx`,
/// `docker.io/nginx`, `docker.io/library/nginx` and
/// `index.docker.io/library/nginx` all pull the same image.
pub fn spellings(repository: &str) -> Vec<String> {
    let hub = repository
        .strip_prefix("docker.io/")
        .or_else(|| repository.strip_prefix("index.docker.io/"));
    let Some(path) = hub else {
        return vec![repository.to_string()];
    };
    let mut out = vec![
        path.to_string(),
        format!("docker.io/{path}"),
        format!("index.docker.io/{path}"),
    ];
    if let Some(short) = path.strip_prefix("library/") {
        out.push(short.to_string());
        out.push(format!("docker.io/{short}"));
        out.push(format!("index.docker.io/{short}"));
    }
    out
}

/// policy-controller's name for a repository: Docker Hub is
/// `index.docker.io`.
fn pc_repo(r: &str) -> String {
    match r.strip_prefix("docker.io/") {
        Some(rest) => format!("index.docker.io/{rest}"),
        None => r.to_string(),
    }
}

fn pc_authorities(g: &Group, predicates: &[String]) -> Vec<Value> {
    g.authorities
        .iter()
        .enumerate()
        .map(|(i, a)| {
            let mut v = match a {
                Authority::Keyless {
                    issuer,
                    subject,
                    regexp,
                } => {
                    let id = if *regexp {
                        json!({"issuer": issuer, "subjectRegExp": subject})
                    } else {
                        json!({"issuer": issuer, "subject": subject})
                    };
                    json!({"name": format!("a{i}"), "keyless": {"identities": [id]}})
                }
                Authority::Key { pem, .. } => {
                    json!({"name": format!("a{i}"), "key": {"data": pem}})
                }
            };
            if !predicates.is_empty() {
                v["attestations"] = Value::Array(
                    predicates
                        .iter()
                        .enumerate()
                        .map(|(j, p)| json!({"name": format!("p{j}"), "predicateType": p}))
                        .collect(),
                );
            }
            v
        })
        .collect()
}

fn policy_controller(g: &Group, name: &str, enforce: bool) -> Vec<Value> {
    let mut images = Vec::new();
    for r in &g.repositories {
        let n = pc_repo(&r.repository);
        // ":**" / "@**": any tag or digest ("*" alone stops at "/").
        images.push(json!({"glob": format!("{n}:**")}));
        images.push(json!({"glob": format!("{n}@**")}));
    }
    let mode = if enforce { "enforce" } else { "warn" };
    let mut out = vec![json!({
        "apiVersion": "policy.sigstore.dev/v1beta1",
        "kind": "ClusterImagePolicy",
        "metadata": {"name": name, "annotations": annotations(&[])},
        "spec": {"mode": mode, "images": images.clone(), "authorities": pc_authorities(g, &[])},
    })];
    if !g.predicates.is_empty() {
        // An authority with attestations checks only attestations, and
        // every matching policy must pass: a second policy adds the
        // requirement without dropping the signature check.
        out.push(json!({
            "apiVersion": "policy.sigstore.dev/v1beta1",
            "kind": "ClusterImagePolicy",
            "metadata": {"name": format!("{name}-provenance"), "annotations": annotations(&[])},
            "spec": {"mode": mode, "images": images, "authorities": pc_authorities(g, &g.predicates)},
        }));
    }
    out
}

fn kguardian(g: &Group, name: &str, namespace: Option<&str>) -> Value {
    let images: Vec<Value> = g.repositories.iter().map(|r| json!(r.repository)).collect();
    let authorities: Vec<Value> = g
        .authorities
        .iter()
        .enumerate()
        .map(|(i, a)| match a {
            Authority::Keyless {
                issuer,
                subject,
                regexp,
            } => {
                let id = if *regexp {
                    json!({"issuer": issuer, "subjectRegExp": subject})
                } else {
                    json!({"issuer": issuer, "subject": subject})
                };
                json!({"name": format!("a{i}"), "keyless": id})
            }
            Authority::Key { pem, .. } => {
                json!({"name": format!("a{i}"), "key": {"publicKey": pem}})
            }
        })
        .collect();
    let mut spec = json!({"images": images, "authorities": authorities});
    if !g.predicates.is_empty() {
        spec["attestations"] = Value::Array(
            g.predicates
                .iter()
                .map(|p| json!({"predicateType": p}))
                .collect(),
        );
    }
    let mut meta = json!({"name": name, "annotations": annotations(&[])});
    let kind = match namespace {
        Some(ns) => {
            meta["namespace"] = json!(ns);
            "ImageTrustPolicy"
        }
        None => "ClusterImageTrustPolicy",
    };
    json!({"apiVersion": "kguardian.dev/v1alpha1", "kind": kind, "metadata": meta, "spec": spec})
}

/// The header every rendering starts with.
pub fn header(p: &Plan, o: &Options, scope: &str) -> String {
    let what = match (o.format, o.enforce) {
        ("kyverno", false) => "Kyverno ImageValidatingPolicy, validationActions [Audit] (failures go to policy reports)",
        ("kyverno", true) => "Kyverno ImageValidatingPolicy, validationActions [Deny]",
        ("policy-controller", false) => "Sigstore policy-controller ClusterImagePolicy, mode warn (admits and warns; policy-controller has no audit-only mode)",
        ("policy-controller", true) => "Sigstore policy-controller ClusterImagePolicy, mode enforce",
        _ => "kguardian ImageTrustPolicy (report only, evaluated by the kguardian evaluator)",
    };
    let scope = comment(scope);
    let mut h = format!(
        "# kguardian image admission policy for {scope}\n\
         # {what}\n\
         # Generated from the signers kguardian verified on running images. kguardian never applies\n\
         # anything: review, commit and apply it yourself.\n"
    );
    if o.format == "policy-controller" {
        h.push_str("# policy-controller only checks namespaces labelled policy.sigstore.dev/include=true.\n");
    }
    if p.groups.is_empty() {
        h.push_str("# No repository qualifies: none has every running digest signed by a signer kguardian verified.\n");
    }
    if !p.evidence.is_empty() {
        h.push_str("# REVIEW EVERY IDENTITY BEFORE APPLYING: identities were observed on running images, not vetted.\n");
        h.push_str("# A signer that signed an image you run is trusted by this policy for every image it covers.\n");
        for (a, seen) in &p.evidence {
            h.push_str(&format!("# identity: {}\n", comment(&describe(a))));
            for (repo, digest) in seen {
                h.push_str(&format!(
                    "#   verified {}@{}\n",
                    comment(repo),
                    comment(digest)
                ));
            }
        }
    }
    for (repo, why) in &p.uncovered {
        h.push_str(&format!(
            "# not covered: {} ({})\n",
            comment(repo),
            comment(why)
        ));
    }
    h
}

/// One line describing a trusted identity.
pub fn describe(a: &Authority) -> String {
    match a {
        Authority::Keyless {
            issuer,
            subject,
            regexp: false,
        } => format!("keyless issuer={issuer} subject={subject}"),
        Authority::Keyless {
            issuer,
            subject,
            regexp: true,
        } => {
            format!("keyless issuer={issuer} subjectRegExp={subject} (widened from observed tag subjects)")
        }
        Authority::Key { fingerprint, .. } => format!("key sha256:{fingerprint}"),
    }
}

/// Text for inside one comment line: the shared export helper, so every
/// generated comment is escaped one way.
pub fn comment(s: &str) -> String {
    crate::profile_export::comment_text(s)
}

/// Renders a plan to a multi-document YAML stream.
pub fn render(p: &Plan, o: &Options, scope: &str) -> Result<String, serde_norway::Error> {
    // No "---" before the first document: some tools (policy-controller's
    // tester) read the comment-only preamble as an empty first document.
    let mut y = header(p, o, scope);
    for (i, d) in documents(p, o).iter().enumerate() {
        if i > 0 {
            y.push_str("---\n");
        }
        y.push_str(&serde_norway::to_string(d)?);
    }
    Ok(y)
}

// ---------------------------------------------------------------------
// GET /attestations/policy
// ---------------------------------------------------------------------

/// Running containers read for one generation. Beyond this the request is
/// refused (narrow it with `?namespace=`): a policy from part of the
/// cluster would silently leave the rest out.
pub const MAX_POLICY_ROWS: i64 = 5_000;
const PAGE: i64 = 1_000;

type DbPool = diesel::r2d2::Pool<diesel::r2d2::ConnectionManager<diesel::pg::PgConnection>>;
type DbError = Box<dyn std::error::Error + Send + Sync>;

/// Every running container of the scope, or `None` past
/// [`MAX_POLICY_ROWS`].
pub fn load_rows(
    conn: &mut diesel::pg::PgConnection,
    namespace: Option<&str>,
    workload: Option<(&str, &str)>,
) -> Result<Option<Vec<RunningImage>>, DbError> {
    let mut rows = Vec::new();
    let mut after: Option<[String; 6]> = None;
    loop {
        let page =
            crate::attestation::running_filtered(conn, namespace, workload, after.as_ref(), PAGE)?;
        rows.extend(page.items);
        if rows.len() as i64 > MAX_POLICY_ROWS {
            return Ok(None);
        }
        match page
            .next_after
            .and_then(|c| crate::attestation::decode_cursor(&c))
        {
            Some(c) => after = Some(c),
            None => return Ok(Some(rows)),
        }
    }
}

#[derive(Debug, serde::Deserialize)]
pub struct PolicyQuery {
    pub format: Option<String>,
    pub mode: Option<String>,
    pub namespace: Option<String>,
    #[serde(rename = "acknowledgePartial")]
    pub acknowledge_partial: Option<String>,
}

fn truthy(v: Option<&str>) -> bool {
    matches!(
        v.map(|s| s.trim().to_ascii_lowercase()).as_deref(),
        Some("true" | "1" | "yes" | "on")
    )
}

#[actix_web::get(
    "/attestations/policy",
    wrap = "::actix_web::middleware::from_fn(crate::auth::authorize)"
)]
pub async fn get_attestation_policy(
    pool: actix_web::web::Data<DbPool>,
    budget: actix_web::web::Data<crate::read_budget::ReadBudget>,
    query: actix_web::web::Query<PolicyQuery>,
) -> actix_web::Result<actix_web::HttpResponse> {
    use actix_web::HttpResponse;
    let q = query.into_inner();
    let format = q
        .format
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("kyverno")
        .to_string();
    if !FORMATS.contains(&format.as_str()) {
        return Ok(HttpResponse::BadRequest().body(format!("format must be one of {FORMATS:?}")));
    }
    let enforce = match q.mode.as_deref().map(str::trim).unwrap_or("audit") {
        "" | "audit" => false,
        "enforce" => true,
        _ => return Ok(HttpResponse::BadRequest().body("mode must be audit or enforce")),
    };
    if enforce && format == "kguardian" {
        return Ok(HttpResponse::BadRequest().body(
            "the kguardian format is report-only; use kyverno or policy-controller for enforce",
        ));
    }
    let namespace = q
        .namespace
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let ack = truthy(q.acknowledge_partial.as_deref());
    // Charged at the worst case (every row as large as one stored result),
    // which is more than any budget: the budget clamps it to the whole, so
    // a generation runs alone and other reads wait or shed meanwhile.
    // Generation is an occasional operator action; real rows are far
    // smaller, but the charge is not allowed to under-count.
    let _permit = match budget
        .acquire(crate::read_budget::cost_kib(
            MAX_POLICY_ROWS,
            crate::attestation::RUNNING_ROW_COST_BYTES,
        ))
        .await
    {
        Ok(p) => p,
        Err(shed) => return Ok(shed.into_response()),
    };
    let ns = namespace.clone();
    let rows = actix_web::web::block(move || {
        let mut conn = pool.get()?;
        load_rows(&mut conn, ns.as_deref(), None)
    })
    .await?
    .map_err(actix_web::error::ErrorInternalServerError)?;
    let Some(rows) = rows else {
        return Ok(HttpResponse::UnprocessableEntity().body(format!(
            "more than {MAX_POLICY_ROWS} running containers; generate per namespace with ?namespace="
        )));
    };
    let p = plan(&rows);
    if enforce && !p.uncovered.is_empty() && !ack {
        let list: Vec<String> = p
            .uncovered
            .iter()
            .map(|(r, w)| format!("{r} ({w})"))
            .collect();
        return Ok(HttpResponse::Conflict().body(format!(
            "an enforcing policy would not cover every running image: {}. Resolve them, or pass acknowledgePartial=true to generate for the rest.",
            list.join("; ")
        )));
    }
    let scope = match &namespace {
        Some(ns) => format!("namespace {ns}"),
        None => "the cluster".to_string(),
    };
    let o = Options {
        format: &format,
        enforce,
        name_prefix: "kguardian-signed",
        namespace: namespace.as_deref(),
    };
    let y = render(&p, &o, &scope).map_err(actix_web::error::ErrorInternalServerError)?;
    Ok(HttpResponse::Ok().content_type("application/yaml").body(y))
}

#[cfg(test)]
#[path = "admission_tests.rs"]
mod tests;
