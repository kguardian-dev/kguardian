use super::*;
use crate::attestation::RunningImage;
use serde::Deserialize;
use serde_json::json;
use std::collections::BTreeSet;

const PEM: &str = "-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAErBclBIBz28Uo7W6PFzioZ8s5BVr2
EYJgLPCfyhpM7+6uFQCC2ImZ9FKVx4+CV1qtW4tSBa49kJwn4pedaEd69A==
-----END PUBLIC KEY-----"; // supplychain/pkg/attest/testdata/cosign.pub
const FP: &str = "e2312c28209f4778ffc6c0ca2786638bb86d6027ee8092aba67c5d94d268ee30";
const GH: &str = "https://token.actions.githubusercontent.com";
const K8S_SAN: &str = "krel-trust@k8s-releng-prod.iam.gserviceaccount.com";

#[allow(clippy::too_many_arguments)]
fn row(
    ns: &str,
    name: &str,
    digest: u32,
    image_ref: &str,
    repo: Option<&str>,
    verdict: Option<&str>,
    signers: Value,
    atts: Value,
) -> RunningImage {
    RunningImage {
        cluster_id: "primary".into(),
        namespace: ns.into(),
        workload_kind: "Deployment".into(),
        workload_name: name.into(),
        container: "app".into(),
        digest: format!("sha256:{digest:064x}"),
        image_ref: image_ref.into(),
        repository: repo.map(Into::into),
        verdict: verdict.map(Into::into),
        reason: None,
        checked_at: None,
        signers,
        attestations: atts,
    }
}

fn keyless(issuer: &str, san: &str) -> Value {
    json!({"signerKind": "keyless", "issuer": issuer, "san": san, "verified": true})
}

fn key() -> Value {
    json!({"signerKind": "key", "keyName": "release", "keyFingerprint": FP, "keyPem": PEM, "verified": true})
}

fn fixtures() -> Vec<RunningImage> {
    vec![
        // keyless (Kubernetes release identity), referenced unqualified.
        row(
            "shop",
            "pause",
            1,
            "registry.k8s.io/pause:3.10",
            Some("registry.k8s.io/pause"),
            Some("verified"),
            json!([keyless("https://accounts.google.com", K8S_SAN)]),
            json!([]),
        ),
        // key-signed, verified with the configured key.
        row(
            "shop",
            "keyed",
            2,
            "ghcr.io/example/keyed:1",
            Some("ghcr.io/example/keyed"),
            Some("verified"),
            json!([key()]),
            json!([]),
        ),
        // unsigned, invalid, key_signed (key not held), not checked.
        row(
            "shop",
            "unsigned",
            3,
            "ghcr.io/example/unsigned:1",
            Some("ghcr.io/example/unsigned"),
            Some("unsigned"),
            json!([]),
            json!([]),
        ),
        row(
            "shop",
            "tampered",
            4,
            "ghcr.io/example/tampered:1",
            Some("ghcr.io/example/tampered"),
            Some("invalid"),
            json!([]),
            json!([]),
        ),
        row(
            "shop",
            "otherkey",
            5,
            "ghcr.io/example/otherkey:1",
            Some("ghcr.io/example/otherkey"),
            Some("key_signed"),
            json!([]),
            json!([]),
        ),
        row(
            "shop",
            "new",
            6,
            "docker.io/library/nginx:1.27",
            Some("docker.io/library/nginx"),
            None,
            json!([]),
            json!([]),
        ),
    ]
}

#[test]
fn plan_covers_only_fully_verified_repositories() {
    let p = plan(&fixtures());
    let mut covered: Vec<&str> = p
        .groups
        .iter()
        .flat_map(|g| g.repositories.iter().map(|r| r.repository.as_str()))
        .collect();
    covered.sort();
    assert_eq!(
        covered,
        vec!["ghcr.io/example/keyed", "registry.k8s.io/pause"]
    );
    assert_eq!(p.uncovered.len(), 4);
    assert_eq!(
        p.uncovered["ghcr.io/example/unsigned"],
        "a running digest is unsigned"
    );
    assert_eq!(
        p.uncovered["ghcr.io/example/tampered"],
        "a running digest is invalid"
    );
    assert_eq!(
        p.uncovered["ghcr.io/example/otherkey"],
        "a running digest is key_signed"
    );
    assert_eq!(
        p.uncovered["docker.io/library/nginx"],
        "a running digest has not been checked"
    );
}

#[test]
fn one_unsigned_digest_uncovers_the_repository() {
    let mut rows = fixtures()[..1].to_vec();
    rows.push(row(
        "shop",
        "pause2",
        9,
        "registry.k8s.io/pause:3.9",
        Some("registry.k8s.io/pause"),
        Some("unsigned"),
        json!([]),
        json!([]),
    ));
    let p = plan(&rows);
    assert!(p.groups.is_empty());
    assert!(p.uncovered.contains_key("registry.k8s.io/pause"));
}

#[test]
fn key_signer_without_pem_is_not_expressible() {
    let mut k = key();
    k.as_object_mut().unwrap().remove("keyPem");
    let p = plan(&[row(
        "a",
        "b",
        1,
        "r/x:1",
        Some("r/x"),
        Some("verified"),
        json!([k]),
        json!([]),
    )]);
    assert!(p.groups.is_empty());
    assert!(p.uncovered["r/x"].contains("public key"));
}

#[test]
fn github_tag_subjects_widen_to_any_tag_only() {
    let tag = authority_of(&keyless(
        GH,
        "https://github.com/example/api/.github/workflows/release.yaml@refs/tags/v1.2.3",
    ))
    .unwrap();
    assert_eq!(
        tag,
        Authority::Keyless {
            issuer: GH.into(),
            subject:
                r"^https://github\.com/example/api/\.github/workflows/release\.yaml@refs/tags/.+$"
                    .into(),
            regexp: true
        }
    );
    // A branch build stays exact; so does another issuer.
    let branch = authority_of(&keyless(
        GH,
        "https://github.com/example/api/.github/workflows/ci.yaml@refs/heads/main",
    ))
    .unwrap();
    assert!(matches!(branch, Authority::Keyless { regexp: false, .. }));
    let google = authority_of(&keyless("https://accounts.google.com", K8S_SAN)).unwrap();
    assert!(matches!(google, Authority::Keyless { regexp: false, .. }));
    // Two releases of one workflow are one authority.
    let rows = vec![
        row(
            "a",
            "x",
            1,
            "ghcr.io/example/api:1.2.3",
            Some("ghcr.io/example/api"),
            Some("verified"),
            json!([keyless(
                GH,
                "https://github.com/example/api/.github/workflows/release.yaml@refs/tags/v1.2.3"
            )]),
            json!([]),
        ),
        row(
            "a",
            "y",
            2,
            "ghcr.io/example/api:1.2.4",
            Some("ghcr.io/example/api"),
            Some("verified"),
            json!([keyless(
                GH,
                "https://github.com/example/api/.github/workflows/release.yaml@refs/tags/v1.2.4"
            )]),
            json!([]),
        ),
    ];
    let p = plan(&rows);
    assert_eq!(p.groups.len(), 1);
    assert_eq!(p.groups[0].authorities.len(), 1);
}

fn slsa(signer: Value) -> Value {
    let mut a = signer;
    a["predicateType"] = json!("https://slsa.dev/provenance/v1");
    a
}

#[test]
fn provenance_required_only_when_every_digest_has_it_from_an_authority() {
    let s = keyless(
        GH,
        "https://github.com/example/api/.github/workflows/release.yaml@refs/tags/v1",
    );
    let r1 = row(
        "a",
        "x",
        1,
        "ghcr.io/example/api:1",
        Some("ghcr.io/example/api"),
        Some("verified"),
        json!([s.clone()]),
        json!([slsa(s.clone())]),
    );
    let mut r2 = r1.clone();
    r2.digest = format!("sha256:{:064x}", 2);
    assert_eq!(
        plan(&[r1.clone(), r2.clone()]).groups[0].predicates,
        vec![SLSA_V1.to_string()]
    );
    // One digest without provenance: not required.
    r2.attestations = json!([]);
    assert!(plan(&[r1.clone(), r2.clone()]).groups[0]
        .predicates
        .is_empty());
    // Provenance signed by someone else: not required.
    r2.attestations = json!([slsa(keyless(
        GH,
        "https://github.com/attacker/x/.github/workflows/y@refs/heads/main"
    ))]);
    assert!(plan(&[r1, r2]).groups[0].predicates.is_empty());
}

fn docs(format: &str, enforce: bool) -> Vec<Value> {
    let p = plan(&fixtures());
    let o = Options {
        format,
        enforce,
        name_prefix: "kguardian-signed",
        namespace: Some("shop"),
    };
    let y = render(&p, &o, "namespace shop").unwrap();
    // The comment preamble is part of the first document.
    y.split("\n---\n")
        .map(|d| serde_norway::from_str::<Value>(d).unwrap())
        .collect()
}

#[test]
fn kyverno_audit_policy() {
    let d = docs("kyverno", false);
    assert_eq!(d.len(), 2);
    let pause = d
        .iter()
        .find(|x| x["spec"]["matchImageReferences"][0]["glob"] == "registry.k8s.io/pause")
        .unwrap();
    assert_eq!(pause["apiVersion"], "policies.kyverno.io/v1beta1");
    assert_eq!(pause["kind"], "ImageValidatingPolicy");
    assert_eq!(pause["spec"]["validationActions"], json!(["Audit"]));
    assert_eq!(
        pause["spec"]["validationConfigurations"],
        json!({"mutateDigest": false, "verifyDigest": false})
    );
    let globs: Vec<&str> = pause["spec"]["matchImageReferences"]
        .as_array()
        .unwrap()
        .iter()
        .map(|g| g["glob"].as_str().unwrap())
        .collect();
    assert_eq!(
        globs,
        vec![
            "registry.k8s.io/pause",
            "registry.k8s.io/pause:*",
            "registry.k8s.io/pause@*"
        ]
    );
    assert_eq!(
        pause["spec"]["attestors"][0]["cosign"]["keyless"]["identities"][0],
        json!({"issuer": "https://accounts.google.com", "subject": K8S_SAN})
    );
    let v = pause["spec"]["validations"].as_array().unwrap();
    assert_eq!(v.len(), 3);
    assert_eq!(
        v[0]["expression"],
        "!has(images.containers) || images.containers.map(image, verifyImageSignatures(image, [attestors.a0])).all(e, e > 0)"
    );
    let keyed = d
        .iter()
        .find(|x| x["spec"]["matchImageReferences"][0]["glob"] == "ghcr.io/example/keyed")
        .unwrap();
    assert_eq!(keyed["spec"]["attestors"][0]["cosign"]["key"]["data"], PEM);
    let enf = docs("kyverno", true);
    assert_eq!(enf[0]["spec"]["validationActions"], json!(["Deny"]));
    assert_eq!(
        enf[0]["spec"]["validationConfigurations"]["mutateDigest"],
        true
    );
}

#[test]
fn policy_controller_warn_policy_and_provenance_split() {
    let d = docs("policy-controller", false);
    assert_eq!(d.len(), 2);
    for x in &d {
        assert_eq!(x["apiVersion"], "policy.sigstore.dev/v1beta1");
        assert_eq!(x["spec"]["mode"], "warn");
    }
    let s = keyless(
        GH,
        "https://github.com/example/api/.github/workflows/release.yaml@refs/tags/v1",
    );
    let rows = vec![row(
        "a",
        "x",
        1,
        "nginx:1",
        Some("docker.io/library/nginx"),
        Some("verified"),
        json!([s.clone()]),
        json!([slsa(s)]),
    )];
    let o = Options {
        format: "policy-controller",
        enforce: true,
        name_prefix: "p",
        namespace: None,
    };
    let docs = documents(&plan(&rows), &o);
    assert_eq!(docs.len(), 2, "signatures + provenance policies");
    assert_eq!(docs[0]["spec"]["mode"], "enforce");
    assert_eq!(
        docs[0]["spec"]["images"][0]["glob"],
        "index.docker.io/library/nginx:**"
    );
    assert!(docs[0]["spec"]["authorities"][0]
        .get("attestations")
        .is_none());
    assert_eq!(
        docs[1]["spec"]["authorities"][0]["attestations"][0]["predicateType"],
        SLSA_V1
    );
    assert!(docs[1]["metadata"]["name"]
        .as_str()
        .unwrap()
        .ends_with("-provenance"));
    // Kyverno keeps the spec name as pods write it.
    let k = documents(
        &plan(&rows),
        &Options {
            format: "kyverno",
            ..o.clone()
        },
    );
    // Every Docker Hub spelling, bare, tagged and by digest.
    let globs: BTreeSet<&str> = k[0]["spec"]["matchImageReferences"]
        .as_array()
        .unwrap()
        .iter()
        .map(|g| g["glob"].as_str().unwrap())
        .collect();
    for n in [
        "nginx",
        "library/nginx",
        "docker.io/nginx",
        "docker.io/library/nginx",
        "index.docker.io/library/nginx",
        "index.docker.io/nginx",
    ] {
        for g in [n.to_string(), format!("{n}:*"), format!("{n}@*")] {
            assert!(globs.contains(g.as_str()), "missing {g}");
        }
    }
    assert_eq!(k[0]["spec"]["attestations"][0]["intoto"]["type"], SLSA_V1);
    assert_eq!(k[0]["spec"]["validations"].as_array().unwrap().len(), 6);
}

#[test]
fn kguardian_policy() {
    let d = docs("kguardian", false);
    assert_eq!(d[0]["kind"], "ImageTrustPolicy");
    assert_eq!(d[0]["metadata"]["namespace"], "shop");
    let all: Vec<&Value> = d
        .iter()
        .flat_map(|x| x["spec"]["authorities"].as_array().unwrap())
        .collect();
    assert!(all.iter().any(|a| a["key"]["publicKey"] == PEM));
    assert!(all.iter().any(|a| a["keyless"]["subject"] == K8S_SAN));
    let o = Options {
        format: "kguardian",
        enforce: false,
        name_prefix: "k",
        namespace: None,
    };
    assert_eq!(
        documents(&plan(&fixtures()), &o)[0]["kind"],
        "ClusterImageTrustPolicy"
    );
}

#[test]
fn header_lists_what_is_not_covered_and_names_are_stable() {
    let p = plan(&fixtures());
    let o = Options {
        format: "kyverno",
        enforce: false,
        name_prefix: "kguardian-signed",
        namespace: None,
    };
    let y = render(&p, &o, "the cluster").unwrap();
    assert!(y.contains("# not covered: ghcr.io/example/unsigned (a running digest is unsigned)"));
    assert!(y.contains("validationActions [Audit]"));
    assert_eq!(y, render(&plan(&fixtures()), &o, "the cluster").unwrap());
    for d in documents(&p, &o) {
        let n = d["metadata"]["name"].as_str().unwrap();
        assert!(
            n.len() <= 63
                && n.chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'),
            "{n}"
        );
    }
    let empty = render(&plan(&fixtures()[2..3]), &o, "x").unwrap();
    assert!(empty.contains("No repository qualifies") && !empty.contains("---"));
    // The first line after the preamble is the first document.
    assert!(y
        .lines()
        .find(|l| !l.starts_with('#'))
        .unwrap()
        .starts_with("apiVersion"));
}

#[test]
fn strip_ref_keeps_registry_ports() {
    assert_eq!(strip_ref("nginx:1.27"), "nginx");
    assert_eq!(strip_ref("localhost:5000/app:1"), "localhost:5000/app");
    assert_eq!(strip_ref("localhost:5000/app"), "localhost:5000/app");
    assert_eq!(strip_ref("ghcr.io/a/b:1@sha256:abc"), "ghcr.io/a/b");
    assert_eq!(strip_ref("ghcr.io/a/b@sha256:abc"), "ghcr.io/a/b");
}

#[test]
#[ignore = "requires a live postgres (set KG_TEST_DATABASE_URL)"]
fn live_load_rows_scopes_to_the_workload() {
    use diesel::connection::SimpleConnection;
    use diesel::prelude::*;
    use diesel_migrations::MigrationHarness;
    const M: diesel_migrations::EmbeddedMigrations =
        diesel_migrations::embed_migrations!("./db/migrations");
    let url = std::env::var("KG_TEST_DATABASE_URL").expect("set KG_TEST_DATABASE_URL");
    let mut conn = diesel::pg::PgConnection::establish(&url).unwrap();
    conn.run_pending_migrations(M).unwrap();
    conn.batch_execute("TRUNCATE images, workload_containers, image_attestations")
        .unwrap();
    let d1 = format!("sha256:{:064x}", 71);
    let d2 = format!("sha256:{:064x}", 72);
    conn.batch_execute(&format!(
        "INSERT INTO images (digest, repository, digest_kind) VALUES ('{d1}', 'ghcr.io/example/api', 'repo'), ('{d2}', 'ghcr.io/example/other', 'repo');
         INSERT INTO workload_containers (pod_namespace, workload_kind, workload_name, container_name, image_digest, container_kind, image_ref, state) VALUES
           ('shop', 'Deployment', 'api', 'app', '{d1}', 'regular', 'ghcr.io/example/api:1', 'running'),
           ('shop', 'Deployment', 'other', 'app', '{d2}', 'regular', 'ghcr.io/example/other:1', 'running');
         INSERT INTO image_attestations (digest, repository, verdict, signatures, attestations, checked_at) VALUES
           ('{d1}', 'ghcr.io/example/api', 'verified',
            '[{{\"verified\": true, \"signerKind\": \"keyless\", \"issuer\": \"{GH}\", \"san\": \"https://github.com/example/api/.github/workflows/release.yaml@refs/tags/v1\"}}]', '[]', timezone('UTC', NOW()));"
    ))
    .unwrap();
    let rows = load_rows(&mut conn, Some("shop"), Some(("Deployment", "api")))
        .unwrap()
        .unwrap();
    assert_eq!(rows.len(), 1);
    let p = plan(&rows);
    assert_eq!(p.groups.len(), 1);
    assert!(p.uncovered.is_empty());
    let all = load_rows(&mut conn, Some("shop"), None).unwrap().unwrap();
    assert_eq!(all.len(), 2);
    assert_eq!(
        plan(&all).uncovered["ghcr.io/example/other"],
        "a running digest has not been checked"
    );
}

/// Glob semantics of Kyverno's matchImageReferences (gobwas glob, no
/// separators: "*" matches any run of characters), to check what the
/// generated globs select.
fn kyverno_glob(pattern: &str, image: &str) -> bool {
    fn m(p: &[u8], s: &[u8]) -> bool {
        match (p.first(), s.first()) {
            (None, None) => true,
            (Some(b'*'), _) => m(&p[1..], s) || (!s.is_empty() && m(p, &s[1..])),
            (Some(a), Some(b)) if a == b => m(&p[1..], &s[1..]),
            _ => false,
        }
    }
    m(pattern.as_bytes(), image.as_bytes())
}

/// Every way a pod can reference an observed image is matched: a tagless
/// reference, a digest, and a docker.io/library form of an image observed
/// by its short name.
#[test]
fn kyverno_globs_match_every_spelling() {
    let rows = vec![row(
        "a",
        "x",
        1,
        "nginx:1.27",
        Some("docker.io/library/nginx"),
        Some("verified"),
        json!([keyless("https://accounts.google.com", K8S_SAN)]),
        json!([]),
    )];
    let o = Options {
        format: "kyverno",
        enforce: true,
        name_prefix: "p",
        namespace: None,
    };
    let d = documents(&plan(&rows), &o);
    let globs: Vec<String> = d[0]["spec"]["matchImageReferences"]
        .as_array()
        .unwrap()
        .iter()
        .map(|g| g["glob"].as_str().unwrap().to_string())
        .collect();
    let matched = |img: &str| globs.iter().any(|g| kyverno_glob(g, img));
    for img in [
        "nginx",
        "nginx:1.28",
        "nginx@sha256:abc",
        "library/nginx:1.27",
        "docker.io/nginx",
        "docker.io/library/nginx:1.27",
        "docker.io/library/nginx@sha256:abc",
        "index.docker.io/library/nginx:latest",
    ] {
        assert!(matched(img), "{img} escapes the policy");
    }
    for img in ["nginx-exporter:1", "evil/nginx:1", "ghcr.io/nginx:1"] {
        assert!(!matched(img), "{img} wrongly selected");
    }
    // A non-Docker Hub repository has one spelling.
    assert_eq!(
        spellings("ghcr.io/example/api"),
        vec!["ghcr.io/example/api"]
    );
}

/// D3: every trusted identity is listed with the images and digests it was
/// seen verifying, under a review warning.
#[test]
fn header_lists_every_identity_with_its_evidence() {
    let p = plan(&fixtures());
    let o = Options {
        format: "kyverno",
        enforce: false,
        name_prefix: "k",
        namespace: None,
    };
    let y = render(&p, &o, "the cluster").unwrap();
    assert!(y.contains("# REVIEW EVERY IDENTITY BEFORE APPLYING: identities were observed on running images, not vetted."));
    assert!(y.contains(&format!(
        "# identity: keyless issuer=https://accounts.google.com subject={K8S_SAN}"
    )));
    assert!(y.contains(&format!(
        "#   verified registry.k8s.io/pause@sha256:{:064x}",
        1
    )));
    assert!(y.contains(&format!("# identity: key sha256:{FP}")));
    assert!(y.contains(&format!(
        "#   verified ghcr.io/example/keyed@sha256:{:064x}",
        2
    )));
    // Nothing trusted, no identity section.
    let none = render(&plan(&fixtures()[2..3]), &o, "x").unwrap();
    assert!(!none.contains("REVIEW EVERY IDENTITY"));
}

/// Values that reach header comments (repository names, scope, reasons)
/// cannot start a line: whatever the separator, the stream decodes to the
/// generated policies only, never an injected object.
#[test]
fn comments_cannot_inject_documents() {
    for sep in ["\n", "\r", "\r\n", "\u{0085}", "\u{2028}", "\u{2029}"] {
        let inj = format!(
            "evil{sep}---{sep}apiVersion: v1{sep}kind: Secret{sep}metadata:{sep}  name: pwned{sep}#"
        );
        let mut rows = fixtures();
        // An uncovered repository and a covered one carry the payload.
        rows[2].repository = Some(inj.clone());
        rows[0].repository = Some(format!("registry.k8s.io/{inj}"));
        let p = plan(&rows);
        for format in ["kyverno", "policy-controller", "kguardian"] {
            let o = Options {
                format,
                enforce: false,
                name_prefix: "k",
                namespace: Some("shop"),
            };
            let y = render(&p, &o, &format!("namespace {inj}")).unwrap();
            let want: Vec<String> = documents(&p, &o)
                .iter()
                .map(|d| d["kind"].as_str().unwrap().to_string())
                .collect();
            let mut got = Vec::new();
            for doc in serde_norway::Deserializer::from_str(&y) {
                let v = Value::deserialize(doc).unwrap();
                if let Some(k) = v.get("kind").and_then(Value::as_str) {
                    got.push(k.to_string());
                }
            }
            assert_eq!(got, want, "{format} {sep:?}: decoded kinds");
            // No comment line carries a line break of any kind.
            for line in y.split('\n').filter(|l| l.starts_with('#')) {
                assert!(
                    !line.contains(['\r', '\u{0085}', '\u{2028}', '\u{2029}']),
                    "{format} {sep:?}: separator in comment {line:?}"
                );
            }
        }
    }
}
