use super::*;
use chrono::TimeZone;
use serde_json::json;

fn d(i: u32) -> String {
    format!("sha256:{:064x}", i)
}

fn now() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 9, 27, 12, 0, 0).unwrap()
}

fn body(digest: &str, verdict: &str) -> serde_json::Value {
    json!({
        "schema_version": 1,
        "digest": digest,
        "repository": "ghcr.io/example/api",
        "checked_at": "2026-09-27T11:59:00Z",
        "verdict": verdict,
        "trust_root": "public-good",
        "signed_via": "self",
        "signed_digest": digest,
        "signatures": [
            {"format": "cosign-bundle", "source": "referrers", "verified": true,
             "signer_kind": "keyless",
             "issuer": "https://token.actions.githubusercontent.com",
             "san": "https://github.com/example/api/.github/workflows/release.yaml@refs/tags/v1.0.0",
             "integrated_time": "2026-09-01T00:00:00Z", "tlog_index": 42},
            {"format": "cosign-legacy", "source": "sig-tag", "verified": false,
             "error": "untrusted_key", "detail": "signed with a public key; no keys are configured",
             "signer_kind": "key", "issuer": "https://forged.example", "key_name": "forged",
             "key_hint": "4jEsKCCfR3j/xsDKJ4Zji7htYCfugJKrpnxdlNJo7jA="}
        ],
        "attestations": [
            {"predicate_type": "https://slsa.dev/provenance/v1", "format": "bundle", "source": "referrers",
             "verified": true, "signer_kind": "keyless", "issuer": "https://token.actions.githubusercontent.com",
             "san": "x", "payload_sha256": "ab".repeat(32),
             "provenance": {"builder_id": "https://github.com/actions/runner", "source_repo": "https://github.com/example/api"}},
            {"predicate_type": "https://spdx.dev/Document", "format": "bundle", "source": "referrers",
             "verified": false, "error": "bad_signature", "issuer": "i", "san": "s",
             "provenance": {"builder_id": "claimed"}}
        ]
    })
}

fn parse(v: &serde_json::Value, path: &str) -> Result<AttestationPost, Reject> {
    parse_post(path, &serde_json::to_vec(v).unwrap(), now())
}

#[test]
fn parses_a_result_and_drops_unverified_identity() {
    let p = parse(&body(&d(1), "verified"), &d(1)).unwrap();
    assert_eq!(p.verdict, "verified");
    assert_eq!(p.signatures.len(), 2);
    let ok = &p.signatures[0];
    assert_eq!(ok.signer_kind.as_deref(), Some("keyless"));
    assert_eq!(ok.tlog_index, Some(42));
    // An unverified signature keeps its error and key hint, never an
    // identity it merely claims.
    let bad = &p.signatures[1];
    assert_eq!(bad.error.as_deref(), Some("untrusted_key"));
    assert_eq!(
        bad.key_hint.as_deref(),
        Some("4jEsKCCfR3j/xsDKJ4Zji7htYCfugJKrpnxdlNJo7jA=")
    );
    assert!(bad.issuer.is_none() && bad.key_name.is_none() && bad.signer_kind.is_none());
    // Unverified attestations lose identity and provenance.
    assert!(p.attestations[0].provenance.is_some());
    let a = &p.attestations[1];
    assert!(a.issuer.is_none() && a.san.is_none() && a.provenance.is_none());
}

#[test]
fn key_signed_is_a_verdict() {
    let mut v = body(&d(2), "key_signed");
    v["signatures"] = json!([v["signatures"][1].clone()]);
    let p = parse(&v, &d(2)).unwrap();
    assert_eq!(p.verdict, "key_signed");
}

#[test]
fn verdict_must_match_the_signatures() {
    let unverified_only = |verdict: &str| {
        let mut v = body(&d(5), verdict);
        v["signatures"] =
            json!([{"format": "cosign-legacy", "verified": false, "error": "bad_signature"}]);
        v
    };
    // "verified" with no verified signature; "unsigned" with signatures;
    // "invalid"/"key_signed"/"unknown" next to a verified one; "key_signed"
    // with no signature at all.
    let mut no_sigs = body(&d(5), "key_signed");
    no_sigs["signatures"] = json!([]);
    for v in [
        unverified_only("verified"),
        body(&d(5), "unsigned"),
        body(&d(5), "invalid"),
        body(&d(5), "unknown"),
        body(&d(5), "key_signed"),
        no_sigs,
    ] {
        assert!(
            matches!(parse(&v, &d(5)), Err(Reject::Unprocessable(_))),
            "{} accepted",
            v["verdict"]
        );
    }
    assert!(parse(&unverified_only("invalid"), &d(5)).is_ok());
    // A tampered signature is invalid, never key_signed or unknown.
    assert!(parse(&unverified_only("key_signed"), &d(5)).is_err());
    assert!(parse(&unverified_only("unknown"), &d(5)).is_err());
    let mut none = body(&d(5), "unsigned");
    none["signatures"] = json!([]);
    assert!(parse(&none, &d(5)).is_ok());
}

#[test]
fn verified_key_signer_is_kept() {
    let mut v = body(&d(3), "verified");
    v["signatures"] = json!([{"format": "cosign-legacy", "source": "sig-tag", "verified": true,
        "signer_kind": "key", "key_name": "release", "key_fingerprint": "cd".repeat(32)}]);
    let p = parse(&v, &d(3)).unwrap();
    let s = &p.signatures[0];
    assert_eq!(s.signer_kind.as_deref(), Some("key"));
    assert_eq!(s.key_name.as_deref(), Some("release"));
    assert_eq!(s.key_fingerprint.as_deref().map(str::len), Some(64));
    // Stored camelCase, which the summary query reads.
    let stored = serde_json::to_value(&p.signatures).unwrap();
    assert_eq!(stored[0]["signerKind"], "key");
    assert_eq!(stored[0]["keyName"], "release");
}

#[test]
fn rejects_bad_posts() {
    let cases: Vec<(serde_json::Value, &str, &str)> = vec![
        (body(&d(1), "verified"), "sha256:ff", "path mismatch"),
        (body(&d(1), "trusted"), "", "unknown verdict"),
        (
            {
                let mut v = body(&d(1), "verified");
                v["schema_version"] = json!(2);
                v
            },
            "",
            "schema",
        ),
        (
            {
                let mut v = body(&d(1), "verified");
                v["checked_at"] = json!("2026-09-27T12:05:00Z");
                v
            },
            "",
            "future",
        ),
        (
            {
                let mut v = body(&d(1), "verified");
                v["reason"] = json!("Not A Token");
                v
            },
            "",
            "reason token",
        ),
        (
            {
                let mut v = body(&d(1), "verified");
                v["signatures"][0]["signer_kind"] = json!("kms");
                v
            },
            "",
            "signer kind",
        ),
        (
            {
                let mut v = body(&d(1), "verified");
                v["signed_digest"] = json!("latest");
                v
            },
            "",
            "signed digest",
        ),
    ];
    for (v, path, what) in cases {
        let path = if path.is_empty() {
            d(1)
        } else {
            path.to_string()
        };
        assert!(
            matches!(parse(&v, &path), Err(Reject::Unprocessable(_))),
            "{what}: accepted"
        );
    }
    assert!(matches!(
        parse_post(&d(1), b"{not json", now()),
        Err(Reject::BadRequest(_))
    ));
}

#[test]
fn caps_list_lengths() {
    let mut v = body(&d(1), "verified");
    v["signatures"] = json!(vec![
        json!({"format": "f", "verified": false});
        MAX_SIGNATURES + 1
    ]);
    assert!(matches!(parse(&v, &d(1)), Err(Reject::TooLarge(_))));
    let mut v = body(&d(1), "verified");
    v["attestations"] = json!(vec![
        json!({"predicate_type": "p", "verified": false});
        MAX_ATTESTATIONS + 1
    ]);
    assert!(matches!(parse(&v, &d(1)), Err(Reject::TooLarge(_))));
    let mut v = body(&d(1), "invalid");
    v["signatures"] = json!(vec![
        json!({"format": "f", "verified": false, "error": "bad_signature"});
        MAX_SIGNATURES
    ]);
    assert!(parse(&v, &d(1)).is_ok());
}

#[test]
fn truncates_long_strings_on_char_boundaries() {
    let mut v = body(&d(1), "verified");
    v["signatures"][1]["detail"] = json!("é".repeat(10_000));
    let p = parse(&v, &d(1)).unwrap();
    let det = p.signatures[1].detail.as_ref().unwrap();
    assert!(det.len() <= MAX_DETAIL && det.chars().all(|c| c == 'é'));
}

// A verified identity is stored whole or refused, never truncated: a
// prefix of a SAN could match a policy the real SAN does not.
#[test]
fn verified_identity_is_never_truncated() {
    let mut v = body(&d(1), "verified");
    v["signatures"][0]["san"] = json!("é".repeat(MAX_URI));
    assert!(matches!(parse(&v, &d(1)), Err(Reject::Unprocessable(_))));
    let mut v = body(&d(1), "verified");
    v["attestations"][0]["provenance"]["source_repo"] = json!("x".repeat(MAX_URI + 1));
    assert!(matches!(parse(&v, &d(1)), Err(Reject::Unprocessable(_))));
    // An unverified signature's claimed identity is dropped, not refused.
    let mut v = body(&d(1), "verified");
    v["signatures"][1]["san"] = json!("x".repeat(MAX_URI * 2));
    assert!(parse(&v, &d(1)).unwrap().signatures[1].san.is_none());
}

// ---------------------------------------------------------------------
// Live database (ignored by default; CI runs them against Postgres with
// the shipped migrations).
// ---------------------------------------------------------------------

const TEST_MIGRATIONS: diesel_migrations::EmbeddedMigrations =
    diesel_migrations::embed_migrations!("./db/migrations");

fn live_conn() -> PgConnection {
    use diesel::connection::SimpleConnection;
    use diesel_migrations::MigrationHarness;
    let Ok(url) = std::env::var("KG_TEST_DATABASE_URL") else {
        panic!("set KG_TEST_DATABASE_URL to run this test");
    };
    let mut conn = PgConnection::establish(&url).expect("connect");
    conn.run_pending_migrations(TEST_MIGRATIONS)
        .expect("apply the shipped migrations");
    conn.batch_execute("TRUNCATE images, image_attestations")
        .expect("reset the inventory");
    conn
}

fn add_image(conn: &mut PgConnection, digest: &str) {
    sql_query(
        "INSERT INTO images (digest, repository, digest_kind, first_seen, last_seen) \
         VALUES ($1, 'ghcr.io/example/api', 'repo', timezone('UTC', NOW()), timezone('UTC', NOW()))",
    )
    .bind::<Text, _>(digest)
    .execute(conn)
    .expect("insert image");
}

fn post_at(digest: &str, verdict: &str, checked_at: &str) -> AttestationPost {
    let mut v = body(digest, verdict);
    v["checked_at"] = json!(checked_at);
    // Signatures consistent with the verdict (parse_post checks it).
    match verdict {
        "unsigned" => v["signatures"] = json!([]),
        "key_signed" => v["signatures"] = json!([v["signatures"][1].clone()]),
        "invalid" => {
            v["signatures"] =
                json!([{"format": "cosign-legacy", "verified": false, "error": "bad_signature"}])
        }
        "unknown" => {
            v["signatures"] =
                json!([{"format": "cosign-legacy", "verified": false, "error": "untrusted_root"}])
        }
        _ => {}
    }
    parse_post(digest, &serde_json::to_vec(&v).unwrap(), Utc::now()).unwrap()
}

#[test]
#[ignore = "requires a live postgres (set KG_TEST_DATABASE_URL)"]
fn live_store_replacement_rules() {
    let mut conn = live_conn();
    let dg = d(10);
    // Unknown to the inventory: refused.
    assert_eq!(
        store(&mut conn, &post_at(&dg, "verified", "2026-09-01T00:00:00Z")).unwrap(),
        Outcome::UnknownDigest
    );
    add_image(&mut conn, &dg);
    let first = post_at(&dg, "verified", "2026-09-01T00:00:00Z");
    assert_eq!(store(&mut conn, &first).unwrap(), Outcome::Stored);
    // Same content, same time: no-op.
    assert_eq!(store(&mut conn, &first).unwrap(), Outcome::Unchanged);
    // Same time, different content: refused.
    assert_eq!(
        store(&mut conn, &post_at(&dg, "unsigned", "2026-09-01T00:00:00Z")).unwrap(),
        Outcome::Stale
    );
    // Older: refused.
    assert_eq!(
        store(&mut conn, &post_at(&dg, "unsigned", "2026-08-01T00:00:00Z")).unwrap(),
        Outcome::Stale
    );
    // Newer: replaces.
    assert_eq!(
        store(
            &mut conn,
            &post_at(&dg, "key_signed", "2026-09-02T00:00:00Z")
        )
        .unwrap(),
        Outcome::Stored
    );
    let row = load_one(&mut conn, &dg).unwrap().unwrap();
    assert_eq!(row.verdict, "key_signed");
    // The one unverified key signature: its claimed identity is not
    // stored, its key hint is.
    assert_eq!(row.signatures.as_array().unwrap().len(), 1);
    assert!(row.signatures[0].get("issuer").is_none());
    assert!(row.signatures[0].get("keyHint").is_some());
}

#[test]
#[ignore = "requires a live postgres (set KG_TEST_DATABASE_URL)"]
fn live_list_summaries_and_filters() {
    let mut conn = live_conn();
    for (i, verdict) in [(20, "verified"), (21, "unsigned"), (22, "key_signed")] {
        add_image(&mut conn, &d(i));
        let mut p = post_at(&d(i), verdict, "2026-09-01T00:00:00Z");
        if i == 22 {
            let mut v = body(&d(i), "verified");
            v["signatures"] = json!([{"format": "cosign-legacy", "source": "sig-tag", "verified": true,
                "signer_kind": "key", "key_name": "release", "key_fingerprint": "cd".repeat(32)}]);
            v["checked_at"] = json!("2026-09-01T00:00:00Z");
            p = parse_post(&d(i), &serde_json::to_vec(&v).unwrap(), Utc::now()).unwrap();
        }
        store(&mut conn, &p).unwrap();
    }
    let page = list(&mut conn, None, None, None, 2).unwrap();
    assert_eq!(page.items.len(), 2);
    assert_eq!(page.next_after.as_deref(), Some(d(21).as_str()));
    let rest = list(&mut conn, page.next_after.as_deref(), None, None, 2).unwrap();
    assert_eq!(rest.items.len(), 1);
    assert!(rest.next_after.is_none());

    let verified = list(&mut conn, None, Some("verified"), None, 10).unwrap();
    assert_eq!(verified.items.len(), 2);
    let keyless = verified.items.iter().find(|i| i.digest == d(20)).unwrap();
    assert_eq!(keyless.signers.as_array().unwrap().len(), 1);
    assert_eq!(keyless.signers[0]["kind"], "keyless");
    assert_eq!(
        keyless.signers[0]["issuer"],
        "https://token.actions.githubusercontent.com"
    );
    assert_eq!(
        keyless.verified_predicates,
        json!(["https://slsa.dev/provenance/v1"])
    );
    let keyed = verified.items.iter().find(|i| i.digest == d(22)).unwrap();
    assert_eq!(keyed.signers[0]["kind"], "key");
    assert_eq!(keyed.signers[0]["keyName"], "release");
    assert!(keyed.signers[0].get("issuer").is_none());
}

#[test]
#[ignore = "requires a live postgres (set KG_TEST_DATABASE_URL)"]
fn live_gc_follows_inventory_and_age() {
    use diesel::connection::SimpleConnection;
    let mut conn = live_conn();
    add_image(&mut conn, &d(30));
    add_image(&mut conn, &d(31));
    store(
        &mut conn,
        &post_at(&d(30), "verified", "2026-09-01T00:00:00Z"),
    )
    .unwrap();
    store(
        &mut conn,
        &post_at(&d(31), "unsigned", "2026-09-01T00:00:00Z"),
    )
    .unwrap();
    // The digest stops running and inventory retention drops it: the
    // next pass removes its result, even with age pruning off.
    conn.batch_execute(&format!("DELETE FROM images WHERE digest = '{}'", d(30)))
        .unwrap();
    assert_eq!(prune(&mut conn, 0).unwrap(), 1);
    assert!(load_one(&mut conn, &d(30)).unwrap().is_none());
    assert!(load_one(&mut conn, &d(31)).unwrap().is_some());
    // A result not re-checked within the window is pruned, unless age
    // pruning is off.
    conn.batch_execute(
        "UPDATE image_attestations SET checked_at = timezone('UTC', NOW()) - INTERVAL '8 days'",
    )
    .unwrap();
    assert_eq!(prune(&mut conn, 0).unwrap(), 0);
    assert_eq!(prune(&mut conn, 7).unwrap(), 1);
    assert!(load_one(&mut conn, &d(31)).unwrap().is_none());
}

/// The summary and single-row charges cover the largest rows the caps
/// allow.
#[test]
#[ignore = "requires a live postgres (set KG_TEST_DATABASE_URL)"]
fn live_summary_cost_covers_the_largest_row() {
    // ASCII, 2-byte UTF-8, 4-byte UTF-8 (emoji) and a character JSON
    // escapes (a quote serialises to 2 bytes): the served summary row
    // stays within the charge in every case (strings are cut by bytes).
    let chars = [
        'i',
        char::from_u32(0xE9).unwrap(),
        char::from_u32(0x1F600).unwrap(),
        '"',
    ];
    for (n, c) in chars.into_iter().enumerate() {
        let mut conn = live_conn();
        let dg = d(90 + n as u32);
        add_image(&mut conn, &dg);
        // Longest strings the caps allow for this character (bytes).
        let fill = |prefix: String, max: usize| {
            let room = (max - prefix.len()) / c.len_utf8();
            prefix + &c.to_string().repeat(room)
        };
        let mut pred_len = MAX_URI;
        let body = loop {
            let sigs: Vec<_> = (0..MAX_SIGNATURES)
                .map(|i| json!({"format": "cosign-bundle", "source": "referrers", "verified": true,
                    "signer_kind": if i % 2 == 0 { "keyless" } else { "key" },
                    "issuer": fill(format!("{i:02}"), MAX_URI), "san": fill(format!("{i:02}"), MAX_URI),
                    "key_name": fill(format!("{i:02}"), MAX_SHORT), "key_fingerprint": format!("{i:064x}")}))
                .collect();
            let atts: Vec<_> = (0..MAX_ATTESTATIONS)
                .map(|i| {
                    json!({"predicate_type": fill(format!("{i:02}"), pred_len), "verified": true,
                    "signer_kind": "keyless", "issuer": "i", "san": "s"})
                })
                .collect();
            let v = json!({"schema_version": 1, "digest": dg, "repository": fill(String::new(), MAX_URI),
                "checked_at": "2026-09-01T00:00:00Z", "verdict": "verified", "reason": "trust_root_unavailable",
                "signed_via": "self", "signatures": sigs, "attestations": atts});
            let body = serde_json::to_vec(&v).unwrap();
            // Escaped characters inflate the body: shrink the least
            // interesting part (predicates) until it is a valid post.
            if body.len() <= MAX_BODY_BYTES {
                break body;
            }
            pred_len -= 64;
        };
        let p = parse_post(&dg, &body, Utc::now()).unwrap();
        assert_eq!(store(&mut conn, &p).unwrap(), Outcome::Stored);
        let page = list(&mut conn, None, None, None, 10).unwrap();
        let row = serde_json::to_vec(&page.items[0]).unwrap().len() as u64;
        assert!(
            row <= ATTESTATION_SUMMARY_COST_BYTES,
            "{c:?}: largest summary row is {row} bytes, charged {ATTESTATION_SUMMARY_COST_BYTES}"
        );
        let one = serde_json::to_vec(&load_one(&mut conn, &dg).unwrap().unwrap())
            .unwrap()
            .len() as u64;
        assert!(
            one <= ATTESTATION_ROW_COST_BYTES,
            "{c:?}: largest row is {one} bytes"
        );
        eprintln!("{c:?}: largest summary row {row} bytes; largest stored row {one} bytes");
    }
}

/// VERDICTS and SIGNER_KINDS equal the shared contract file, which
/// supplychain's constants are tested against too (contract_test.go).
#[test]
fn verdict_contract_matches_supplychain() {
    let c: serde_json::Value = serde_json::from_str(include_str!(
        "../../test/fixtures/contracts/attestation-verdicts.json"
    ))
    .unwrap();
    let set = |k: &str| -> std::collections::BTreeSet<String> {
        c[k].as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect()
    };
    let ours = |v: &[&str]| -> std::collections::BTreeSet<String> {
        v.iter().map(|s| s.to_string()).collect()
    };
    assert_eq!(
        ours(&VERDICTS),
        set("verdicts"),
        "broker VERDICTS drifted from the contract"
    );
    assert_eq!(
        ours(&SIGNER_KINDS),
        set("signer_kinds"),
        "broker SIGNER_KINDS drifted from the contract"
    );
    assert_eq!(
        ours(&REASONS),
        set("reasons"),
        "broker REASONS drifted from the contract"
    );
}

/// Every string is checked: a control character or U+2028/U+2029 anywhere
/// is a 422 naming the field.
#[test]
fn control_characters_are_refused_naming_the_field() {
    for bad in [
        "\n", "\r", "\t", "\u{0001}", "\u{0085}", "\u{2028}", "\u{2029}",
    ] {
        for (path, field) in [
            ("/repository", "repository"),
            ("/signatures/0/san", "signatures[0].san"),
            ("/signatures/0/issuer", "signatures[0].issuer"),
            ("/signatures/1/detail", "signatures[1].detail"),
            (
                "/attestations/0/predicate_type",
                "attestations[0].predicate_type",
            ),
            (
                "/attestations/0/provenance/builder_id",
                "attestations[0].provenance.builder_id",
            ),
        ] {
            let mut v = body(&d(7), "verified");
            *v.pointer_mut(path).unwrap() = json!(format!("x{bad}y"));
            match parse(&v, &d(7)) {
                Err(Reject::Unprocessable(m)) => {
                    assert!(m.starts_with(field), "{bad:?} {field}: {m}")
                }
                other => panic!("{bad:?} {field}: {other:?}"),
            }
        }
    }
    // The summary-cost worst case with control characters (each \u0001
    // serialises to 6 bytes) cannot be stored.
    let mut v = body(&d(7), "verified");
    v["attestations"][0]["predicate_type"] = json!("\u{0001}".repeat(1000));
    assert!(matches!(parse(&v, &d(7)), Err(Reject::Unprocessable(_))));
}

/// supplychain's encodeBounded puts the verified signature ahead of 40 junk
/// ones before capping; the payload it produces (checked in by its test)
/// is accepted as verified.
#[test]
fn verified_signature_survives_the_caps() {
    let raw = include_str!("../../test/fixtures/contracts/attestation-post-buried-signature.json");
    let v: serde_json::Value = serde_json::from_str(raw).unwrap();
    let dg = v["digest"].as_str().unwrap().to_string();
    // The fixture's checked_at is the test clock (2026-09-27T12:00Z).
    let p = parse_post(&dg, raw.as_bytes(), now()).unwrap();
    assert_eq!(p.verdict, "verified");
    assert_eq!(p.signatures.len(), MAX_SIGNATURES);
    assert!(p.signatures[0].verified);
    assert!(p.attestations[0].verified);
}

/// Bidi and invisible format controls are refused like control characters
/// (identities are what operators review), and so is an unknown reason.
#[test]
fn bidi_controls_and_unknown_reasons_are_refused() {
    for cp in [
        0x200Eu32, 0x200F, 0x202A, 0x202B, 0x202C, 0x202D, 0x202E, 0x2066, 0x2067, 0x2068, 0x2069,
        0xFEFF,
    ] {
        let c = char::from_u32(cp).unwrap();
        for (path, field) in [
            ("/signatures/0/san", "signatures[0].san"),
            (
                "/attestations/0/predicate_type",
                "attestations[0].predicate_type",
            ),
            ("/repository", "repository"),
        ] {
            let mut v = body(&d(9), "verified");
            *v.pointer_mut(path).unwrap() = json!(format!("gh{c}evil"));
            match parse(&v, &d(9)) {
                Err(Reject::Unprocessable(m)) => {
                    assert!(m.starts_with(field), "U+{cp:04X} {field}: {m}")
                }
                other => panic!("U+{cp:04X} {field}: {other:?}"),
            }
        }
    }
    let mut v = body(&d(9), "verified");
    // A malformed reason token is refused, naming the field.
    v["signatures"][1]["error"] = json!("Not A Token");
    match parse(&v, &d(9)) {
        Err(Reject::Unprocessable(m)) => assert!(m.starts_with("signatures[1].error"), "{m}"),
        other => panic!("{other:?}"),
    }
}

/// Version skew: a well-formed reason code this broker does not know (a
/// newer supplychain) is stored as unrecognised_reason and counted, never
/// refused, and never changes the verdict. Verdicts and signer kinds stay
/// strict.
#[test]
fn unknown_reason_codes_are_tolerated() {
    let before = UNRECOGNISED_REASONS.load(std::sync::atomic::Ordering::Relaxed);
    let mut v = body(&d(9), "verified");
    v["signatures"][1]["error"] = json!("brand_new_reason");
    v["attestations"][1]["error"] = json!("another_new_one");
    let p = parse(&v, &d(9)).unwrap();
    assert_eq!(p.verdict, "verified");
    assert_eq!(p.signatures[1].error.as_deref(), Some(UNRECOGNISED_REASON));
    assert_eq!(
        p.attestations[1].error.as_deref(),
        Some(UNRECOGNISED_REASON)
    );
    let mut v = body(&d(9), "unknown");
    v["signatures"] = json!([]);
    v["reason"] = json!("registry_auth");
    assert_eq!(
        parse(&v, &d(9)).unwrap().reason.as_deref(),
        Some("registry_auth")
    );
    v["reason"] = json!("made_up");
    let p = parse(&v, &d(9)).unwrap();
    assert_eq!(
        (p.verdict.as_str(), p.reason.as_deref()),
        ("unknown", Some(UNRECOGNISED_REASON))
    );
    assert!(UNRECOGNISED_REASONS.load(std::sync::atomic::Ordering::Relaxed) >= before + 3);
    assert!(render_metrics().contains("kguardian_attestation_unrecognised_reason_total "));
    // Still strict: verdicts and signer kinds.
    let mut v = body(&d(9), "brand_new_verdict");
    assert!(matches!(parse(&v, &d(9)), Err(Reject::Unprocessable(_))));
    v = body(&d(9), "verified");
    v["signatures"][0]["signer_kind"] = json!("brand_new_kind");
    assert!(matches!(parse(&v, &d(9)), Err(Reject::Unprocessable(_))));
}

/// Byte truncation never splits a UTF-8 sequence and never exceeds the
/// limit.
#[test]
fn truncate_bytes_stays_on_char_boundaries() {
    let sample: String = [
        'a',
        char::from_u32(0xE9).unwrap(),
        char::from_u32(0x4E2D).unwrap(),
        char::from_u32(0x1F600).unwrap(),
    ]
    .iter()
    .cycle()
    .take(40)
    .collect();
    for max in 0..=sample.len() + 2 {
        let mut s = sample.clone();
        truncate_bytes(&mut s, max);
        assert!(s.len() <= max, "max {max}: {} bytes", s.len());
        assert!(sample.starts_with(&s));
        // As long as possible: one more character would not fit.
        if let Some(next) = sample[s.len()..].chars().next() {
            assert!(s.len() + next.len_utf8() > max, "max {max}: cut too short");
        }
        assert!(std::str::from_utf8(s.as_bytes()).is_ok());
    }
}

/// An unknown reason from a newer supplychain is stored (201 path), as
/// unrecognised_reason, with the verdict it came with.
#[test]
#[ignore = "requires a live postgres (set KG_TEST_DATABASE_URL)"]
fn live_unknown_reason_is_stored() {
    let mut conn = live_conn();
    let dg = d(95);
    add_image(&mut conn, &dg);
    let mut v = body(&dg, "verified");
    v["checked_at"] = json!("2026-09-01T00:00:00Z");
    v["signatures"][1]["error"] = json!("brand_new_reason");
    let p = parse_post(&dg, &serde_json::to_vec(&v).unwrap(), Utc::now()).unwrap();
    assert_eq!(store(&mut conn, &p).unwrap(), Outcome::Stored);
    let row = load_one(&mut conn, &dg).unwrap().unwrap();
    assert_eq!(row.verdict, "verified");
    assert_eq!(row.signatures[1]["error"], UNRECOGNISED_REASON);
}

/// Which verdict each combination of unverified signature errors allows
/// (the poster cannot pick): tamper → invalid only; untrusted_key without
/// tamper → key_signed or unknown; an unrecognised code → invalid or
/// unknown, never key_signed on its own.
#[test]
fn verdict_follows_the_signature_classes() {
    let sig = |err: &str| json!({"format": "cosign-bundle", "source": "referrers", "verified": false, "error": err});
    let cases: Vec<(Vec<&str>, &[&str])> = vec![
        (vec!["bad_signature"], &["invalid"]),
        (vec!["digest_mismatch"], &["invalid"]),
        (vec!["malformed"], &["invalid"]),
        (vec!["bad_signature", "untrusted_key"], &["invalid"]),
        (vec!["untrusted_key"], &["key_signed", "unknown"]),
        (
            vec!["untrusted_key", "unsupported_format"],
            &["key_signed", "unknown"],
        ),
        (vec!["unsupported_format"], &["unknown"]),
        (vec!["untrusted_root"], &["unknown"]),
        (vec!["brand_new_code"], &["invalid", "unknown"]),
        (
            vec!["brand_new_code", "untrusted_key"],
            &["invalid", "key_signed", "unknown"],
        ),
    ];
    for (errs, allowed) in cases {
        for verdict in ["verified", "key_signed", "unsigned", "invalid", "unknown"] {
            let mut v = body(&d(12), verdict);
            v["signatures"] = json!(errs.iter().map(|e| sig(e)).collect::<Vec<_>>());
            let ok = parse(&v, &d(12)).is_ok();
            assert_eq!(
                ok,
                allowed.contains(&verdict),
                "{errs:?} as {verdict}: accepted={ok}"
            );
        }
    }
    // No signatures: unsigned or unknown (lookup failed), nothing else.
    for verdict in ["verified", "key_signed", "unsigned", "invalid", "unknown"] {
        let mut v = body(&d(12), verdict);
        v["signatures"] = json!([]);
        assert_eq!(
            parse(&v, &d(12)).is_ok(),
            ["unsigned", "unknown"].contains(&verdict),
            "no signatures as {verdict}"
        );
    }
}
