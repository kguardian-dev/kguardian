use std::env;

/// Mutate RUST_LOG to add kguardian's noisy-dependency suppressions.
/// Pure on `current` — separated from the global env mutation in
/// `init_logger` so it's testable without poking `std::env`.
pub(crate) fn rust_log_with_suppressions(current: Option<&str>) -> &'static str {
    match current {
        // Default level + the user explicitly set "info" or it was unset
        // (which we treat as info). Suppress kube_client only.
        None => "info,kube_client=off",
        Some(level) if level.eq_ignore_ascii_case("info") => "info,kube_client=off",
        // Anything else: assume the operator wants verbose output and
        // suppress the chattier transport/HTTP layers too.
        Some(_) => "debug,kube_client=off,tower=off,hyper=off,h2=off,rustls=off,reqwest=off",
    }
}

pub fn init_logger() {
    // Read once. Avoids the previous read-then-unwrap pattern that would
    // panic if another thread cleared RUST_LOG between the is_err() check
    // and the unwrap() (Rust's std::env is process-global; even if the
    // race is benign here in practice, the unwrap was a code smell).
    //
    // Trim before passing to rust_log_with_suppressions —
    // its eq_ignore_ascii_case("info") comparison is strict on
    // whitespace, so "info\n" (typical operator paste artefact)
    // would silently take the non-info branch and apply the
    // verbose-suppression set instead of the default.
    let current = env::var("RUST_LOG")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let next = rust_log_with_suppressions(current.as_deref());
    env::set_var("RUST_LOG", next);

    let timer = time::format_description::parse_borrowed::<2>(
        "[year]-[month padding:zero]-[day padding:zero] [hour]:[minute]:[second]",
    )
    .expect("Time Error");
    let time_offset = time::UtcOffset::current_local_offset().unwrap_or(time::UtcOffset::UTC);
    let timer = tracing_subscriber::fmt::time::OffsetTime::new(time_offset, timer);

    // Initialize the logger
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_timer(timer)
        .init();
}

#[cfg(test)]
mod tests {
    use super::*;

    // rust_log_with_suppressions is the pure piece of init_logger that
    // computes the next RUST_LOG value. Tests pin the contract so a
    // refactor that swaps suppressions silently doesn't drown debug
    // sessions in kube_client / hyper / rustls noise.

    #[test]
    fn unset_defaults_to_info_with_kube_client_suppression() {
        assert_eq!(rust_log_with_suppressions(None), "info,kube_client=off",);
    }

    #[test]
    fn explicit_info_keeps_kube_client_suppression() {
        assert_eq!(
            rust_log_with_suppressions(Some("info")),
            "info,kube_client=off",
        );
    }

    #[test]
    fn case_insensitive_match_on_info() {
        assert_eq!(
            rust_log_with_suppressions(Some("INFO")),
            "info,kube_client=off",
        );
        assert_eq!(
            rust_log_with_suppressions(Some("Info")),
            "info,kube_client=off",
        );
    }

    #[test]
    fn non_info_levels_get_full_suppression_set() {
        // The full suppression set protects debug sessions from drowning
        // in chatty dependency logs. Order doesn't matter for env_filter
        // semantics but the test pins the literal string for grep-ability.
        let want = "debug,kube_client=off,tower=off,hyper=off,h2=off,rustls=off,reqwest=off";
        assert_eq!(rust_log_with_suppressions(Some("debug")), want);
        assert_eq!(rust_log_with_suppressions(Some("trace")), want);
        // Even an unrecognised value triggers the verbose suppression
        // set rather than panicking — matches the prior behaviour.
        assert_eq!(rust_log_with_suppressions(Some("garbage")), want);
    }
}
