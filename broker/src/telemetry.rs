use std::env;

pub fn init_logging() {
    // Normalise RUST_LOG to either the trimmed operator value or
    // "info" as default. Three cases to handle:
    //   - unset            → "info"
    //   - "  " (effectively-empty)  → "info"
    //   - "  info  " (trimmable)    → "info" (we write back the trim)
    // The previous version only handled the first two. The third
    // case slipped through: EnvFilter::from_default_env reads the
    // still-untrimmed env value and tries to parse "  info  " as a
    // filter directive — produces a confused EnvFilter that doesn't
    // emit logs at the expected level.
    //
    // We write the normalised value back into the env so anything
    // downstream that re-reads RUST_LOG (tracing_subscriber + any
    // libraries that consult it) sees the clean value too.
    let normalised = env::var("RUST_LOG")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "info".to_string());
    env::set_var("RUST_LOG", normalised);

    // Initialize the logger
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
}
