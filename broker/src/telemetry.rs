use std::env;

pub fn init_logging() {
    // Set RUST_LOG=info when the env is unset OR effectively-empty
    // (whitespace-only). The previous `is_err()` check treated
    // RUST_LOG="  " or "\n" as "set" and let tracing_subscriber try
    // to parse it — producing a confused EnvFilter that doesn't
    // emit logs at the expected level. Trim defensively here just
    // like every other env reader in the broker.
    let effective = env::var("RUST_LOG").ok().filter(|s| !s.trim().is_empty());
    if effective.is_none() {
        env::set_var("RUST_LOG", "info");
    }

    // Initialize the logger
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
}
