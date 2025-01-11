use std::env;

pub fn init_logging() {
    // check the rust log
    if env::var("RUST_LOG").is_err() {
        env::set_var("RUST_LOG", "info")
    }

    // Initialize the logger
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
}
