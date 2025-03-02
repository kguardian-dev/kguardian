use std::env;

pub fn init_logger() {
    // check the rust log
    if env::var("RUST_LOG").is_err() {
        env::set_var("RUST_LOG", "info")
    }
    if std::env::var("RUST_LOG").unwrap().to_lowercase().eq("info") {
        std::env::set_var("RUST_LOG", "info,kube_client=off");
    } else {
        std::env::set_var(
            "RUST_LOG",
            "debug,kube_client=off,tower=off,hyper=off,h2=off,rustls=off,reqwest=off",
        );
    }

    let timer = time::format_description::parse(
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
