use jeangrey::cli;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                tracing_subscriber::EnvFilter::new("jeangrey=info,libp2p=warn")
            }),
        )
        .init();

    let cli = <cli::Cli as clap::Parser>::parse();
    cli::run(cli).await
}
