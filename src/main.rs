//! Main entry point for the TL (Timeline) CLI application.

use clap::Parser;
use tl::{app::App, cli::Args, error::Result};

fn main() -> Result<()> {
    let args = Args::parse();
    let config = tl::cli::Config::from_args(args)?;
    let app = App::new(config);
    app.run()
}