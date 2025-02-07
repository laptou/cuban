use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use coff::CoffFile;
use parse::Parse;

mod coff;
mod flags;
mod parse;
mod pe;
mod util;

#[derive(Parser)]
struct Cli {
    input_files: Vec<PathBuf>,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    for file in cli.input_files {
        let data = std::fs::read(file)?;
        let coff = CoffFile::parse(&mut &data[..]).unwrap();

        println!("{coff:#?}");
    }

    Ok(())
}
