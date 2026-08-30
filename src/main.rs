use std::{
    fs,
    io::{BufReader, Read},
    path::PathBuf,
};

use anyhow::{Result, anyhow};
use auto_artifactarium::{matches_avatars_all_data_notify, matches_items_all_data_notify};
use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Avatars { path: PathBuf },
    Items { path: PathBuf },
}

fn read_file(path: PathBuf) -> Result<Vec<u8>> {
    let f = fs::File::open(path)?;
    let mut reader = BufReader::new(f);
    let mut buffer = Vec::new();
    reader.read_to_end(&mut buffer)?;
    Ok(buffer)
}

fn avatars_command(path: PathBuf) -> Result<()> {
    let buffer = read_file(path)?;

    let avatars = matches_avatars_all_data_notify(&buffer)
        .ok_or_else(|| anyhow!("unable to parse data as avatars"))?;
    println!("{avatars:#?}");

    Ok(())
}

fn items_command(path: PathBuf) -> Result<()> {
    let buffer = read_file(path)?;

    let items = matches_items_all_data_notify(&buffer)
        .ok_or_else(|| anyhow!("unable to parse data as items"))?;
    println!("{items:#?}");

    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Avatars { path } => avatars_command(path),
        Command::Items { path } => items_command(path),
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use clap::CommandFactory;

    use super::*;

    /// clap's own consistency check for the derived command tree; catches
    /// duplicate/invalid argument definitions at test time rather than at
    /// first run.
    #[test]
    fn cli_definition_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn parses_avatars_subcommand() {
        let cli = Cli::parse_from(["auto-artifactarium", "avatars", "dump.bin"]);
        match cli.command {
            Command::Avatars { path } => assert_eq!(path, PathBuf::from("dump.bin")),
            other => panic!("expected `avatars`, got {other:?}"),
        }
    }

    #[test]
    fn parses_items_subcommand() {
        let cli = Cli::parse_from(["auto-artifactarium", "items", "dump.bin"]);
        match cli.command {
            Command::Items { path } => assert_eq!(path, PathBuf::from("dump.bin")),
            other => panic!("expected `items`, got {other:?}"),
        }
    }

    #[test]
    fn rejects_unknown_subcommand_and_missing_path() {
        assert!(Cli::try_parse_from(["auto-artifactarium", "not-a-subcommand"]).is_err());
        assert!(Cli::try_parse_from(["auto-artifactarium", "avatars"]).is_err());
        assert!(Cli::try_parse_from(["auto-artifactarium"]).is_err());
    }

    #[test]
    fn read_file_round_trips_bytes() {
        let mut path = std::env::temp_dir();
        path.push(format!("auto-artifactarium-cli-{}.bin", std::process::id()));

        let payload: Vec<u8> = (0u8..=255).collect();
        {
            let mut f = fs::File::create(&path).expect("create temp file");
            f.write_all(&payload).expect("write temp file");
        }

        let read_back = read_file(path.clone()).expect("read temp file");
        let _ = fs::remove_file(&path);

        assert_eq!(read_back, payload);
    }

    #[test]
    fn read_file_reports_missing_path() {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "auto-artifactarium-does-not-exist-{}.bin",
            std::process::id()
        ));
        assert!(read_file(path).is_err());
    }
}
