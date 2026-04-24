use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "seedless")]
#[command(about = "Bitcoin Taproot TSS signing with HSM (YubiKey/NitroKey)", long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Initialize keys: run DKG and distribute shares to HSMs
    Setup {
        /// Number of participants (default: 3)
        #[arg(short, long, default_value = "3")]
        participants: u16,

        /// Threshold: minimum signers needed (default: 2)
        #[arg(short, long, default_value = "2")]
        threshold: u16,

        /// Network: bitcoin or testnet (default: bitcoin)
        #[arg(short, long, default_value = "bitcoin")]
        network: String,
    },

    /// Sign a PSBT file using threshold signatures
    Sign {
        /// Path to PSBT file
        #[arg(value_name = "PSBT_FILE")]
        psbt_file: PathBuf,

        /// Which signers to use (comma-separated IDs, e.g. "1,2")
        #[arg(short, long)]
        signers: Option<String>,

        /// Output file for signed PSBT (default: PSBT_FILE.signed)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Display the group Taproot address
    Address,

    /// Display configuration
    Info,

    /// Export BIP-86 xpub for watch-only wallet import (Sparrow, Electrum)
    ExportXpub {
        /// Output file (default: print to stdout)
        #[arg(short, long)]
        output: Option<std::path::PathBuf>,
    },
}
