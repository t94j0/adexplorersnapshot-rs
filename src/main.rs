use clap::Parser;
use flate2::write::GzEncoder;
use flate2::Compression;
use rand::Rng;
use std::fs::File;
use std::io::BufWriter;
use std::io::{Error, ErrorKind};
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::Instant;
use tar::Builder;

use adexplorersnapshot::output::bloodhound::{
    ComputersOutput, ContainersOutput, DomainsOutput, GPOsOutput, GroupsOutput, OUsOutput,
    UsersOutput,
};
use adexplorersnapshot::parser::ADExplorerSnapshot;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(help = "Input .dat file path")]
    input: String,

    #[clap(short, long, help = "Output .tar.gz file path")]
    output: Option<String>,

    #[clap(short, long, help = "Compression level (0-9, default 6)")]
    compression: Option<u32>,

    #[clap(short, long, help = "Verbose output")]
    verbose: bool,
}

trait Output: Send {
    fn to_json(&self) -> serde_json::Result<Vec<u8>>;
}

impl<T: serde::Serialize + Send> Output for T {
    fn to_json(&self) -> serde_json::Result<Vec<u8>> {
        serde_json::to_vec(self)
    }
}

fn main() -> std::io::Result<()> {
    let start_time = Instant::now();
    let args = Args::parse();

    let verbose = args.verbose;

    if verbose {
        println!("Parsing");
    }
    let parsing_start = Instant::now();
    let snapshot = ADExplorerSnapshot::snapshot_from_file(&args.input)?;
    if verbose {
        println!("Parsing took: {:?}", parsing_start.elapsed());
    }

    let output_path = args.output.map(PathBuf::from).unwrap_or_else(|| {
        let random_name: String = rand::thread_rng()
            .sample_iter(&rand::distributions::Alphanumeric)
            .take(10)
            .map(char::from)
            .collect();
        PathBuf::from(format!("{}.tar.gz", random_name))
    });

    let file = File::create(&output_path)?;
    let buf_writer = BufWriter::with_capacity(8 * 1024 * 1024, file);
    let compression_level = args.compression.unwrap_or(6);
    let gzip_encoder = GzEncoder::new(buf_writer, Compression::new(compression_level));
    let archive = Mutex::new(Builder::new(gzip_encoder));

    process_outputs(&archive, &snapshot, verbose)?;

    let write_start = Instant::now();
    archive.into_inner().unwrap().into_inner()?.finish()?;
    if verbose {
        println!("Writing zip took: {:?}", write_start.elapsed());
    }

    println!("Output written to: {}", output_path.display());
    println!("Total elapsed time: {:?}", start_time.elapsed());

    Ok(())
}

fn process_outputs(
    archive: &Mutex<Builder<GzEncoder<BufWriter<File>>>>,
    snapshot: &ADExplorerSnapshot,
    verbose: bool,
) -> std::io::Result<()> {
    let output_types: Vec<(&str, Box<dyn Fn() -> Box<dyn Output>>)> = vec![
        (
            "domains.json",
            Box::new(|| Box::new(DomainsOutput::new(snapshot))),
        ),
        (
            "users.json",
            Box::new(|| Box::new(UsersOutput::new(snapshot))),
        ),
        (
            "computers.json",
            Box::new(|| Box::new(ComputersOutput::new(snapshot))),
        ),
        (
            "groups.json",
            Box::new(|| Box::new(GroupsOutput::new(snapshot))),
        ),
        ("ous.json", Box::new(|| Box::new(OUsOutput::new(snapshot)))),
        (
            "containers.json",
            Box::new(|| Box::new(ContainersOutput::new(snapshot))),
        ),
        (
            "gpos.json",
            Box::new(|| Box::new(GPOsOutput::new(snapshot))),
        ),
    ];

    for (filename, output_fn) in output_types {
        if verbose {
            println!("Generating {}", filename);
        }
        let start = Instant::now();
        let output = output_fn();
        if verbose {
            println!("Generating {} took: {:?}", filename, start.elapsed());
        }

        add_output(archive, filename, &*output, verbose)?;
    }

    Ok(())
}

fn add_output(
    archive: &Mutex<Builder<GzEncoder<BufWriter<File>>>>,
    filename: &str,
    output: &dyn Output,
    verbose: bool,
) -> std::io::Result<()> {
    if verbose {
        println!("Processing {}", filename);
    }
    let start = Instant::now();
    let mut header = tar::Header::new_ustar();
    let json = output
        .to_json()
        .map_err(|e| Error::new(ErrorKind::Other, e))?;
    header.set_size(json.len() as u64);
    header.set_cksum();

    let mut archive = archive.lock().unwrap();
    archive.append_data(&mut header, filename, json.as_slice())?;
    if verbose {
        println!("Processing {} took: {:?}", filename, start.elapsed());
    }
    Ok(())
}
