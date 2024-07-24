# ADExplorerSnapshot-rs

Rewrite of [ADExplorerSnapshot.py](https://github.com/c3c/ADExplorerSnapshot.py). Outputs a .tar.gz of BloodHound CE JSON files for ingestion.

# Installation

## Linux

Download the latest published [release](https://github.com/t94j0/adexplorersnapshot-rs/releases/)

## Windows

Build from source

# Usage

```
Usage: convertsnapshot [OPTIONS] <INPUT>

Arguments:
  <INPUT>  Input .dat file path

Options:
  -o, --output <OUTPUT>            Output .tar.gz file path
  -c, --compression <COMPRESSION>  Compression level (0-9, default 6)
  -v, --verbose                    Verbose output
  -h, --help                       Print help
  -V, --version                    Print version
```

## Example usage

```
$ convertsnapshot ./data/snapshot.dat
Output written to: 8YO51UQHGM.tar.gz
Total elapsed time: 47.034845ms
```

```
$ convertsnapshot -c 9 --output output.tar.gz ./data/snapshot.bak 
Output written to: output.tar.gz
Total elapsed time: 47.26538ms
```

# Fun Links

- https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/1522b774-6464-41a3-87a5-1e5633c3fbbb
- https://github.com/SpecterOps/BloodHound/tree/181c5d894b04201fbaaa353df1cbee9bb892556f/cmd/api/src/test/fixtures/fixtures/v6/all

# Shoutouts

- [c3c](https://github.com/c3c/) - Building ADExplorerSnapshot.py
- [Matt Ehrnschwender](https://github.com/MEhrn00) - Lots of Rust help
