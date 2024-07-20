#![feature(test)]

extern crate test;
use std::fs::File;

use adexplorersnapshot::parser::ADExplorerSnapshot;
use memmap2::Mmap;
use test::Bencher;

const SNAPSHOT_PATH: &str = "data/snapshot.bak";

#[bench]
fn snapshot(b: &mut Bencher) {
    let file = File::open(SNAPSHOT_PATH).expect("Failed to open snapshot");
    let mapped = unsafe { Mmap::map(&file) }.expect("Failed to map in snapshot");

    b.iter(|| {
        test::black_box(
            ADExplorerSnapshot::snapshot_from_memory(&mapped[..])
                .expect("Failed to parse snapshot"),
        );
    });
}
