//! Compiles `proto/*.proto` with `protox` (pure Rust, no `protoc`) and
//! generates Rust types with `prost-build`.

use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR")?);
    let proto_dir = manifest_dir.join("../../proto");
    println!("cargo:rerun-if-changed={}", proto_dir.display());

    let fds = protox::compile([proto_dir.join("s2s.proto")], [&proto_dir])?;
    prost_build::Config::new().compile_fds(fds)?;
    Ok(())
}
