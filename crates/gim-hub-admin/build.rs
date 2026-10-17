//! Embeds the built admin UI (`admin-ui/dist`, from `scripts/admin-ui.sh
//! build`) into the crate: generates `$OUT_DIR/admin_ui.rs` with one
//! `include_bytes!` per file. Without `dist/index.html` the generated file is
//! a `compile_error!`, so a binary never ships without the UI.

use std::{
    env,
    fmt::Write as _,
    fs,
    path::{Path, PathBuf},
};

fn main() {
    let manifest = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let dist = manifest.join("../../admin-ui/dist");
    println!("cargo:rerun-if-changed={}", dist.display());

    let mut code = String::new();
    if dist.join("index.html").is_file() {
        let mut files = Vec::new();
        collect(&dist, &dist, &mut files);
        files.sort();
        code.push_str("pub(crate) static FILES: &[(&str, &[u8])] = &[\n");
        for (name, path) in files {
            writeln!(code, "    ({name:?}, include_bytes!({path:?})),").unwrap();
        }
        code.push_str("];\n");
    } else {
        code.push_str(
            "compile_error!(\"admin-ui/dist/index.html is missing: the admin UI is not built; \
run scripts/admin-ui.sh build first\");\n\
pub(crate) static FILES: &[(&str, &[u8])] = &[];\n",
        );
    }
    let out = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR")).join("admin_ui.rs");
    fs::write(out, code).expect("write admin_ui.rs");
}

/// Collects `(path relative to dist with '/' separators, absolute path)`.
fn collect(dist: &Path, dir: &Path, files: &mut Vec<(String, String)>) {
    for entry in fs::read_dir(dir).expect("read admin-ui/dist") {
        let path = entry.expect("read admin-ui/dist").path();
        if path.is_dir() {
            collect(dist, &path, files);
        } else {
            let name = path
                .strip_prefix(dist)
                .expect("under dist")
                .components()
                .map(|c| c.as_os_str().to_str().expect("UTF-8 file name"))
                .collect::<Vec<_>>()
                .join("/");
            let path = fs::canonicalize(&path).expect("canonical path");
            files.push((name, path.to_str().expect("UTF-8 path").to_owned()));
        }
    }
}
