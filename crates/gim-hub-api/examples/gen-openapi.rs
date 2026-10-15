//! Writes the client API v2 OpenAPI document to `openapi.json` at the
//! repository root. Run through `scripts/gen-openapi.sh`.

use std::path::Path;

fn main() -> std::io::Result<()> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../openapi.json");
    std::fs::write(&path, gim_hub_api::openapi_json())?;
    println!("wrote {}", path.display());
    Ok(())
}
