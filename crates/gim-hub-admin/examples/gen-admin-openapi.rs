//! Writes the admin API OpenAPI document to `admin-openapi.json` at the
//! repository root. Run through `scripts/gen-openapi.sh`.

use std::path::Path;

fn main() -> std::io::Result<()> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../admin-openapi.json");
    std::fs::write(&path, gim_hub_admin::admin_openapi_json())?;
    println!("wrote {}", path.display());
    Ok(())
}
