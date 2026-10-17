//! The committed `admin-openapi.json` matches the code.

use std::path::Path;

use gim_hub_admin::admin_openapi_json;

#[test]
fn committed_admin_openapi_json_is_up_to_date() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../admin-openapi.json");
    let committed = std::fs::read_to_string(&path).unwrap_or_default();
    assert!(
        committed == admin_openapi_json(),
        "{} is out of date; run scripts/gen-openapi.sh and commit the result",
        path.display()
    );
}
