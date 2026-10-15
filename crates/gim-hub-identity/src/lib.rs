//! Self-certifying identity types and verification for gim.
//!
//! Covers the user root key, the `user_id` derived from it, `DeviceCert`,
//! `DeviceList` and `UserHostingRecord`. This crate must stay free of
//! hub-only dependencies so that gim-core can depend on it.

#[cfg(test)]
mod tests {
    #[test]
    fn crate_name() {
        assert_eq!(env!("CARGO_PKG_NAME"), "gim-hub-identity");
    }
}
