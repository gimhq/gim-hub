//! S2S op handlers and the client side of synchronous S2S requests.
//!
//! - [`device_list`]: remote DeviceLists (§5.1): the cache, `GetDeviceList`
//!   and `NotifyDeviceList`.
//! - [`claim`]: cross-hub KeyPackage claims (§5.2, §6.1).

pub mod claim;
pub mod device_list;

fn request_id() -> String {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).expect("random request id");
    hex::encode(bytes)
}
