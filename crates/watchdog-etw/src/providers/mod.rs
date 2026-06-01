//! One module per ETW provider we consume. Each module exposes a
//! `build(tx, dropped) -> Provider` that registers its callback.

pub mod dns_client;
pub mod kernel_file;
pub mod kernel_network;
pub mod kernel_process;
pub mod kernel_registry;
