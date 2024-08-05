#[cfg(all(not(feature = "udp"), not(feature = "tcp")))]
compile_error!("you must enable support for at least one L4 protocol");
#[cfg(all(not(feature = "output"), not(feature = "input")))]
compile_error!("you must enable support for at least one hook");

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::run_with;

mod packet;
pub use packet::*;

mod types;
pub use types::*;
