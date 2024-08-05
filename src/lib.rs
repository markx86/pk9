#[cfg(all(not(feature = "udp"), not(feature = "tcp")))]
compile_error!("you must enable support for at least one L4 protocol");
#[cfg(all(not(feature = "output"), not(feature = "input")))]
compile_error!("you must enable support for at least one hook");

#[cfg(target_os = "linux")]
mod linux;
mod packet;

pub use linux::*;
pub use packet::*;

#[cfg(test)]
mod test {
    use super::{
        nfqueue::NfQueue,
        nftable::{NfPort, NfProtocol, NfTable},
    };

    #[test]
    fn create_nfqueue() {
        NfQueue::new().unwrap();
    }

    #[test]
    fn apply_nftable_client_rules() {
        let table = NfTable::new("test-table-client", crate::nftable::NfRole::Client).unwrap();
        table
            .add_ports(&[
                #[cfg(feature = "tcp")]
                NfPort(4444, NfProtocol::TCP),
                #[cfg(feature = "tcp")]
                NfPort(8888, NfProtocol::TCP),
                #[cfg(feature = "udp")]
                NfPort(4443, NfProtocol::UDP),
                #[cfg(feature = "udp")]
                NfPort(8887, NfProtocol::UDP),
            ])
            .unwrap();
    }

    #[test]
    fn apply_nftable_server_rules() {
        let table = NfTable::new("test-table-server", crate::nftable::NfRole::Server).unwrap();
        table
            .add_ports(&[
                #[cfg(feature = "tcp")]
                NfPort(4444, NfProtocol::TCP),
                #[cfg(feature = "tcp")]
                NfPort(8888, NfProtocol::TCP),
                #[cfg(feature = "udp")]
                NfPort(4443, NfProtocol::UDP),
                #[cfg(feature = "udp")]
                NfPort(8887, NfProtocol::UDP),
            ])
            .unwrap();
    }
}
