use std::io::Error;

use crate::{Actions, Port, PortManager, Role};

use self::{nfqueue::NfQueue, nftable::NfTable};

pub mod nfqueue;
pub mod nftable;

pub fn run_with(
    app_name: &str,
    role: Role,
    ports: &[Port],
    actions: &mut dyn Actions,
) -> Result<(), Error> {
    let mut queue = NfQueue::new()?;
    let mut table = NfTable::new(format!("{app_name}-pk9").as_str(), role)?;
    if ports.len() > 0 {
        table.add_ports(ports)?;
    }
    queue.run_with(&mut table, actions)?;
    Ok(())
}

#[cfg(test)]
mod linux_tests {
    use crate::{Port, PortManager, Protocol, Role};

    use super::{nfqueue::NfQueue, nftable::NfTable};

    #[test]
    fn create_nfqueue() {
        NfQueue::new().unwrap();
    }

    #[test]
    fn apply_nftable_client_rules() {
        let mut table = NfTable::new("test-table-client", Role::Client).unwrap();
        table
            .add_ports(&[
                #[cfg(feature = "tcp")]
                Port(4444, Protocol::TCP),
                #[cfg(feature = "tcp")]
                Port(8888, Protocol::TCP),
                #[cfg(feature = "udp")]
                Port(4443, Protocol::UDP),
                #[cfg(feature = "udp")]
                Port(8887, Protocol::UDP),
            ])
            .unwrap();
    }

    #[test]
    fn apply_nftable_server_rules() {
        let mut table = NfTable::new("test-table-server", Role::Server).unwrap();
        table
            .add_ports(&[
                #[cfg(feature = "tcp")]
                Port(4444, Protocol::TCP),
                #[cfg(feature = "tcp")]
                Port(8888, Protocol::TCP),
                #[cfg(feature = "udp")]
                Port(4443, Protocol::UDP),
                #[cfg(feature = "udp")]
                Port(8887, Protocol::UDP),
            ])
            .unwrap();
    }

    #[test]
    fn add_and_remove_ports() {
        let mut table = NfTable::new("test-add-and-remove-ports", Role::Client).unwrap();
        table
            .add_ports(&[
                #[cfg(feature = "tcp")]
                Port(4444, Protocol::TCP),
                #[cfg(feature = "udp")]
                Port(4443, Protocol::UDP),
            ])
            .unwrap();
        let fail = table.add_ports(&[
            #[cfg(feature = "tcp")]
            Port(4444, Protocol::TCP),
            #[cfg(feature = "udp")]
            Port(4443, Protocol::UDP),
        ]);
        assert!(fail.is_err());
        table
            .remove_ports(&[
                #[cfg(feature = "tcp")]
                Port(4444, Protocol::TCP),
                #[cfg(feature = "udp")]
                Port(4443, Protocol::UDP),
            ])
            .unwrap();
        let fail = table.remove_ports(&[
            #[cfg(feature = "tcp")]
            Port(4444, Protocol::TCP),
            #[cfg(feature = "udp")]
            Port(4443, Protocol::UDP),
        ]);
        assert!(fail.is_err());
    }
}
