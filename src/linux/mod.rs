use std::io::Error;

use crate::{Actions, Port, Role};

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
    let table = NfTable::new(format!("{app_name}-pk9").as_str(), role)?;
    table.add_ports(ports)?;
    queue.run_with(actions)?;
    Ok(())
}

#[cfg(test)]
mod linux_tests {
    use crate::{Port, Protocol, Role};

    use super::{nfqueue::NfQueue, nftable::NfTable};

    #[test]
    fn create_nfqueue() {
        NfQueue::new().unwrap();
    }

    #[test]
    fn apply_nftable_client_rules() {
        let table = NfTable::new("test-table-client", Role::Client).unwrap();
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
        let table = NfTable::new("test-table-server", Role::Server).unwrap();
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
}
