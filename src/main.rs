mod nfqueue;
mod nftable;

use nfqueue::{NfAction, NfActions};
use nftable::{NfPort, NfProtocol};

const QUEUE_NUM: u16 = 0;

struct SimpleActions {}

impl NfActions for SimpleActions {
    fn filter(&mut self, protocol: NfProtocol, payload: &[u8]) -> NfAction {
        match protocol {
            NfProtocol::TCP => {
                let hdr_size = if let Some(v) = payload.get(12) {
                    (*v & 0xf0) >> 2
                } else {
                    return NfAction::Drop;
                };
                let (_, data) = payload.split_at(hdr_size as usize);
                if let Some(p) = data.windows(4).position(|w| w == "ciao".as_bytes()) {
                    println!("[+] found salute @ {p}");
                    NfAction::Transform
                } else {
                    NfAction::Pass
                }
            }
            NfProtocol::UDP => NfAction::Pass,
        }
    }
    fn transform(&mut self, protocol: NfProtocol, payload: &[u8]) -> Vec<u8> {
        match protocol {
            NfProtocol::TCP => {
                let hdr_size = (payload[12] & 0xf0) >> 2;
                let (hdr, data) = payload.split_at(hdr_size as usize);
                let mut packet = hdr.to_vec();
                packet.extend_from_slice(&data.to_ascii_uppercase());
                packet
            }
            NfProtocol::UDP => payload.to_vec(),
        }
    }
}

fn main() -> std::io::Result<()> {
    let mut actions = SimpleActions {};
    let mut queue = match nfqueue::NfQueue::new(QUEUE_NUM) {
        Ok(q) => {
            println!("[+] nfqueue successfully created with id {QUEUE_NUM}");
            q
        }
        Err(e) => {
            panic!("[!] could not create nfqueue: {e}");
        }
    };
    let table = match nftable::NfTable::new(QUEUE_NUM) {
        Ok(t) => {
            println!("[+] nftables rules loaded successfully");
            t
        }
        Err(e) => {
            panic!("[!] error occurred while trying to load nftables rules: {e}");
        }
    };

    let ports = [NfPort(4444, NfProtocol::TCP), NfPort(8888, NfProtocol::TCP)];
    match table.add_ports(&ports) {
        Ok(_) => println!("[+] added ports to nftables set"),
        Err(e) => panic!("[!] could not add ports to nftables set: {e}"),
    };

    match queue.run_with(&mut actions) {
        Err(e) => panic!("[!] an error occurred while recieving packets: {e}"),
        Ok(_) => {}
    }

    Ok(())
}
