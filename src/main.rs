#[cfg(target_os = "linux")]
mod linux;
mod packet;

use linux::nfqueue::NfQueue;
use linux::nftable::{NfPort, NfProtocol, NfTable};
use packet::{Actions, L4Header};

use crate::packet::Verdict;

const QUEUE_NUM: u16 = 0;

struct SimpleActions {}

impl Actions for SimpleActions {
    fn filter(&mut self, l4_header: &L4Header, payload: &[u8]) -> Verdict {
        match l4_header {
            L4Header::TCP(_) => {
                if let Some(p) = payload.windows(4).position(|w| w == "ciao".as_bytes()) {
                    println!("[+] found salute at offset {p}");
                    Verdict::Transform
                } else {
                    Verdict::Pass
                }
            }
        }
    }

    fn transform(&mut self, l4_header: &L4Header, payload: &[u8]) -> Vec<u8> {
        match l4_header {
            L4Header::TCP(_) => payload.to_ascii_uppercase().to_vec(),
        }
    }
}

fn main() -> std::io::Result<()> {
    let mut actions = SimpleActions {};
    let mut queue = match NfQueue::new(QUEUE_NUM) {
        Ok(q) => {
            println!("[+] nfqueue successfully created with id {QUEUE_NUM}");
            q
        }
        Err(e) => {
            panic!("[!] could not create nfqueue: {e}");
        }
    };
    let table = match NfTable::new(QUEUE_NUM) {
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
