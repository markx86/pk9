use std::{
    io::Error,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

use nfq::{Queue, Verdict};

use crate::packet::{self, L4Header};

pub enum NfAction {
    Pass,
    Drop,
    Transform,
}

pub trait NfActions {
    fn filter(&mut self, l4_header: &L4Header, payload: &[u8]) -> NfAction;
    fn transform(&mut self, l4_header: &L4Header, payload: &[u8]) -> Vec<u8>;
}

pub struct NfQueue {
    q: Queue,
}

// fn dump_packet(d: &[u8]) {
//     let mut i = 0;
//     d.iter().for_each(|b| {
//         i += 1;
//         print!("{:02x} ", *b);
//         if (i & 3) == 0 {
//             println!();
//         }
//     });
//     if (i & 3) != 0 {
//         println!();
//     }
// }

impl NfQueue {
    pub fn new(queue_num: u16) -> Result<Self, Error> {
        let mut q = Queue::open()?;
        q.bind(queue_num)?;
        Ok(Self { q })
    }

    pub fn run_with(&mut self, actions: &mut dyn NfActions) -> Result<(), Error> {
        let term = Arc::new(AtomicBool::new(false));
        signal_hook::flag::register(signal_hook::consts::SIGINT, Arc::clone(&term))?;
        while !term.load(Ordering::Relaxed) {
            println!("[*] waiting for packets");
            let mut msg = self.q.recv()?;
            println!("[+] got pkt!");
            let payload = msg.get_payload();
            let verdict;
            if let Some((ip_header, payload)) = packet::unwrap_ip_packet(payload) {
                if let Some((mut l4_header, payload)) =
                    packet::unwrap_l4_packet(&ip_header, payload)
                {
                    let action = actions.filter(&l4_header, payload);
                    verdict = match action {
                        NfAction::Pass => Verdict::Accept,
                        NfAction::Drop => Verdict::Drop,
                        NfAction::Transform => {
                            let initial_length = payload.len();
                            let mut data = actions.transform(&l4_header, payload);
                            if data.len() != initial_length {
                                eprintln!("[~] data extension is not supported, yet");
                                data.resize(initial_length, 0);
                            }
                            packet::recompute_l4_checksum(&ip_header, &mut l4_header, &data);
                            let mut payload = Vec::new();
                            payload.extend_from_slice(ip_header.bytes());
                            payload.extend_from_slice(match l4_header {
                                L4Header::TCP(ref tcp) => tcp.bytes(),
                                L4Header::UDP(ref udp) => udp.bytes(),
                            });
                            payload.extend_from_slice(&data);
                            msg.set_payload(payload);
                            Verdict::Accept
                        }
                    };
                } else {
                    verdict = Verdict::Accept;
                }
            } else {
                verdict = Verdict::Drop;
            }
            msg.set_verdict(verdict);
            self.q.verdict(msg)?;
        }
        Ok(())
    }
}
