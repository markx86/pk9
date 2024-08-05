use std::{
    io::Error,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

use libc::{EAGAIN, EWOULDBLOCK};
use nfq::{Queue, Verdict};

use crate::packet::{self, Actions, L4Header};

pub struct NfQueue {
    q: Queue,
}

impl NfQueue {
    pub fn new() -> Result<Self, Error> {
        let mut q = Queue::open()?;
        q.bind(0)?;
        q.set_nonblocking(true);
        Ok(Self { q })
    }

    pub fn run_with(&mut self, actions: &mut dyn Actions) -> Result<(), Error> {
        let term = Arc::new(AtomicBool::new(false));
        signal_hook::flag::register(signal_hook::consts::SIGINT, Arc::clone(&term))?;
        println!("[*] waiting for packets");
        while !term.load(Ordering::Relaxed) {
            let mut msg = match self.q.recv() {
                Ok(msg) => msg,
                Err(e) => {
                    if let Some(errno) = e.raw_os_error() {
                        if errno == EWOULDBLOCK || errno == EAGAIN {
                            actions.busy_wait();
                            continue;
                        }
                    }
                    return Err(e);
                }
            };
            println!("[+] got pkt!");
            let payload = msg.get_payload();
            let verdict;
            if let Some((ip_header, payload)) = packet::unwrap_ip_packet(payload) {
                if let Some((mut l4_header, payload)) =
                    packet::unwrap_l4_packet(&ip_header, payload)
                {
                    let action = actions.filter(&l4_header, payload);
                    verdict = match action {
                        packet::Verdict::Pass => Verdict::Accept,
                        packet::Verdict::Drop => Verdict::Drop,
                        packet::Verdict::Transform => {
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
                                #[cfg(feature = "tcp")]
                                L4Header::TCP(ref tcp) => tcp.bytes(),
                                #[cfg(feature = "udp")]
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