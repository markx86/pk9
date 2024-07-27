use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

use nft::NfPort;

mod nft;

fn main() -> std::io::Result<()> {
    let term = Arc::new(AtomicBool::new(false));
    let mut queue = nfq::Queue::open()?;

    queue.bind(0)?;

    let table = match nft::NfTable::new(0) {
        Ok(t) => {
            println!("[+] nftables rules loaded successfully");
            t
        }
        Err(e) => {
            panic!("[!] error occurred while trying to load nftables rules: {e}");
        }
    };

    let ports = [NfPort(4444, nft::NfProtocol::TCP)];
    match table.add_ports(&ports) {
        Ok(_) => println!("[+] added ports to nftables set"),
        Err(e) => panic!("[!] could not add ports to nftables set: {e}"),
    };

    signal_hook::flag::register(signal_hook::consts::SIGINT, Arc::clone(&term))?;
    while !term.load(Ordering::Relaxed) {
        println!("[*] waiting for packets");
        let mut msg = queue.recv()?;
        let mut i = 0;
        println!("[+] got pkt!");
        msg.get_payload().iter().for_each(|b| {
            print!("{:02x} ", *b);
            i += 1;
            if (i & 0xf) == 0 {
                println!();
            }
        });
        if (i & 0xf) > 0 {
            println!();
        }
        msg.set_verdict(nfq::Verdict::Accept);
        queue.verdict(msg)?;
    }

    Ok(())
}
