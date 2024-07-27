use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

mod nft;

fn main() -> std::io::Result<()> {
    let term = Arc::new(AtomicBool::new(false));
    let mut queue = nfq::Queue::open()?;
    queue.bind(0)?;

    let _table = match nft::NfTable::new(&[4444, 6969], nft::NfProtocol::TCP) {
        Ok(t) => {
            println!("[+] nftables rules loaded successfully");
            t
        }
        Err(e) => {
            panic!("[!] error occurred while trying to load nftables rules: {e}");
        }
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
