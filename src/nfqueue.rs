use std::{
    io::Error,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

use nfq::{Queue, Verdict};

use crate::nftable::NfProtocol;

pub enum NfAction {
    Pass,
    Drop,
    Transform,
}

pub trait NfActions {
    fn filter(&mut self, protocol: NfProtocol, payload: &[u8]) -> NfAction;
    fn transform(&mut self, protocol: NfProtocol, payload: &[u8]) -> Vec<u8>;
}

enum IpAddress {
    IPv4(u32),
    IPv6(u128),
}

impl IpAddress {
    fn bytes(&self) -> Vec<u8> {
        match self {
            IpAddress::IPv4(a) => a.to_be_bytes().to_vec(),
            IpAddress::IPv6(a) => a.to_be_bytes().to_vec(),
        }
    }
}

struct IpHeader {
    packet_protocol: u8,
    packet_offset: usize,
    packet_length: usize,
    source_address: IpAddress,
    destination_address: IpAddress,
}

fn unwrap_ip_packet(payload: &[u8]) -> Option<(IpHeader, &[u8])> {
    let ip_version = if let Some(v) = payload.get(0) {
        (*v & 0xf0) >> 4
    } else {
        return None;
    };
    let ip_header = match ip_version {
        4 => {
            println!("[*] packet is ipv4");
            if payload.len() < 20 {
                eprintln!("[-] invalid ipv4 packet: payload length is less than the minimum size");
                return None;
            }
            let total_size = u16::from_be_bytes(payload[2..4].try_into().unwrap()) as usize;
            if payload.len() < total_size {
                eprintln!(
                    "[-] invalid ipv4 packet: payload length is shorter than the reported size"
                );
                return None;
            }
            let packet_protocol = payload[9];
            let packet_offset = ((payload[0] & 0xf) as usize) << 2;
            let packet_length = total_size - packet_offset;
            let source_address =
                IpAddress::IPv4(u32::from_be_bytes(payload[12..16].try_into().unwrap()));
            let destination_address =
                IpAddress::IPv4(u32::from_be_bytes(payload[16..20].try_into().unwrap()));
            IpHeader {
                packet_protocol,
                packet_offset,
                packet_length,
                source_address,
                destination_address,
            }
        }
        6 => {
            println!("[*] packet is ipv6");
            if payload.len() < 40 {
                eprintln!("[-] invalid ipv6 packet: payload length is less than the minimum size");
                return None;
            }
            let total_size = u16::from_be_bytes(payload[4..6].try_into().unwrap()) as usize;
            if payload.len() < total_size {
                eprintln!(
                    "[-] invalid ipv6 packet: payload length is shorter than the reported size"
                );
                return None;
            }
            let mut cur = 40;
            let mut next = payload[6];
            while next == 0
                || next == 43
                || next == 44
                // do not check for ESP packets, we don't support them anyways
                || next == 51
                || next == 60
                || next == 135
                || next == 139
                || next == 140
            {
                if cur + 2 > total_size {
                    eprintln!("[-] invalid ipv6 packet: invalid option header");
                    return None;
                }
                let size = match next {
                    44 => 8,
                    51 => (payload[cur + 1] as usize + 2) << 2,
                    _ => (payload[cur + 1] as usize + 1) << 3,
                };
                next = payload[cur];
                cur += size;
            }
            let packet_protocol = next;
            let packet_offset = cur;
            let packet_length = total_size - packet_offset;
            let source_address =
                IpAddress::IPv6(u128::from_be_bytes(payload[8..24].try_into().unwrap()));
            let destination_address =
                IpAddress::IPv6(u128::from_be_bytes(payload[24..40].try_into().unwrap()));
            IpHeader {
                packet_protocol,
                packet_length,
                packet_offset,
                source_address,
                destination_address,
            }
        }
        _ => {
            eprintln!("[-] unknown packet: {ip_version}");
            return None;
        }
    };
    let data = &payload[ip_header.packet_offset..];
    Some((ip_header, data))
}

fn recompute_checksum(ip_header: &IpHeader, protocol: NfProtocol, data: &mut Vec<u8>) {
    let IpHeader {
        packet_protocol,
        source_address,
        destination_address,
        ..
    } = ip_header;
    let checksum_offset = match protocol {
        NfProtocol::TCP => 16,
        NfProtocol::UDP => 6,
    };
    data[checksum_offset + 0] = 0;
    data[checksum_offset + 1] = 0;
    let mut checksum_data = Vec::new();
    checksum_data.extend_from_slice(&source_address.bytes());
    checksum_data.extend_from_slice(&destination_address.bytes());
    checksum_data.push(0);
    checksum_data.push(*packet_protocol);
    checksum_data.extend_from_slice(&(data.len() as u16).to_be_bytes());
    checksum_data.extend_from_slice(data);
    let checksum_data = checksum_data
        .chunks(2)
        .map(|c| {
            let bytes: [u8; 2] = if c.len() == 2 {
                c.try_into().unwrap()
            } else {
                // c.len() == 1
                [c[0], 0]
            };
            u16::from_be_bytes(bytes)
        })
        .collect::<Vec<u16>>();
    let mut checksum = checksum_data
        .iter()
        .map(|w| *w as u32)
        .reduce(|acc, w| acc + w) // this should never overflow
        .unwrap();
    checksum = (checksum >> 16) + (checksum & 0xffff);
    checksum += checksum >> 16;
    let checksum = if checksum == 0xffff && protocol == NfProtocol::UDP {
        checksum as u16
    } else {
        !(checksum as u16)
    };
    let checksum_bytes = checksum.to_be_bytes();
    data[checksum_offset + 0] = checksum_bytes[0];
    data[checksum_offset + 1] = checksum_bytes[1];
}

pub struct NfQueue {
    q: Queue,
}

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
            if let Some((ip_header, data)) = unwrap_ip_packet(payload) {
                let protocol = ip_header.packet_protocol;
                let protocol = match protocol as i32 {
                    libc::IPPROTO_TCP => NfProtocol::TCP,
                    libc::IPPROTO_UDP => NfProtocol::UDP,
                    _ => {
                        eprintln!("[~] unknown protocol {protocol}");
                        msg.set_verdict(Verdict::Accept);
                        self.q.verdict(msg)?;
                        continue;
                    }
                };
                let action = actions.filter(protocol, data);
                verdict = match action {
                    NfAction::Pass => Verdict::Accept,
                    NfAction::Drop => Verdict::Drop,
                    NfAction::Transform => {
                        let mut data = actions.transform(protocol, data);
                        if data.len() != ip_header.packet_length {
                            eprintln!("[~] data extension is not supported, yet");
                            data.resize(ip_header.packet_length, 0);
                        }
                        recompute_checksum(&ip_header, protocol, &mut data);
                        let mut payload = payload.to_vec();
                        payload.truncate(ip_header.packet_offset);
                        payload.extend_from_slice(&data);
                        msg.set_payload(payload);
                        Verdict::Accept
                    }
                };
            } else {
                verdict = Verdict::Drop;
            }
            msg.set_verdict(verdict);
            self.q.verdict(msg)?;
        }
        Ok(())
    }
}
