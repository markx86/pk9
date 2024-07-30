pub enum IpAddress {
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

enum IpType {
    IPv4,
    IPv6,
}

pub struct IpHeader {
    raw: Vec<u8>,
    ip_type: IpType,
    pub l4_protocol: u8,
    pub l4_offset: usize,
    pub l4_length: usize,
    pub src_address: IpAddress,
    pub dst_address: IpAddress,
}

impl IpHeader {
    pub fn bytes(&self) -> &[u8] {
        &self.raw
    }
}

pub fn unwrap_ip_packet(payload: &[u8]) -> Option<(IpHeader, &[u8])> {
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
            let l4_protocol = payload[9];
            let l4_offset = ((payload[0] & 0xf) as usize) << 2;
            let l4_length = total_size - l4_offset;
            let src_address =
                IpAddress::IPv4(u32::from_be_bytes(payload[12..16].try_into().unwrap()));
            let dst_address =
                IpAddress::IPv4(u32::from_be_bytes(payload[16..20].try_into().unwrap()));
            let raw = payload[..l4_offset].to_vec();
            IpHeader {
                raw,
                ip_type: IpType::IPv4,
                l4_protocol,
                l4_offset,
                l4_length,
                src_address,
                dst_address,
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
            let l4_protocol = next;
            let l4_offset = cur;
            let l4_length = total_size - l4_offset;
            let src_address =
                IpAddress::IPv6(u128::from_be_bytes(payload[8..24].try_into().unwrap()));
            let dst_address =
                IpAddress::IPv6(u128::from_be_bytes(payload[24..40].try_into().unwrap()));
            let raw = payload[..l4_offset].to_vec();
            IpHeader {
                raw,
                ip_type: IpType::IPv6,
                l4_protocol,
                l4_length,
                l4_offset,
                src_address,
                dst_address,
            }
        }
        _ => {
            eprintln!("[-] unknown packet: {ip_version}");
            return None;
        }
    };
    let data = &payload[ip_header.l4_offset..];
    Some((ip_header, data))
}

fn generate_pseudo_header(ip_header: &IpHeader) -> Vec<u8> {
    let IpHeader {
        ip_type,
        l4_protocol,
        l4_length,
        src_address,
        dst_address,
        ..
    } = ip_header;
    let mut pseudo = Vec::new();
    pseudo.extend_from_slice(&src_address.bytes());
    pseudo.extend_from_slice(&dst_address.bytes());
    match ip_type {
        IpType::IPv4 => {
            pseudo.extend_from_slice(&[0, *l4_protocol]);
            pseudo.extend_from_slice(&(*l4_length as u16).to_be_bytes());
        }
        IpType::IPv6 => {
            pseudo.extend_from_slice(&(*l4_length as u32).to_be_bytes());
            pseudo.extend_from_slice(&[0, 0, 0, *l4_protocol]);
        }
    };
    pseudo
}

fn compute_checksum(ip_header: &IpHeader, l4_header: &[u8], l4_payload: &[u8]) -> u16 {
    let mut checksum_bytes = Vec::new();
    checksum_bytes.extend_from_slice(&generate_pseudo_header(ip_header));
    checksum_bytes.extend_from_slice(l4_header);
    checksum_bytes.extend_from_slice(l4_payload);
    let checksum_words = checksum_bytes
        .chunks(2)
        .map(|c| {
            if c.len() == 2 {
                u16::from_be_bytes(c.try_into().unwrap())
            } else {
                // c.len() == 1
                u16::from_be_bytes([c[0], 0])
            }
        })
        .collect::<Vec<u16>>();
    let mut checksum = checksum_words
        .iter()
        .map(|w| *w as u32)
        .reduce(|acc, d| acc + d)
        .unwrap();
    checksum = (checksum >> 16) + (checksum & 0xffff);
    checksum += checksum >> 16;
    let checksum = if checksum == 0xffff && ip_header.l4_protocol as i32 == libc::IPPROTO_UDP {
        checksum as u16
    } else {
        !(checksum as u16)
    };
    checksum
}

pub struct TcpHeader {
    bytes: Vec<u8>,
}

impl TcpHeader {
    pub fn from(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 20 {
            eprintln!("[-] invalid tcp packet: length is less than the minimum size");
            None
        } else {
            let length = (bytes[12] & 0xf0) as usize >> 2;
            if length > bytes.len() {
                eprintln!(
                    "[-] invalid tcp packet: length is longer than the amount of bytes received"
                );
                None
            } else {
                let bytes = bytes[..length].to_vec();
                Some(Self { bytes })
            }
        }
    }

    pub fn get_dst_port(&self) -> u16 {
        u16::from_be_bytes(self.bytes[2..4].try_into().unwrap())
    }

    pub fn set_dst_port(&mut self, port: u16) -> &mut Self {
        let port = port.to_be_bytes();
        self.bytes[2] = port[0];
        self.bytes[3] = port[1];
        self
    }

    pub fn get_src_port(&self) -> u16 {
        u16::from_be_bytes(self.bytes[0..2].try_into().unwrap())
    }

    pub fn set_src_port(&mut self, port: u16) -> &mut Self {
        let port = port.to_be_bytes();
        self.bytes[0] = port[0];
        self.bytes[1] = port[1];
        self
    }

    fn get_option_offset_and_size(&self, opt: u8) -> Option<(usize, usize)> {
        let mut cur = 20;
        let len = self.bytes.len();
        while cur < len {
            let opt_type = self.bytes[cur];
            let opt_size = match opt_type {
                0 => break,
                1 => 1,
                _ => {
                    if cur + 1 < len {
                        self.bytes[cur + 1] as usize
                    } else {
                        break;
                    }
                }
            };
            if cur + opt_size > len {
                return None; // invalid option
            }
            if opt_type == opt {
                return Some((cur, opt_size));
            }
            cur += opt_size;
        }
        None
    }

    pub fn get_timestamp(&self) -> Option<u32> {
        if let Some((ts_off, _)) = self.get_option_offset_and_size(5 /* tcp timestamp */) {
            let (start, end) = (ts_off + 2, ts_off + 6);
            Some(u32::from_be_bytes(
                self.bytes[start..end].try_into().unwrap(),
            ))
        } else {
            None
        }
    }

    pub fn length(&self) -> usize {
        (self.bytes[12] & 0xf0) as usize >> 2
    }

    pub fn update_checksum(&mut self, ip_header: &IpHeader, payload: &[u8]) {
        self.bytes[16] = 0;
        self.bytes[17] = 0;
        let checksum = compute_checksum(ip_header, &self.bytes, payload);
        let checksum_bytes = checksum.to_be_bytes();
        self.bytes[16] = checksum_bytes[0];
        self.bytes[17] = checksum_bytes[1];
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

pub struct UdpHeader {
    bytes: Vec<u8>,
}

impl UdpHeader {
    pub fn from(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 8 {
            eprintln!("[-] invalid udp packet: length is less than the minimum size");
            None
        } else {
            if 8 > bytes.len() {
                eprintln!(
                    "[-] invalid udp packet: length is longer than the amount of bytes received"
                );
                None
            } else {
                let bytes = bytes[..8].to_vec();
                Some(Self { bytes })
            }
        }
    }

    pub fn get_dst_port(&self) -> u16 {
        u16::from_be_bytes(self.bytes[2..4].try_into().unwrap())
    }

    pub fn set_dst_port(&mut self, port: u16) -> &mut Self {
        let port = port.to_be_bytes();
        self.bytes[2] = port[0];
        self.bytes[3] = port[1];
        self
    }

    pub fn get_src_port(&self) -> u16 {
        u16::from_be_bytes(self.bytes[0..2].try_into().unwrap())
    }

    pub fn set_src_port(&mut self, port: u16) -> &mut Self {
        let port = port.to_be_bytes();
        self.bytes[0] = port[0];
        self.bytes[1] = port[1];
        self
    }

    pub fn length(&self) -> usize {
        8
    }

    pub fn update_checksum(&mut self, ip_header: &IpHeader, payload: &[u8]) {
        self.bytes[6] = 0;
        self.bytes[7] = 0;
        let checksum = compute_checksum(ip_header, &self.bytes, payload);
        let checksum_bytes = checksum.to_be_bytes();
        self.bytes[6] = checksum_bytes[0];
        self.bytes[7] = checksum_bytes[1];
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

pub enum L4Header {
    TCP(TcpHeader),
    UDP(UdpHeader),
}

pub fn unwrap_l4_packet<'a>(
    ip_header: &IpHeader,
    payload: &'a [u8],
) -> Option<(L4Header, &'a [u8])> {
    let l4_header = match ip_header.l4_protocol as i32 {
        libc::IPPROTO_TCP => {
            if let Some(tcp_header) = TcpHeader::from(&payload) {
                L4Header::TCP(tcp_header)
            } else {
                return None;
            }
        }
        libc::IPPROTO_UDP => {
            if let Some(udp_header) = UdpHeader::from(&payload) {
                L4Header::UDP(udp_header)
            } else {
                return None;
            }
        }
        _ => {
            eprintln!("[-] unsupported protocol {}", ip_header.l4_protocol);
            return None;
        }
    };
    let data = match l4_header {
        L4Header::TCP(ref tcp) => &payload[tcp.length()..],
        L4Header::UDP(ref udp) => &payload[udp.length()..],
    };
    Some((l4_header, data))
}

pub fn recompute_l4_checksum(ip_header: &IpHeader, l4_header: &mut L4Header, data: &[u8]) {
    match l4_header {
        L4Header::TCP(tcp) => tcp.update_checksum(ip_header, data),
        L4Header::UDP(udp) => udp.update_checksum(ip_header, data),
    }
}