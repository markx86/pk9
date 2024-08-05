use std::{ffi::CString, fmt::Display, io::Error, str::Utf8Error};

use mnl::{cb_run, Bus, CbResult, Socket};
use nftnl::{
    nft_expr, nft_nlmsg_maxsize, nftnl_sys as sys,
    set::{Set, SetKey},
    Batch, Chain, FinalizedBatch, Hook, MsgType, Policy, ProtoFamily, Rule, Table,
};

use crate::{Port, Protocol, Role};

const FAMILY: ProtoFamily = ProtoFamily::Inet;

struct InetService(u16);

impl SetKey for InetService {
    const TYPE: u32 = 13;
    const LEN: u32 = 2;

    fn data(&self) -> Box<[u8]> {
        Box::new(self.0.to_be_bytes())
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum NfHook {
    Out,
    In,
}

impl NfHook {
    fn for_nftnl(&self) -> Hook {
        match self {
            NfHook::Out => Hook::Out,
            NfHook::In => Hook::In,
        }
    }
}

impl Display for NfHook {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            NfHook::Out => "out",
            NfHook::In => "in",
        };
        f.write_str(name)
    }
}

fn new_rules<'a>(
    chain: &'a Chain,
    hook: NfHook,
    role: Role,
    tcp_set: Option<&Set<InetService>>,
    udp_set: Option<&Set<InetService>>,
) -> Vec<Rule<'a>> {
    vec![
        #[cfg(feature = "tcp")]
        {
            let tcp_set = tcp_set.unwrap();
            let mut tcp_rule = Rule::new(chain);
            tcp_rule.add_expr(&nft_expr!(meta l4proto));
            tcp_rule.add_expr(&nft_expr!(cmp == libc::IPPROTO_TCP as u8));
            tcp_rule.add_expr(
                &(if (role == Role::Client && hook == NfHook::Out)
                    || (role == Role::Server && hook == NfHook::In)
                {
                    nft_expr!(payload tcp dport)
                } else {
                    nft_expr!(payload tcp sport)
                }),
            );
            tcp_rule.add_expr(&nft_expr!(lookup tcp_set));
            tcp_rule.add_expr(&nft_expr!(verdict queue));
            tcp_rule
        },
        #[cfg(feature = "udp")]
        {
            let udp_set = udp_set.unwrap();
            let mut udp_rule = Rule::new(chain);
            udp_rule.add_expr(&nft_expr!(meta l4proto));
            udp_rule.add_expr(&nft_expr!(cmp == libc::IPPROTO_UDP as u8));
            udp_rule.add_expr(
                &(if (role == Role::Client && hook == NfHook::Out)
                    || (role == Role::Server && hook == NfHook::In)
                {
                    nft_expr!(payload udp dport)
                } else {
                    nft_expr!(payload udp sport)
                }),
            );
            udp_rule.add_expr(&nft_expr!(lookup udp_set));
            udp_rule.add_expr(&nft_expr!(verdict queue));
            udp_rule
        },
    ]
}

fn new_chain(
    table: &Table,
    hook: NfHook,
    priority: i32,
    policy: Policy,
) -> Result<Chain<'_>, Utf8Error> {
    let table_name = table.get_name().to_str()?;
    let chain_name = format!("{table_name}-{hook}");
    let mut chain = Chain::new(&CString::new(chain_name.as_str()).unwrap(), table);
    chain.set_hook(hook.for_nftnl(), priority);
    chain.set_policy(policy);
    Ok(chain)
}

fn new_set(table: &Table, id: u32, protocol: Protocol) -> Result<Set<InetService>, Utf8Error> {
    let table_name = table.get_name().to_str()?;
    let set_name = format!("{table_name}-{protocol}");
    let set = Set::new(&CString::new(set_name.as_str()).unwrap(), id, table, FAMILY);
    // workaround to "Invalid argument error"
    unsafe {
        sys::nftnl_set_set_u32(set.as_ptr(), sys::NFTNL_SET_FLAGS as u16, 0);
    }
    Ok(set)
}

fn new_table(table_name: &str) -> Table {
    Table::new(&CString::new(table_name).unwrap(), FAMILY)
}

fn socket_recv<'a>(socket: &Socket, buf: &'a mut [u8]) -> Result<Option<&'a [u8]>, Error> {
    let ret = socket.recv(buf)?;
    if ret > 0 {
        Ok(Some(&buf[..ret]))
    } else {
        Ok(None)
    }
}

fn send_batch(finalized: &FinalizedBatch) -> Result<(), Error> {
    let socket = Socket::new(Bus::Netfilter)?;
    socket.send_all(finalized)?;
    let port_id = socket.portid();
    let mut buffer = vec![0; nft_nlmsg_maxsize() as usize];
    let seq = 2;
    while let Some(msg) = socket_recv(&socket, &mut buffer[..])? {
        match cb_run(msg, seq, port_id)? {
            CbResult::Ok => (),
            CbResult::Stop => break,
        }
    }
    Ok(())
}

pub struct NfTable {
    table_name: String,
}

impl NfTable {
    pub fn new(table_name: &str, role: Role) -> Result<Self, Error> {
        let mut batch = Batch::new();
        let table = new_table(table_name);
        let table_name = table_name.to_string();
        batch.add(&table, MsgType::Add);
        let tcp_set = {
            #[cfg(feature = "tcp")]
            {
                let set = new_set(&table, 1337, Protocol::TCP).unwrap();
                batch.add(&set, MsgType::Add);
                Some(set)
            }
            #[cfg(not(feature = "tcp"))]
            None
        };
        let udp_set = {
            #[cfg(feature = "udp")]
            {
                let set = new_set(&table, 1338, Protocol::UDP).unwrap();
                batch.add(&set, MsgType::Add);
                Some(set)
            }
            #[cfg(not(feature = "udp"))]
            None
        };
        #[cfg(feature = "input")]
        {
            let hook = NfHook::In;
            let in_chain = new_chain(&table, hook, 0, Policy::Accept).unwrap();
            let rules = new_rules(&in_chain, hook, role, tcp_set.as_ref(), udp_set.as_ref());
            batch.add(&in_chain, MsgType::Add);
            rules.iter().for_each(|r| batch.add(r, MsgType::Add));
        }
        #[cfg(feature = "output")]
        {
            let hook = NfHook::Out;
            let out_chain = new_chain(&table, hook, 0, Policy::Accept).unwrap();
            let rules = new_rules(&out_chain, hook, role, tcp_set.as_ref(), udp_set.as_ref());
            batch.add(&out_chain, MsgType::Add);
            rules.iter().for_each(|r| batch.add(r, MsgType::Add));
        }

        let finalized = batch.finalize();
        send_batch(&finalized)?;

        Ok(Self { table_name })
    }

    pub fn add_ports(&self, ports: &[Port]) -> Result<(), Error> {
        #[cfg(feature = "tcp")]
        let mut tcp_elem = Vec::new();
        #[cfg(feature = "udp")]
        let mut udp_elem = Vec::new();
        ports.iter().for_each(|Port(port, proto)| {
            let v = match proto {
                #[cfg(feature = "tcp")]
                Protocol::TCP => &mut tcp_elem,
                #[cfg(feature = "udp")]
                Protocol::UDP => &mut udp_elem,
            };
            v.push(InetService(*port));
        });

        let table = new_table(&self.table_name);

        let mut batch = Batch::new();

        #[cfg(feature = "tcp")]
        if tcp_elem.len() > 0 {
            let mut set = new_set(&table, 1337, Protocol::TCP).unwrap();
            tcp_elem.iter().for_each(|p| set.add(p));
            set.elems_iter().for_each(|e| batch.add(&e, MsgType::Add));
        }

        #[cfg(feature = "udp")]
        if udp_elem.len() > 0 {
            let mut set = new_set(&table, 1338, Protocol::UDP).unwrap();
            udp_elem.iter().for_each(|p| set.add(p));
            set.elems_iter().for_each(|e| batch.add(&e, MsgType::Add));
        }

        let finalized = batch.finalize();
        send_batch(&finalized)?;

        Ok(())
    }
}

impl Drop for NfTable {
    fn drop(&mut self) {
        let mut batch = Batch::new();
        let table = new_table(&self.table_name);
        batch.add(&table, MsgType::Del);
        let finalized = batch.finalize();
        match send_batch(&finalized) {
            Ok(()) => (),
            Err(e) => eprintln!("[!] an error occurred while deleting table: {e}"),
        }
    }
}
