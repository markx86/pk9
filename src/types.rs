use std::fmt::Display;

use crate::{L4Header, Verdict};

pub trait Actions {
    fn busy_wait(&mut self);
    fn filter(&mut self, l4_header: &L4Header, payload: &[u8]) -> Verdict;
    fn transform(&mut self, l4_header: &mut L4Header, payload: &[u8]) -> Vec<u8>;
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Client,
    Server,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    #[cfg(feature = "tcp")]
    TCP,
    #[cfg(feature = "udp")]
    UDP,
}

impl Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            #[cfg(feature = "tcp")]
            Protocol::TCP => "tcp",
            #[cfg(feature = "udp")]
            Protocol::UDP => "udp",
        };
        f.write_str(name)
    }
}

pub struct Port(pub u16, pub Protocol);
