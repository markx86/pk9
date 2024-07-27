use nftables::{
    batch::Batch,
    expr::{Expression, Meta, MetaKey, NamedExpression, Payload, PayloadField},
    helper::{self, NftablesError},
    schema::{self, Chain, NfListObject, Rule, SetPolicy, SetTypeValue, Table},
    stmt::{Match, Operator, Queue, Statement},
    types::{NfChainPolicy, NfChainType, NfFamily, NfHook},
};

const FAMILY: NfFamily = NfFamily::INet;

fn generate_statements(
    set_name: &str,
    port_field: &str,
    proto: i32,
    proto_name: &str,
    queue_num: u32,
) -> Vec<Statement> {
    let set_name = format!("@{set_name}");
    vec![
        Statement::Match(Match {
            left: Expression::Named(NamedExpression::Meta(Meta {
                key: MetaKey::L4proto,
            })),
            right: Expression::Number(proto as u32),
            op: Operator::EQ,
        }),
        Statement::Match(Match {
            left: Expression::Named(NamedExpression::Payload(Payload::PayloadField(
                PayloadField {
                    protocol: proto_name.to_string(),
                    field: port_field.to_string(),
                },
            ))),
            right: Expression::String(set_name.clone()),
            op: Operator::IN,
        }),
        Statement::Queue(Queue {
            num: Expression::Number(queue_num),
            flags: None,
        }),
    ]
}

fn generate_chains(table: &str) -> [NfListObject; 2] {
    [
        NfListObject::Chain(Chain::new(
            FAMILY,
            table.to_string(),
            format!("{table}-input"),
            Some(NfChainType::Filter),
            Some(NfHook::Input),
            Some(0),
            None,
            Some(NfChainPolicy::Accept),
        )),
        NfListObject::Chain(Chain::new(
            FAMILY,
            table.to_string(),
            format!("{table}-output"),
            Some(NfChainType::Filter),
            Some(NfHook::Output),
            Some(0),
            None,
            Some(NfChainPolicy::Accept),
        )),
    ]
}

fn generate_rules(table: &str, set_name: &str, proto: i32, queue_num: u32) -> [NfListObject; 2] {
    let proto_name = match proto {
        libc::IPPROTO_TCP => "tcp",
        libc::IPPROTO_UDP => "udp",
        _ => panic!("[!] unsupported protocol {proto}"),
    };
    [
        NfListObject::Rule(Rule::new(
            FAMILY,
            table.to_string(),
            format!("{table}-input"),
            generate_statements(set_name, "dport", proto, proto_name, queue_num),
        )),
        NfListObject::Rule(Rule::new(
            FAMILY,
            table.to_string(),
            format!("{table}-output"),
            generate_statements(set_name, "sport", proto, proto_name, queue_num),
        )),
    ]
}

fn generate_table(table: &str) -> NfListObject {
    NfListObject::Table(Table::new(FAMILY, table.to_string()))
}

fn generate_set(table: &str, name: &str) -> NfListObject {
    NfListObject::Set(schema::Set {
        family: FAMILY,
        table: table.to_string(),
        name: name.to_string(),
        handle: None,
        set_type: SetTypeValue::Single(schema::SetType::InetService),
        policy: Some(SetPolicy::Performance),
        flags: None,
        elem: None,
        timeout: None,
        gc_interval: None,
        size: None,
        comment: None,
    })
}

pub enum NfProtocol {
    TCP,
    UDP,
}

pub struct NfPort(pub u16, pub NfProtocol);

pub struct NfTable {
    table_obj: NfListObject,
    table_name: String,
    udp_set_name: String,
    tcp_set_name: String,
}

impl NfTable {
    pub fn new(queue_num: u32) -> Result<Self, NftablesError> {
        let table_name = "pk9".to_string();
        let table_obj = generate_table(&table_name);
        let udp_set_name = format!("{table_name}-udp");
        let udp_set_obj = generate_set(&table_name, &udp_set_name);
        let tcp_set_name = format!("{table_name}-tcp");
        let tcp_set_obj = generate_set(&table_name, &tcp_set_name);
        let mut batch = Batch::new();
        batch.add(table_obj.clone());
        batch.add(udp_set_obj.clone());
        batch.add(tcp_set_obj.clone());
        generate_chains(&table_name)
            .iter()
            .for_each(|o| batch.add(o.clone()));
        generate_rules(&table_name, &udp_set_name, libc::IPPROTO_UDP, queue_num)
            .iter()
            .for_each(|o| batch.add(o.clone()));
        generate_rules(&table_name, &tcp_set_name, libc::IPPROTO_TCP, queue_num)
            .iter()
            .for_each(|o| batch.add(o.clone()));
        let ruleset = batch.to_nftables();
        match helper::apply_ruleset(&ruleset, None, None) {
            Ok(_) => Ok(Self {
                table_obj,
                table_name,
                udp_set_name,
                tcp_set_name,
            }),
            Err(e) => Err(e),
        }
    }

    pub fn add_ports(&self, ports: &[NfPort]) -> Result<(), NftablesError> {
        let mut udp_elem = Vec::new();
        let mut tcp_elem = Vec::new();
        ports.iter().for_each(|NfPort(port, proto)| {
            let v = match proto {
                NfProtocol::TCP => &mut tcp_elem,
                NfProtocol::UDP => &mut udp_elem,
            };
            v.push(Expression::Number(*port as u32));
        });
        let mut batch = Batch::new();
        if udp_elem.len() > 0 {
            batch.add(NfListObject::Element(schema::Element {
                family: FAMILY,
                table: self.table_name.clone(),
                name: self.udp_set_name.clone(),
                elem: udp_elem,
            }));
        }
        if tcp_elem.len() > 0 {
            batch.add(NfListObject::Element(schema::Element {
                family: FAMILY,
                table: self.table_name.clone(),
                name: self.tcp_set_name.clone(),
                elem: tcp_elem,
            }));
        }
        let ruleset = batch.to_nftables();
        helper::apply_ruleset(&ruleset, None, None)
    }
}

impl Drop for NfTable {
    fn drop(&mut self) {
        let mut batch = Batch::new();
        batch.delete(self.table_obj.clone());
        let ruleset = batch.to_nftables();
        helper::apply_ruleset(&ruleset, None, None).unwrap_or_default();
    }
}
