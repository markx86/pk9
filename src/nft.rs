use nftables::{
    batch::Batch,
    expr::{Expression, Meta, MetaKey, NamedExpression, Payload, PayloadField},
    helper::{self, NftablesError},
    schema::{Chain, NfListObject, Rule, Table},
    stmt::{Match, Operator, Queue, Statement},
    types::{NfChainPolicy, NfChainType, NfFamily, NfHook},
};

fn generate_statements(
    ports: &[u16],
    port_field: &str,
    proto: i32,
    proto_name: &str,
) -> Vec<Statement> {
    let mut s = Vec::new();
    ports.iter().for_each(|port| {
        s.push(Statement::Match(Match {
            left: Expression::Named(NamedExpression::Meta(Meta {
                key: MetaKey::L4proto,
            })),
            right: Expression::Number(proto as u32),
            op: Operator::EQ,
        }));
        s.push(Statement::Match(Match {
            left: Expression::Named(NamedExpression::Payload(Payload::PayloadField(
                PayloadField {
                    protocol: proto_name.to_string(),
                    field: port_field.to_string(),
                },
            ))),
            right: Expression::Number(*port as u32),
            op: Operator::EQ,
        }));
        s.push(Statement::Queue(Queue {
            num: Expression::Number(0),
            flags: None,
        }));
    });
    s
}

fn generate_chains(table: &str, family: NfFamily) -> [NfListObject; 2] {
    [
        NfListObject::Chain(Chain::new(
            family,
            table.to_string(),
            format!("{table}-input"),
            Some(NfChainType::Filter),
            Some(NfHook::Input),
            Some(0),
            None,
            Some(NfChainPolicy::Accept),
        )),
        NfListObject::Chain(Chain::new(
            family,
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

fn generate_rules(
    table: &str,
    ports: &[u16],
    proto: i32,
    proto_name: &str,
    family: NfFamily,
) -> [NfListObject; 2] {
    [
        NfListObject::Rule(Rule::new(
            family,
            table.to_string(),
            format!("{table}-input"),
            generate_statements(ports, "dport", proto, proto_name),
        )),
        NfListObject::Rule(Rule::new(
            family,
            table.to_string(),
            format!("{table}-output"),
            generate_statements(ports, "sport", proto, proto_name),
        )),
    ]
}

fn generate_table(table: &str, family: NfFamily) -> NfListObject {
    NfListObject::Table(Table::new(family, table.to_string()))
}

pub enum NfProtocol {
    TCP,
    UDP,
}

pub struct NfTable {
    table_obj: NfListObject,
}

impl NfTable {
    pub fn new(ports: &[u16], proto: NfProtocol) -> Result<Self, NftablesError> {
        const FAMILY: NfFamily = NfFamily::INet;
        let proto_name = match proto {
            NfProtocol::UDP => "udp",
            NfProtocol::TCP => "tcp",
        };
        let proto = match proto {
            NfProtocol::UDP => libc::IPPROTO_UDP,
            NfProtocol::TCP => libc::IPPROTO_TCP,
        };
        let table_name = format!("pk9-{proto_name}");
        let table_obj = generate_table(&table_name, FAMILY);
        let mut batch = Batch::new();
        batch.add(table_obj.clone());
        generate_chains(&table_name, FAMILY)
            .iter()
            .for_each(|o| batch.add(o.clone()));
        generate_rules(&table_name, ports, proto, proto_name, FAMILY)
            .iter()
            .for_each(|o| batch.add(o.clone()));
        let ruleset = batch.to_nftables();
        match helper::apply_ruleset(&ruleset, None, None) {
            Ok(_) => Ok(Self { table_obj }),
            Err(e) => Err(e),
        }
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
