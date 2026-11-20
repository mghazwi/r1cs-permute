//! Derive the RLN partial-witness mask from a witnesscalc graph.
//!
//! The protobuf fields and dependency propagation match ZeroKit's
//! `rln/src/circuit/iden3calc/{proto,graph,storage}.rs`. We only track
//! known/unknown dependencies, so private input values are not needed.
use prost::Message;
use std::{
    collections::{HashMap, HashSet},
    io::{self, Cursor, Read},
};

#[derive(Clone, PartialEq, Message)]
struct Input {
    #[prost(uint32, tag = "1")]
    idx: u32,
}
#[derive(Clone, PartialEq, Message)]
struct Constant {}
#[derive(Clone, PartialEq, Message)]
struct Unary {
    #[prost(uint32, tag = "2")]
    a: u32,
}
#[derive(Clone, PartialEq, Message)]
struct Binary {
    #[prost(uint32, tag = "2")]
    a: u32,
    #[prost(uint32, tag = "3")]
    b: u32,
}
#[derive(Clone, PartialEq, Message)]
struct Ternary {
    #[prost(uint32, tag = "2")]
    a: u32,
    #[prost(uint32, tag = "3")]
    b: u32,
    #[prost(uint32, tag = "4")]
    c: u32,
}
#[derive(Clone, PartialEq, Message)]
struct Node {
    #[prost(oneof = "node::Kind", tags = "1,2,3,4,5")]
    kind: Option<node::Kind>,
}
mod node {
    #[derive(Clone, PartialEq, prost::Oneof)]
    pub enum Kind {
        #[prost(message, tag = "1")]
        Input(super::Input),
        #[prost(message, tag = "2")]
        Constant(super::Constant),
        #[prost(message, tag = "3")]
        Unary(super::Unary),
        #[prost(message, tag = "4")]
        Binary(super::Binary),
        #[prost(message, tag = "5")]
        Ternary(super::Ternary),
    }
}
#[derive(Clone, PartialEq, Message)]
struct Signal {
    #[prost(uint32, tag = "1")]
    offset: u32,
    #[prost(uint32, tag = "2")]
    len: u32,
}
#[derive(Clone, PartialEq, Message)]
struct Metadata {
    #[prost(uint32, repeated, tag = "1")]
    witness_signals: Vec<u32>,
    #[prost(map = "string, message", tag = "2")]
    inputs: HashMap<String, Signal>,
}
fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

pub fn rln_dynamic_indices(bytes: &[u8], expected_wires: usize) -> io::Result<Vec<usize>> {
    let mut cursor = Cursor::new(bytes);
    let mut magic = [0u8; 14];
    cursor.read_exact(&mut magic)?;
    if &magic != b"wtns.graph.001" {
        return Err(invalid("unsupported witness graph format"));
    }
    let mut count = [0u8; 8];
    cursor.read_exact(&mut count)?;
    let count =
        usize::try_from(u64::from_le_bytes(count)).map_err(|_| invalid("too many nodes"))?;
    if count > bytes.len() {
        return Err(invalid("invalid graph node count"));
    }
    let mut rest = &bytes[cursor.position() as usize..];
    let mut nodes = Vec::with_capacity(count);
    for _ in 0..count {
        nodes.push(
            Node::decode_length_delimited(&mut rest).map_err(|_| invalid("invalid graph node"))?,
        );
    }
    let metadata = Metadata::decode_length_delimited(&mut rest)
        .map_err(|_| invalid("invalid graph metadata"))?;
    if rest.len() != 8 {
        return Err(invalid("unexpected graph trailer"));
    }
    if metadata.witness_signals.len() != expected_wires {
        return Err(invalid("graph witness count does not match R1CS wires"));
    }

    let known = [
        "identitySecret",
        "userMessageLimit",
        "pathElements",
        "identityPathIndex",
    ];
    let dynamic = ["messageId", "x", "externalNullifier"];
    if known
        .iter()
        .chain(dynamic.iter())
        .any(|name| !metadata.inputs.contains_key(*name))
    {
        return Err(invalid("graph is missing expected RLN inputs"));
    }
    if metadata.inputs.keys().any(|name| {
        !known.contains(&name.as_str())
            && !dynamic.contains(&name.as_str())
            && name != "selectorUsed"
    }) {
        return Err(invalid(
            "graph has unexpected inputs; RLN mask policy must be reviewed",
        ));
    }
    let mut all_inputs = HashSet::new();
    for signal in metadata.inputs.values() {
        let end = signal
            .offset
            .checked_add(signal.len)
            .ok_or_else(|| invalid("input range overflow"))?;
        if signal.len == 0 || signal.offset == 0 {
            return Err(invalid("invalid graph input range"));
        }
        for i in signal.offset..end {
            if !all_inputs.insert(i) {
                return Err(invalid("overlapping graph input ranges"));
            }
        }
    }
    let message_len = metadata.inputs["messageId"].len;
    if message_len > 1 && metadata.inputs.get("selectorUsed").map(|s| s.len) != Some(message_len) {
        return Err(invalid(
            "multi-message RLN graph requires matching selectorUsed inputs",
        ));
    }
    let mut dynamic_inputs = HashSet::new();
    for name in dynamic.into_iter().chain(
        metadata
            .inputs
            .contains_key("selectorUsed")
            .then_some("selectorUsed"),
    ) {
        let signal = &metadata.inputs[name];
        if signal.len == 0 {
            return Err(invalid("empty dynamic input"));
        }
        let end = signal
            .offset
            .checked_add(signal.len)
            .ok_or_else(|| invalid("input range overflow"))?;
        dynamic_inputs.extend(signal.offset..end);
    }
    let mut affected = Vec::with_capacity(nodes.len());
    for node in nodes {
        let get = |i: u32| {
            affected
                .get(i as usize)
                .copied()
                .ok_or_else(|| invalid("graph is not topologically ordered"))
        };
        let value = match node.kind.ok_or_else(|| invalid("missing graph node"))? {
            node::Kind::Input(input) => {
                if input.idx != 0 && !all_inputs.contains(&input.idx) {
                    return Err(invalid("graph node references an unmapped input"));
                }
                dynamic_inputs.contains(&input.idx)
            }
            node::Kind::Constant(_) => false,
            node::Kind::Unary(op) => get(op.a)?,
            node::Kind::Binary(op) => get(op.a)? | get(op.b)?,
            node::Kind::Ternary(op) => get(op.a)? | get(op.b)? | get(op.c)?,
        };
        affected.push(value);
    }
    let mut indices = Vec::new();
    for (j, node) in metadata.witness_signals.iter().enumerate() {
        if *affected
            .get(*node as usize)
            .ok_or_else(|| invalid("witness node index out of range"))?
        {
            if j == 0 {
                return Err(invalid("constant-one witness cannot be dynamic"));
            }
            indices.push(j);
        }
    }
    Ok(indices)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn tracks_rln_dynamic_inputs_through_graph_nodes() {
        let names = [
            "identitySecret",
            "userMessageLimit",
            "pathElements",
            "identityPathIndex",
            "messageId",
            "x",
            "externalNullifier",
        ];
        let inputs = names
            .iter()
            .enumerate()
            .map(|(i, name)| {
                (
                    name.to_string(),
                    Signal {
                        offset: (i + 1) as u32,
                        len: 1,
                    },
                )
            })
            .collect();
        let nodes = vec![
            node::Kind::Input(Input { idx: 0 }),
            node::Kind::Input(Input { idx: 1 }),
            node::Kind::Input(Input { idx: 5 }),
            node::Kind::Binary(Binary { a: 1, b: 2 }),
            node::Kind::Unary(Unary { a: 3 }),
            node::Kind::Ternary(Ternary { a: 0, b: 1, c: 4 }),
        ];
        let mut graph = b"wtns.graph.001".to_vec();
        graph.extend_from_slice(&(nodes.len() as u64).to_le_bytes());
        for node in nodes {
            Node { kind: Some(node) }
                .encode_length_delimited(&mut graph)
                .unwrap();
        }
        Metadata {
            witness_signals: vec![0, 1, 2, 3, 4, 5],
            inputs,
        }
        .encode_length_delimited(&mut graph)
        .unwrap();
        graph.extend_from_slice(&0u64.to_le_bytes());
        assert_eq!(rln_dynamic_indices(&graph, 6).unwrap(), vec![2, 3, 4, 5]);
        assert!(rln_dynamic_indices(&graph, 5).is_err());
    }
}
