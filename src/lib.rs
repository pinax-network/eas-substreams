mod abi;
mod pb;
use abi::eas_contract::functions::GetAttestation;
use abi::eas_schema_registry_contract::functions::GetSchema;
use ethabi::{decode, ParamType, Token};
use hex_literal::hex;
use pb::contract::v1 as contract;
use substreams::Hex;
use substreams_ethereum::pb::eth::v2 as eth;
use substreams_ethereum::Event;

use serde_json::{json, Map, Value};

substreams_ethereum::init!();

const EAS_TRACKED_CONTRACT: [u8; 20] = hex!("4200000000000000000000000000000000000021");
const EAS_SCHEMA_REGISTRY_CONTRACT: [u8; 20] = hex!("4200000000000000000000000000000000000020");

pub fn bytes_to_hex(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return "".to_string();
    } else {
        format! {"0x{}", Hex::encode(bytes)}.to_string()
    }
}

/// Decodes ABI-encoded attestation data into a JSON map using the schema signature string.
pub fn decode_data(data: &[u8], schema_signature: &str) -> Map<String, Value> {
    let fields = parse_schema_fields(schema_signature);
    let types = fields.iter().map(|(t, _)| t.clone()).collect::<Vec<_>>();
    let tokens = match decode(&types, data) {
        Ok(tokens) => tokens,
        Err(e) => {
            substreams::log::info!("Failed to decode data: {:?}", e);
            vec![]
        }
    };
    let mut obj = Map::new();
    for ((_, name), token) in fields.into_iter().zip(tokens.into_iter()) {
        obj.insert(name, token_to_json(&token));
    }
    obj
}

/// Parses a schema signature string into a Vec<(ParamType, String)>.
fn parse_schema_fields(schema: &str) -> Vec<(ParamType, String)> {
    fn parse_type(typ: &str) -> ParamType {
        let typ = typ.trim();
        if typ.starts_with("tuple(") && typ.ends_with(')') {
            let inner = &typ[6..typ.len() - 1];
            let inner_types = parse_schema_fields(inner)
                .into_iter()
                .map(|(t, _)| t)
                .collect();
            ParamType::Tuple(inner_types)
        } else if typ.ends_with("[]") {
            let inner_type = &typ[..typ.len() - 2];
            ParamType::Array(Box::new(parse_type(inner_type)))
        } else {
            match typ {
                "bytes32" => ParamType::FixedBytes(32),
                "uint8" => ParamType::Uint(8),
                "uint16" => ParamType::Uint(16),
                "uint32" => ParamType::Uint(32),
                "uint64" => ParamType::Uint(64),
                "uint128" => ParamType::Uint(128),
                "uint256" => ParamType::Uint(256),
                "bool" => ParamType::Bool,
                "string" => ParamType::String,
                "address" => ParamType::Address,
                _ => panic!("Unsupported type: {}", typ),
            }
        }
    }

    // Split schema by commas, but handle nested tuples (do not split inside parentheses)
    let mut fields = Vec::new();
    let mut depth = 0;
    let mut start = 0;
    let chars: Vec<_> = schema.chars().collect();
    for (i, c) in chars.iter().enumerate() {
        match c {
            '(' => depth += 1,
            ')' => depth -= 1,
            ',' if depth == 0 => {
                let field = &schema[start..i];
                let mut parts = field.trim().split_whitespace();
                let typ = parts.next().unwrap();
                let name = parts
                    .next()
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| "field".to_string());
                fields.push((parse_type(typ), name));
                start = i + 1;
            }
            _ => {}
        }
    }
    // Last field
    if start < schema.len() {
        let field = &schema[start..];
        let mut parts = field.trim().split_whitespace();
        let typ = parts.next().unwrap();
        let name = parts
            .next()
            .map(|s| s.to_string())
            .unwrap_or_else(|| "field".to_string());
        fields.push((parse_type(typ), name));
    }
    fields
}

fn token_to_json(token: &Token) -> Value {
    match token {
        Token::Address(addr) => json!(format!("0x{}", Hex::encode(addr))),
        Token::FixedBytes(bytes) | Token::Bytes(bytes) => {
            json!(format!("0x{}", Hex::encode(bytes)))
        }
        Token::Int(i) | Token::Uint(i) => json!(i.to_string()),
        Token::Bool(b) => json!(*b),
        Token::String(s) => json!(s),
        Token::Array(arr) | Token::FixedArray(arr) => {
            Value::Array(arr.iter().map(token_to_json).collect())
        }
        Token::Tuple(tuple) => Value::Array(tuple.iter().map(token_to_json).collect()),
    }
}

#[derive(Debug, Clone)]
pub struct Attestation {
    pub uid: [u8; 32],
    pub schema: [u8; 32],
    pub time: u64,
    pub expiration_time: u64,
    pub revocation_time: u64,
    pub ref_uid: [u8; 32],
    pub recipient: [u8; 20], // Ethereum address
    pub attester: [u8; 20],  // Ethereum address
    pub revocable: bool,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct Schema {
    pub uid_id: [u8; 32],
    pub resolver: Vec<u8>,
    pub revocable: bool,
    pub schema: String,
}

fn map_eas_events(blk: &eth::Block, events: &mut contract::Events) {
    events.eas_attesteds.append(
        &mut blk
            .receipts()
            .flat_map(|view| {
                view.receipt
                    .logs
                    .iter()
                    .filter(|log| log.address == EAS_TRACKED_CONTRACT)
                    .filter_map(|log| {
                        if let Some(event) =
                            abi::eas_contract::events::Attested::match_and_decode(log)
                        {
                            // if bytes_to_hex(&event.schema) != "0xb763e62d940bed6f527dd82418e146a904e62a297b8fa765c9b3e1f0bc6fdd68" {
                            //     return None;
                            // }
                            let uid = event.uid;
                            let res = GetAttestation { uid }
                                .call(EAS_TRACKED_CONTRACT.to_vec())
                                .expect("failed to get attestation");
                            let attestation = Attestation {
                                uid: res.0,
                                schema: res.1,
                                time: res.2.to_u64(),
                                expiration_time: res.3.to_u64(),
                                revocation_time: res.4.to_u64(),
                                ref_uid: res.5,
                                recipient: {
                                    let mut arr = [0u8; 20];
                                    arr.copy_from_slice(&res.6);
                                    arr
                                },
                                attester: {
                                    let mut arr = [0u8; 20];
                                    arr.copy_from_slice(&res.7);
                                    arr
                                },
                                revocable: res.8,
                                data: res.9,
                            };
                            let res = GetSchema {
                                uid: attestation.schema,
                            }
                            .call(EAS_SCHEMA_REGISTRY_CONTRACT.to_vec())
                            .expect("failed to get schema");

                            let schema = Schema {
                                uid_id: res.0,
                                resolver: res.1,
                                revocable: res.2,
                                schema: res.3,
                            };

                            let decoded_json = serde_json::Value::Object(decode_data(
                                &attestation.data,
                                &schema.schema,
                            ));

                            substreams::log::info!("decoded json: {}", decoded_json.to_string());

                            return Some(contract::EasAttested {
                                evt_tx_hash: Hex(&view.transaction.hash).to_string(),
                                evt_index: log.block_index,
                                evt_block_time: Some(blk.timestamp().to_owned()),
                                evt_block_number: blk.number,
                                attester: event.attester,
                                recipient: event.recipient,
                                schema_id: Vec::from(event.schema),
                                uid: Vec::from(event.uid),
                                data: Vec::from(attestation.data),
                                schema: schema.schema,
                                decoded_data: decoded_json.to_string(),
                            });
                        }

                        None
                    })
            })
            .collect(),
    );
    // events.eas_revokeds.append(
    //     &mut blk
    //         .receipts()
    //         .flat_map(|view| {
    //             view.receipt
    //                 .logs
    //                 .iter()
    //                 .filter(|log| log.address == EAS_TRACKED_CONTRACT)
    //                 .filter_map(|log| {
    //                     if let Some(event) =
    //                         abi::eas_contract::events::Revoked::match_and_decode(log)
    //                     {
    //                         return Some(contract::EasRevoked {
    //                             evt_tx_hash: Hex(&view.transaction.hash).to_string(),
    //                             evt_index: log.block_index,
    //                             evt_block_time: Some(blk.timestamp().to_owned()),
    //                             evt_block_number: blk.number,
    //                             attester: event.attester,
    //                             recipient: event.recipient,
    //                             schema: Vec::from(event.schema),
    //                             uid: Vec::from(event.uid),
    //                         });
    //                     }

    //                     None
    //                 })
    //         })
    //         .collect(),
    // );
    // events.eas_revoked_offchains.append(
    //     &mut blk
    //         .receipts()
    //         .flat_map(|view| {
    //             view.receipt
    //                 .logs
    //                 .iter()
    //                 .filter(|log| log.address == EAS_TRACKED_CONTRACT)
    //                 .filter_map(|log| {
    //                     if let Some(event) =
    //                         abi::eas_contract::events::RevokedOffchain::match_and_decode(log)
    //                     {
    //                         return Some(contract::EasRevokedOffchain {
    //                             evt_tx_hash: Hex(&view.transaction.hash).to_string(),
    //                             evt_index: log.block_index,
    //                             evt_block_time: Some(blk.timestamp().to_owned()),
    //                             evt_block_number: blk.number,
    //                             data: Vec::from(event.data),
    //                             revoker: event.revoker,
    //                             timestamp: event.timestamp.to_u64(),
    //                         });
    //                     }

    //                     None
    //                 })
    //         })
    //         .collect(),
    // );
    // events.eas_timestampeds.append(
    //     &mut blk
    //         .receipts()
    //         .flat_map(|view| {
    //             view.receipt
    //                 .logs
    //                 .iter()
    //                 .filter(|log| log.address == EAS_TRACKED_CONTRACT)
    //                 .filter_map(|log| {
    //                     if let Some(event) =
    //                         abi::eas_contract::events::Timestamped::match_and_decode(log)
    //                     {
    //                         return Some(contract::EasTimestamped {
    //                             evt_tx_hash: Hex(&view.transaction.hash).to_string(),
    //                             evt_index: log.block_index,
    //                             evt_block_time: Some(blk.timestamp().to_owned()),
    //                             evt_block_number: blk.number,
    //                             data: Vec::from(event.data),
    //                             timestamp: event.timestamp.to_u64(),
    //                         });
    //                     }

    //                     None
    //                 })
    //         })
    //         .collect(),
    // );
}
#[substreams::handlers::map]
fn map_events(blk: eth::Block) -> Result<contract::Events, substreams::errors::Error> {
    let mut events = contract::Events::default();
    map_eas_events(&blk, &mut events);
    Ok(events)
}
