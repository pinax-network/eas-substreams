mod abi;
mod pb;
mod schema_parser;
use abi::eas_contract::functions::GetAttestation;
use abi::eas_schema_registry_contract::functions::GetSchema;
use ethabi::decode;
use hex_literal::hex;
use pb::contract::v1 as contract;
use serde_json::{Map, Value};
use substreams_ethereum::pb::eth::v2 as eth;
use substreams_ethereum::rpc::RpcBatch;
use substreams_ethereum::Event;

substreams_ethereum::init!();

const EAS_TRACKED_CONTRACT: [u8; 20] = hex!("4200000000000000000000000000000000000021");
const EAS_SCHEMA_REGISTRY_CONTRACT: [u8; 20] = hex!("4200000000000000000000000000000000000020");

/// Decodes ABI-encoded attestation data into a JSON map using the schema signature string.
/// Returns an empty Map if the data cannot be decoded with the schema.
pub fn decode_data(data: &[u8], schema_signature: &str) -> Map<String, Value> {
    // Strip outer parentheses if the entire schema is wrapped in them
    let schema_signature = if schema_signature.starts_with('(') && schema_signature.ends_with(')') && schema_signature.len() > 2 {
        &schema_signature[1..schema_signature.len() - 1]
    } else {
        schema_signature
    };
    let fields = schema_parser::parse_schema_fields(schema_signature);
    let types = fields.iter().map(|(t, _)| schema_parser::fieldtype_to_paramtype(t)).collect::<Vec<_>>();

    match decode(&types, data) {
        Ok(tokens) => fields.into_iter().zip(tokens.into_iter()).fold(Map::new(), |mut obj, ((ft, name), token)| {
            obj.insert(name, schema_parser::token_to_json_with_schema(&ft, &token));
            obj
        }),
        Err(e) => {
            substreams::log::info!("Error decoding data with schema {}: {:?}", schema_signature, e);
            let mut obj = Map::new();
            obj.insert("error".to_string(), Value::String(format!("Failed to decode: {}", e)));
            obj
        }
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

fn extract_attesteds(blk: &eth::Block, events: &mut contract::Events) {
    let attested_events: Vec<_> = blk
        .receipts()
        .flat_map(|view| {
            view.receipt
                .logs
                .iter()
                .filter(|log| log.address == EAS_TRACKED_CONTRACT)
                .filter_map(move |log| {
                    if let Some(event) = abi::eas_contract::events::Attested::match_and_decode(log) {
                        Some((view, log, event))
                    } else {
                        None
                    }
                })
        })
        .collect();

    let attestations = attested_events
        .chunks(100)
        .flat_map(|chunk| {
            let responses = chunk
                .iter()
                .fold(RpcBatch::new(), |batch, (_, _, event)| {
                    batch.add(GetAttestation { uid: event.uid }, EAS_TRACKED_CONTRACT.to_vec())
                })
                .execute()
                .expect("failed to execute GetAttestation RPC batch")
                .responses;

            responses.into_iter().map(|response| {
                RpcBatch::decode::<
                    (
                        [u8; 32],                   // uid
                        [u8; 32],                   // schema
                        substreams::scalar::BigInt, // recipient
                        substreams::scalar::BigInt, // attester
                        substreams::scalar::BigInt, // time
                        [u8; 32],                   // expirationTime
                        Vec<u8>,                    // refUID
                        Vec<u8>,                    // resolver
                        bool,                       // revocable
                        Vec<u8>,                    // data
                    ),
                    GetAttestation,
                >(&response)
                .expect("failed to decode GetAttestation response")
            })
        })
        .collect::<Vec<_>>();

    let schema_ids: Vec<_> = attestations
        .iter()
        .map(|attestation| attestation.1)
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .collect();

    let schemas: std::collections::HashMap<[u8; 32], String> = schema_ids
        .chunks(100)
        .flat_map(|chunk| {
            let responses = chunk
                .iter()
                .fold(RpcBatch::new(), |batch, schema_id| {
                    batch.add(GetSchema { uid: *schema_id }, EAS_SCHEMA_REGISTRY_CONTRACT.to_vec())
                })
                .execute()
                .expect("failed to execute GetSchema RPC batch")
                .responses;

            responses.into_iter().map(|response| {
                let schema = RpcBatch::decode::<
                    (
                        [u8; 32], // uid
                        Vec<u8>,  // resolver
                        bool,     // revocable
                        String,   // schema
                    ),
                    GetSchema,
                >(&response)
                .expect("failed to decode GetSchema response");

                (schema.0, schema.3)
            })
        })
        .collect();

    events.eas_attesteds.extend(
        attested_events
            .into_iter()
            .zip(attestations.into_iter())
            .map(|((view, log, event), attestation)| {
                let schema = schemas.get(&attestation.1).expect("schema should exist in map");
                let decoded_json = serde_json::Value::Object(decode_data(&attestation.9, schema));

                contract::EasAttested {
                    evt_tx_hash: view.transaction.hash.clone(),
                    evt_index: log.block_index,
                    evt_block_time: Some(blk.timestamp().to_owned()),
                    evt_block_number: blk.number,
                    attester: event.attester,
                    recipient: event.recipient,
                    schema_id: Vec::from(event.schema),
                    uid: Vec::from(event.uid),
                    data: attestation.9,
                    schema: schema.to_string(),
                    decoded_data: decoded_json.to_string(),
                }
            }),
    );
}

fn extract_revokeds(blk: &eth::Block, events: &mut contract::Events) {
    events.eas_revokeds.append(
        &mut blk
            .receipts()
            .flat_map(|view| {
                view.receipt.logs.iter().filter(|log| log.address == EAS_TRACKED_CONTRACT).filter_map(|log| {
                    if let Some(event) = abi::eas_contract::events::Revoked::match_and_decode(log) {
                        return Some(contract::EasRevoked {
                            evt_tx_hash: view.transaction.hash.clone(),
                            evt_index: log.block_index,
                            evt_block_time: Some(blk.timestamp().to_owned()),
                            evt_block_number: blk.number,
                            attester: event.attester,
                            recipient: event.recipient,
                            schema: Vec::from(event.schema),
                            uid: Vec::from(event.uid),
                        });
                    }

                    None
                })
            })
            .collect(),
    );
}

fn extract_revoked_offchains(blk: &eth::Block, events: &mut contract::Events) {
    events.eas_revoked_offchains.append(
        &mut blk
            .receipts()
            .flat_map(|view| {
                view.receipt.logs.iter().filter(|log| log.address == EAS_TRACKED_CONTRACT).filter_map(|log| {
                    if let Some(event) = abi::eas_contract::events::RevokedOffchain::match_and_decode(log) {
                        return Some(contract::EasRevokedOffchain {
                            evt_tx_hash: view.transaction.hash.clone(),
                            evt_index: log.block_index,
                            evt_block_time: Some(blk.timestamp().to_owned()),
                            evt_block_number: blk.number,
                            data: Vec::from(event.data),
                            revoker: event.revoker,
                            timestamp: event.timestamp.to_u64(),
                        });
                    }

                    None
                })
            })
            .collect(),
    );
}

fn extract_timestampeds(blk: &eth::Block, events: &mut contract::Events) {
    events.eas_timestampeds.append(
        &mut blk
            .receipts()
            .flat_map(|view| {
                view.receipt.logs.iter().filter(|log| log.address == EAS_TRACKED_CONTRACT).filter_map(|log| {
                    if let Some(event) = abi::eas_contract::events::Timestamped::match_and_decode(log) {
                        return Some(contract::EasTimestamped {
                            evt_tx_hash: view.transaction.hash.clone(),
                            evt_index: log.block_index,
                            evt_block_time: Some(blk.timestamp().to_owned()),
                            evt_block_number: blk.number,
                            data: Vec::from(event.data),
                            timestamp: event.timestamp.to_u64(),
                        });
                    }

                    None
                })
            })
            .collect(),
    );
}
#[substreams::handlers::map]
fn map_events(blk: eth::Block) -> Result<contract::Events, substreams::errors::Error> {
    let mut events = contract::Events::default();
    extract_attesteds(&blk, &mut events);
    extract_revokeds(&blk, &mut events);
    extract_revoked_offchains(&blk, &mut events);
    extract_timestampeds(&blk, &mut events);
    Ok(events)
}
