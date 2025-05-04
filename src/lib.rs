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
use substreams_ethereum::Event;

substreams_ethereum::init!();

const EAS_TRACKED_CONTRACT: [u8; 20] = hex!("4200000000000000000000000000000000000021");
const EAS_SCHEMA_REGISTRY_CONTRACT: [u8; 20] = hex!("4200000000000000000000000000000000000020");

/// Decodes ABI-encoded attestation data into a JSON map using the schema signature string.
pub fn decode_data(data: &[u8], schema_signature: &str) -> Map<String, Value> {
    let fields = schema_parser::parse_schema_fields(schema_signature);
    let types = fields.iter().map(|(t, _)| schema_parser::fieldtype_to_paramtype(t)).collect::<Vec<_>>();
    let tokens = decode(&types, data).expect(format!("Failed to decode data with schema: {}", schema_signature).as_str());
    fields.into_iter().zip(tokens.into_iter()).fold(Map::new(), |mut obj, ((ft, name), token)| {
        obj.insert(name, schema_parser::token_to_json_with_schema(&ft, &token));
        obj
    })
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
                view.receipt.logs.iter().filter(|log| log.address == EAS_TRACKED_CONTRACT).filter_map(|log| {
                    if let Some(event) = abi::eas_contract::events::Attested::match_and_decode(log) {
                        let attestation = GetAttestation { uid: event.uid }
                            .call(EAS_TRACKED_CONTRACT.to_vec())
                            .expect("failed to get attestation");
                        let schema_id = attestation.1;
                        let data = attestation.9;
                        let schema = GetSchema { uid: schema_id }
                            .call(EAS_SCHEMA_REGISTRY_CONTRACT.to_vec())
                            .expect("failed to get schema");
                        let schema = schema.3;
                        let decoded_json = serde_json::Value::Object(decode_data(&data, &schema));

                        return Some(contract::EasAttested {
                            evt_tx_hash: view.transaction.hash.clone(),
                            evt_index: log.block_index,
                            evt_block_time: Some(blk.timestamp().to_owned()),
                            evt_block_number: blk.number,
                            attester: event.attester,
                            recipient: event.recipient,
                            schema_id: Vec::from(event.schema),
                            uid: Vec::from(event.uid),
                            data: Vec::from(data),
                            schema,
                            decoded_data: decoded_json.to_string(),
                        });
                    }
                    None
                })
            })
            .collect(),
    );
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
    map_eas_events(&blk, &mut events);
    Ok(events)
}
