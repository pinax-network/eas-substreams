use ethabi::{ParamType, Token};
use serde_json::{json, Value};
use std::str::FromStr;
use substreams::Hex;

#[derive(Debug, Clone)]
pub enum FieldType {
    Primitive(ParamType),
    Tuple(Vec<(FieldType, String)>),
    Array(Box<FieldType>),
}

impl FromStr for FieldType {
    type Err = String;
    fn from_str(typ: &str) -> Result<Self, Self::Err> {
        let typ = typ.trim();
        if typ.starts_with("tuple(") && typ.ends_with(')') {
            Ok(FieldType::Tuple(parse_schema_fields(&typ[6..typ.len() - 1])))
        } else if typ.ends_with("[]") {
            Ok(FieldType::Array(Box::new(FieldType::from_str(&typ[..typ.len() - 2])?)))
        } else {
            let param_type = if typ == "bytes" {
                ParamType::Bytes
            } else if let Some(bits) = typ.strip_prefix("uint") {
                ParamType::Uint(bits.parse::<usize>().map_err(|_| format!("Invalid uint size: {}", bits))?)
            } else if let Some(bits) = typ.strip_prefix("int") {
                ParamType::Int(bits.parse::<usize>().map_err(|_| format!("Invalid int size: {}", bits))?)
            } else if let Some(bits) = typ.strip_prefix("bytes") {
                ParamType::FixedBytes(bits.parse::<usize>().map_err(|_| format!("Invalid bytes size: {}", bits))?)
            } else {
                match typ {
                    "bool" => ParamType::Bool,
                    "string" => ParamType::String,
                    "address" => ParamType::Address,
                    _ => return Err(format!("Unsupported type: {}", typ)),
                }
            };
            Ok(FieldType::Primitive(param_type))
        }
    }
}

fn parse_field(field: &str) -> (FieldType, String) {
    let mut type_end = 0;
    let mut inner_depth = 0;
    for (j, ch) in field.char_indices().rev() {
        match ch {
            ')' => inner_depth += 1,
            '(' => inner_depth -= 1,
            ' ' if inner_depth == 0 => {
                type_end = j;
                break;
            }
            _ => {}
        }
    }
    let (typ, name) = if type_end > 0 {
        (field[..type_end].trim(), field[type_end..].trim())
    } else {
        (field.trim(), "field")
    };
    (FieldType::from_str(typ).expect(&format!("failed to parse type: {}", typ)), name.to_string())
}

pub fn parse_schema_fields(schema: &str) -> Vec<(FieldType, String)> {
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
                fields.push(parse_field(field.trim()));
                start = i + 1;
            }
            _ => {}
        }
    }
    // Last field
    if start < schema.len() {
        let field = &schema[start..];
        fields.push(parse_field(field.trim()));
    }
    substreams::log::info!("Parsed schema fields: {:?}", fields);
    fields
}

// Add a helper to convert FieldType to ParamType for ABI decoding
pub fn fieldtype_to_paramtype(ft: &FieldType) -> ParamType {
    match ft {
        FieldType::Primitive(p) => p.clone(),
        FieldType::Tuple(fields) => ParamType::Tuple(fields.iter().map(|(f, _)| fieldtype_to_paramtype(f)).collect()),
        FieldType::Array(inner) => ParamType::Array(Box::new(fieldtype_to_paramtype(inner))),
    }
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
        Token::Array(arr) | Token::FixedArray(arr) => Value::Array(arr.iter().map(token_to_json).collect()),
        Token::Tuple(tuple) => Value::Array(tuple.iter().map(token_to_json).collect()),
    }
}

pub fn token_to_json_with_schema(ft: &FieldType, token: &Token) -> Value {
    match (ft, token) {
        (FieldType::Primitive(_), t) => token_to_json(t),
        (FieldType::Tuple(fields), Token::Tuple(tokens)) => {
            let mut obj = serde_json::Map::new();
            for ((field, name), token) in fields.iter().zip(tokens.iter()) {
                obj.insert(name.clone(), token_to_json_with_schema(field, token));
            }
            Value::Object(obj)
        }
        (FieldType::Array(inner_ft), Token::Array(tokens)) => Value::Array(tokens.iter().map(|t| token_to_json_with_schema(inner_ft, t)).collect()),
        _ => Value::Null, // fallback for mismatches
    }
}
