/// Omni Layer message payload parser
///
/// Parses deobfuscated Omni Layer payloads according to the official specification:
/// https://github.com/OmniLayer/spec/blob/master/OmniSpecification.adoc
use crate::types::omni::OmniMessageType;
use serde_json::{json, Value};
use std::io::{Cursor, Read};
use tracing::debug;

/// Parse an Omni Layer message payload into structured JSON
pub fn parse_omni_payload(message_type: &OmniMessageType, payload: &[u8]) -> Result<Value, String> {
    if payload.len() < 4 {
        return Err(format!("Payload too short: {} bytes", payload.len()));
    }

    let version = u16::from_be_bytes([payload[0], payload[1]]);
    let msg_type = u16::from_be_bytes([payload[2], payload[3]]);

    debug!(
        "Parsing Omni message: version={}, type={}",
        version, msg_type
    );

    let mut result = json!({
        "version": version,
        "message_type": msg_type,
        "message_type_name": format!("{:?}", message_type),
    });

    // Parse message-specific fields starting at offset 4
    match message_type {
        OmniMessageType::SimpleSend => {
            if let Ok(fields) = parse_simple_send(&payload[4..]) {
                result["fields"] = fields;
            }
        }
        OmniMessageType::SendToOwners => {
            if let Ok(fields) = parse_send_to_owners(&payload[4..]) {
                result["fields"] = fields;
            }
        }
        OmniMessageType::SendAll => {
            if let Ok(fields) = parse_send_all(&payload[4..]) {
                result["fields"] = fields;
            }
        }
        OmniMessageType::TradeOffer => {
            if let Ok(fields) = parse_trade_offer(&payload[4..]) {
                result["fields"] = fields;
            }
        }
        OmniMessageType::CreatePropertyFixed => {
            if let Ok(fields) = parse_create_property_fixed(&payload[4..]) {
                result["fields"] = fields;
            }
        }
        OmniMessageType::CreatePropertyVariable => {
            if let Ok(fields) = parse_create_property_variable(&payload[4..]) {
                result["fields"] = fields;
            }
        }
        OmniMessageType::CloseCrowdsale => {
            if let Ok(fields) = parse_close_crowdsale(&payload[4..]) {
                result["fields"] = fields;
            }
        }
        OmniMessageType::CreatePropertyManual => {
            if let Ok(fields) = parse_create_property_manual(&payload[4..]) {
                result["fields"] = fields;
            }
        }
        OmniMessageType::GrantPropertyTokens => {
            if let Ok(fields) = parse_grant_property_tokens(&payload[4..]) {
                result["fields"] = fields;
            }
        }
        _ => {
            // For unsupported types, just include the raw hex
            result["raw_payload_hex"] = json!(hex::encode(&payload[4..]));
        }
    }

    Ok(result)
}

/// Parse Simple Send (Type 0) message
/// Fields: Currency ID (4 bytes) + Amount (8 bytes)
fn parse_simple_send(data: &[u8]) -> Result<Value, String> {
    if data.len() < 12 {
        return Err(format!("Simple send data too short: {} bytes", data.len()));
    }

    let currency_id = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    let amount = i64::from_be_bytes([
        data[4], data[5], data[6], data[7], data[8], data[9], data[10], data[11],
    ]);

    Ok(json!({
        "property_id": currency_id,
        "amount": amount,
    }))
}

/// Parse Create Property - Fixed (Type 50) message
/// Fields: Ecosystem (1) + Property Type (2) + Previous Property ID (4) +
///         Category (string) + Subcategory (string) + Name (string) +
///         URL (string) + Data (string) + Number of Properties (8)
fn parse_create_property_fixed(data: &[u8]) -> Result<Value, String> {
    let mut cursor = Cursor::new(data);

    // Fixed fields first
    let ecosystem = read_u8(&mut cursor)?;
    let property_type = read_u16(&mut cursor)?;
    let previous_property_id = read_u32(&mut cursor)?;

    // Variable-length null-terminated strings
    let category = read_null_terminated_string(&mut cursor)?;
    let subcategory = read_null_terminated_string(&mut cursor)?;
    let name = read_null_terminated_string(&mut cursor)?;
    let url = read_null_terminated_string(&mut cursor)?;
    let data_field = read_null_terminated_string(&mut cursor)?;

    // Final fixed field: number of properties (8 bytes)
    let number_properties = read_u64(&mut cursor)?;

    Ok(json!({
        "ecosystem": ecosystem,
        "ecosystem_name": if ecosystem == 1 { "Main" } else { "Test" },
        "property_type": property_type,
        "property_type_name": if property_type == 1 { "Indivisible" } else { "Divisible" },
        "previous_property_id": previous_property_id,
        "category": category,
        "subcategory": subcategory,
        "name": name,
        "url": url,
        "data": data_field,
        "number_properties": number_properties,
    }))
}

/// Parse Create Property - Variable (Type 51) message
/// Similar to Type 50 but with different final field
fn parse_create_property_variable(data: &[u8]) -> Result<Value, String> {
    let mut cursor = Cursor::new(data);

    let ecosystem = read_u8(&mut cursor)?;
    let property_type = read_u16(&mut cursor)?;
    let previous_property_id = read_u32(&mut cursor)?;

    let category = read_null_terminated_string(&mut cursor)?;
    let subcategory = read_null_terminated_string(&mut cursor)?;
    let name = read_null_terminated_string(&mut cursor)?;
    let url = read_null_terminated_string(&mut cursor)?;
    let data_field = read_null_terminated_string(&mut cursor)?;

    let property_id_desired = read_u32(&mut cursor)?;

    Ok(json!({
        "ecosystem": ecosystem,
        "ecosystem_name": if ecosystem == 1 { "Main" } else { "Test" },
        "property_type": property_type,
        "property_type_name": if property_type == 1 { "Indivisible" } else { "Divisible" },
        "previous_property_id": previous_property_id,
        "category": category,
        "subcategory": subcategory,
        "name": name,
        "url": url,
        "data": data_field,
        "property_id_desired": property_id_desired,
    }))
}

/// Parse Send To Owners (Type 3) message
/// Fields: Currency ID (4 bytes) + Amount (8 bytes)
fn parse_send_to_owners(data: &[u8]) -> Result<Value, String> {
    if data.len() < 12 {
        return Err(format!(
            "Send to owners data too short: {} bytes",
            data.len()
        ));
    }

    let currency_id = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    let amount = i64::from_be_bytes([
        data[4], data[5], data[6], data[7], data[8], data[9], data[10], data[11],
    ]);

    Ok(json!({
        "property_id": currency_id,
        "amount": amount,
    }))
}

/// Parse Trade Offer (Type 20) message
/// Fields: Currency ID for sale (4) + Amount for sale (8) +
///         Amount desired (8) + Fee required (1)
fn parse_trade_offer(data: &[u8]) -> Result<Value, String> {
    if data.len() < 21 {
        return Err(format!("Trade offer data too short: {} bytes", data.len()));
    }

    let currency_id = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    let amount_for_sale = i64::from_be_bytes([
        data[4], data[5], data[6], data[7], data[8], data[9], data[10], data[11],
    ]);
    let amount_desired = i64::from_be_bytes([
        data[12], data[13], data[14], data[15], data[16], data[17], data[18], data[19],
    ]);
    let fee_required = data[20];

    Ok(json!({
        "property_id": currency_id,
        "amount_for_sale": amount_for_sale,
        "bitcoin_desired": amount_desired,
        "fee_required": fee_required,
    }))
}

/// Parse Send All (Type 4) message
/// Fields: Ecosystem (1 byte)
/// Source: CreatePayload_SendAll in omnicore/src/omnicore/createpayload.cpp
fn parse_send_all(data: &[u8]) -> Result<Value, String> {
    if data.is_empty() {
        return Err("Send all data is empty".to_string());
    }

    let ecosystem = data[0];

    Ok(json!({
        "ecosystem": ecosystem,
        "ecosystem_name": if ecosystem == 1 { "Main" } else { "Test" },
    }))
}

/// Parse Close Crowdsale (Type 53) message
/// Fields: Property ID (4 bytes)
/// Source: CreatePayload_CloseCrowdsale in omnicore/src/omnicore/createpayload.cpp
fn parse_close_crowdsale(data: &[u8]) -> Result<Value, String> {
    if data.len() < 4 {
        return Err(format!(
            "Close crowdsale data too short: {} bytes",
            data.len()
        ));
    }

    let property_id = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);

    Ok(json!({
        "property_id": property_id,
    }))
}

/// Parse Create Property - Manual (Type 54) message
/// Fields: Ecosystem (1) + Property Type (2) + Previous Property ID (4) +
///         Category (string) + Subcategory (string) + Name (string) +
///         URL (string) + Data (string)
/// Source: CreatePayload_IssuanceManaged in omnicore/src/omnicore/createpayload.cpp
fn parse_create_property_manual(data: &[u8]) -> Result<Value, String> {
    let mut cursor = Cursor::new(data);

    // Fixed fields first
    let ecosystem = read_u8(&mut cursor)?;
    let property_type = read_u16(&mut cursor)?;
    let previous_property_id = read_u32(&mut cursor)?;

    // Variable-length null-terminated strings
    let category = read_null_terminated_string(&mut cursor)?;
    let subcategory = read_null_terminated_string(&mut cursor)?;
    let name = read_null_terminated_string(&mut cursor)?;
    let url = read_null_terminated_string(&mut cursor)?;
    let data_field = read_null_terminated_string(&mut cursor)?;

    Ok(json!({
        "ecosystem": ecosystem,
        "ecosystem_name": if ecosystem == 1 { "Main" } else { "Test" },
        "property_type": property_type,
        "property_type_name": if property_type == 1 { "Indivisible" } else { "Divisible" },
        "previous_property_id": previous_property_id,
        "category": category,
        "subcategory": subcategory,
        "name": name,
        "url": url,
        "data": data_field,
    }))
}

/// Parse Grant Property Tokens (Type 55) message
/// Fields: Property ID (4) + Amount (8) + Info/Memo (null-terminated string)
/// Source: CreatePayload_Grant in omnicore/src/omnicore/createpayload.cpp
fn parse_grant_property_tokens(data: &[u8]) -> Result<Value, String> {
    if data.len() < 12 {
        return Err(format!(
            "Grant property tokens data too short: {} bytes",
            data.len()
        ));
    }

    let property_id = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    let amount = i64::from_be_bytes([
        data[4], data[5], data[6], data[7], data[8], data[9], data[10], data[11],
    ]);

    // Optional info/memo field (null-terminated string)
    let info = if data.len() > 12 {
        let mut cursor = Cursor::new(&data[12..]);
        read_null_terminated_string(&mut cursor).ok()
    } else {
        None
    };

    Ok(json!({
        "property_id": property_id,
        "amount": amount,
        "info": info,
    }))
}

// Helper functions for reading binary data

fn read_u8(cursor: &mut Cursor<&[u8]>) -> Result<u8, String> {
    let mut buf = [0u8; 1];
    cursor
        .read_exact(&mut buf)
        .map_err(|e| format!("Failed to read u8: {}", e))?;
    Ok(buf[0])
}

fn read_u16(cursor: &mut Cursor<&[u8]>) -> Result<u16, String> {
    let mut buf = [0u8; 2];
    cursor
        .read_exact(&mut buf)
        .map_err(|e| format!("Failed to read u16: {}", e))?;
    Ok(u16::from_be_bytes(buf))
}

fn read_u32(cursor: &mut Cursor<&[u8]>) -> Result<u32, String> {
    let mut buf = [0u8; 4];
    cursor
        .read_exact(&mut buf)
        .map_err(|e| format!("Failed to read u32: {}", e))?;
    Ok(u32::from_be_bytes(buf))
}

fn read_u64(cursor: &mut Cursor<&[u8]>) -> Result<u64, String> {
    let mut buf = [0u8; 8];
    cursor
        .read_exact(&mut buf)
        .map_err(|e| format!("Failed to read u64: {}", e))?;
    Ok(u64::from_be_bytes(buf))
}

fn read_null_terminated_string(cursor: &mut Cursor<&[u8]>) -> Result<String, String> {
    let mut bytes = Vec::new();
    let mut buf = [0u8; 1];

    while cursor.read_exact(&mut buf).is_ok() {
        if buf[0] == 0 {
            break;
        }
        bytes.push(buf[0]);
        if bytes.len() > 255 {
            return Err("String exceeds maximum length of 255 bytes".to_string());
        }
    }

    String::from_utf8(bytes).map_err(|e| format!("Invalid UTF-8 in string: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_send() {
        // Version 0, Type 0, Property ID 31 (USDT), Amount 1000000
        // Payload structure: version(2) + type(2) + property_id(4) + amount(8) = 16 bytes
        let payload = hex::decode("000000000000001f00000000000f4240").unwrap();
        let result = parse_omni_payload(&OmniMessageType::SimpleSend, &payload).unwrap();

        assert_eq!(result["version"], 0);
        assert_eq!(result["message_type"], 0);
        assert_eq!(result["fields"]["property_id"], 31);
        assert_eq!(result["fields"]["amount"], 1000000);
    }

    #[test]
    fn test_read_null_terminated_string() {
        let data = b"Hello\x00World\x00";
        let mut cursor = Cursor::new(&data[..]);

        let str1 = read_null_terminated_string(&mut cursor).unwrap();
        assert_eq!(str1, "Hello");

        let str2 = read_null_terminated_string(&mut cursor).unwrap();
        assert_eq!(str2, "World");
    }

    #[test]
    fn test_parse_send_all() {
        // Version 0, Type 4, Ecosystem 1 (Main)
        // Payload structure: version(2) + type(2) + ecosystem(1) = 5 bytes
        let payload = hex::decode("0000000401").unwrap();
        let result = parse_omni_payload(&OmniMessageType::SendAll, &payload).unwrap();

        assert_eq!(result["version"], 0);
        assert_eq!(result["message_type"], 4);
        assert_eq!(result["fields"]["ecosystem"], 1);
        assert_eq!(result["fields"]["ecosystem_name"], "Main");
    }

    #[test]
    fn test_parse_close_crowdsale() {
        // Version 0, Type 53, Property ID 31 (USDT)
        // Payload structure: version(2) + type(2) + property_id(4) = 8 bytes
        let payload = hex::decode("000000350000001f").unwrap();
        let result = parse_omni_payload(&OmniMessageType::CloseCrowdsale, &payload).unwrap();

        assert_eq!(result["version"], 0);
        assert_eq!(result["message_type"], 53);
        assert_eq!(result["fields"]["property_id"], 31);
    }

    #[test]
    fn test_parse_create_property_manual() {
        // Version 0, Type 54
        // Ecosystem 1, Property Type 1 (Indivisible), Previous Property ID 0
        // Category, Subcategory, Name, URL, Data (all null-terminated)
        let mut payload = vec![0x00, 0x00]; // version
        payload.extend_from_slice(&[0x00, 0x36]); // type 54
        payload.push(0x01); // ecosystem (Main)
        payload.extend_from_slice(&[0x00, 0x01]); // property type (Indivisible)
        payload.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // previous property id

        // Null-terminated strings
        payload.extend_from_slice(b"Test Category\x00");
        payload.extend_from_slice(b"Test Subcategory\x00");
        payload.extend_from_slice(b"Test Token\x00");
        payload.extend_from_slice(b"https://test.com\x00");
        payload.extend_from_slice(b"Test data\x00");

        let result = parse_omni_payload(&OmniMessageType::CreatePropertyManual, &payload).unwrap();

        assert_eq!(result["version"], 0);
        assert_eq!(result["message_type"], 54);
        assert_eq!(result["fields"]["ecosystem"], 1);
        assert_eq!(result["fields"]["ecosystem_name"], "Main");
        assert_eq!(result["fields"]["property_type"], 1);
        assert_eq!(result["fields"]["property_type_name"], "Indivisible");
        assert_eq!(result["fields"]["category"], "Test Category");
        assert_eq!(result["fields"]["subcategory"], "Test Subcategory");
        assert_eq!(result["fields"]["name"], "Test Token");
        assert_eq!(result["fields"]["url"], "https://test.com");
        assert_eq!(result["fields"]["data"], "Test data");
    }

    #[test]
    fn test_parse_grant_property_tokens() {
        // Version 0, Type 55, Property ID 31, Amount 100000
        // Payload structure: version(2) + type(2) + property_id(4) + amount(8) + info(null-term) = variable
        let mut payload = vec![0x00, 0x00]; // version
        payload.extend_from_slice(&[0x00, 0x37]); // type 55
        payload.extend_from_slice(&[0x00, 0x00, 0x00, 0x1f]); // property id 31
        payload.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x86, 0xa0]); // amount 100000
        payload.extend_from_slice(b"Grant tokens\x00"); // info

        let result = parse_omni_payload(&OmniMessageType::GrantPropertyTokens, &payload).unwrap();

        assert_eq!(result["version"], 0);
        assert_eq!(result["message_type"], 55);
        assert_eq!(result["fields"]["property_id"], 31);
        assert_eq!(result["fields"]["amount"], 100000);
        assert_eq!(result["fields"]["info"], "Grant tokens");
    }

    #[test]
    fn test_parse_grant_property_tokens_no_info() {
        // Test Grant without optional info field
        // Property ID 31, Amount 100
        let payload = hex::decode("000000370000001f0000000000000064").unwrap();
        let result = parse_omni_payload(&OmniMessageType::GrantPropertyTokens, &payload).unwrap();

        assert_eq!(result["version"], 0);
        assert_eq!(result["message_type"], 55);
        assert_eq!(result["fields"]["property_id"], 31);
        assert_eq!(result["fields"]["amount"], 100);
        assert!(result["fields"]["info"].is_null());
    }
}
