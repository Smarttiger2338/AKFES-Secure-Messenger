use crate::error::AkfesError;

fn field(name: &str, value: &str, max: usize) -> Result<(), AkfesError> {
    if value.is_empty()
        || value.len() > max
        || !value.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        return Err(AkfesError::Crypto(format!("Invalid {name} for E2EE v4 AAD")));
    }
    Ok(())
}

/// Canonical E2EE v4 authenticated metadata encoding shared by native and web clients.
pub fn build_message_aad(
    conversation: &str,
    sender: &str,
    recipient: &str,
    logical: &str,
    session_id: &str,
    number: u32,
    kind: &str,
) -> Result<Vec<u8>, AkfesError> {
    field("conversationId", conversation, 64)?;
    field("senderDeviceId", sender, 64)?;
    field("recipientDeviceId", recipient, 64)?;
    field("logicalMessageId", logical, 64)?;
    field("ratchetSessionId", session_id, 64)?;
    field("messageType", kind, 32)?;
    Ok(format!(
        "AKFES-E2EE-v4|{conversation}|{sender}|{recipient}|{logical}|{session_id}|{number}|{kind}"
    ).into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Vector {
        conversation_id: String,
        sender_device_id: String,
        recipient_device_id: String,
        logical_message_id: String,
        ratchet_session_id: String,
        message_number: u32,
        message_type: String,
        expected_aad: String,
    }

    #[test]
    fn shared_web_native_aad_vectors_match() {
        let vectors: Vec<Vector> = serde_json::from_str(include_str!(
            "../../client/src/protocol-vectors.json"
        )).unwrap();
        for v in vectors {
            let actual = build_message_aad(
                &v.conversation_id,
                &v.sender_device_id,
                &v.recipient_device_id,
                &v.logical_message_id,
                &v.ratchet_session_id,
                v.message_number,
                &v.message_type,
            ).unwrap();
            assert_eq!(actual, v.expected_aad.as_bytes());
        }
    }

    #[test]
    fn delimiter_and_oversized_fields_are_rejected() {
        assert!(build_message_aad("bad|id", "s", "r", "l", "sid", 0, "text").is_err());
        assert!(build_message_aad("c", "s", "r", "l", "sid", 0, &"x".repeat(33)).is_err());
    }
}
