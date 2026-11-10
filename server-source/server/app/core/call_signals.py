def call_signal_payload(
    call_id: str,
    conversation_id: str,
    event_type: str,
    sender_device_id: str,
    description_or_candidate: str,
    media: str = '',
) -> str:
    return f'{call_id}|{conversation_id}|{event_type}|{sender_device_id}|{description_or_candidate}|{media}'
