use sha2::{Digest, Sha256};

use crate::types::PublicKeyBytes;

/// Generate a human-readable Safety Number from two identity public keys.
/// Format example: "1837 5219 8321 7103 ..." (groups of 4 digits)
pub fn generate_safety_number(
    local_identity: &PublicKeyBytes,
    remote_identity: &PublicKeyBytes,
) -> String {
    // Canonical order: sort the two keys to make the number identical on both sides
    let (first, second) = if local_identity.0 < remote_identity.0 {
        (&local_identity.0, &remote_identity.0)
    } else {
        (&remote_identity.0, &local_identity.0)
    };

    let mut hasher = Sha256::new();
    hasher.update(first);
    hasher.update(second);
    let hash = hasher.finalize();

    // Take first 30 bytes → 60 hex chars → convert to decimal groups
    // Simple version: use first 15 bytes as 5 groups of 6-digit numbers (mod 10000 for 4 digits)
    let mut numbers = Vec::new();
    for chunk in hash.chunks(3).take(10) {
        let mut val: u32 = 0;
        for &b in chunk {
            val = (val << 8) | b as u32;
        }
        numbers.push(format!("{:04}", val % 10000));
    }

    numbers.join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safety_number_is_symmetric() {
        let a = PublicKeyBytes([1u8; 32]);
        let b = PublicKeyBytes([2u8; 32]);
        let n1 = generate_safety_number(&a, &b);
        let n2 = generate_safety_number(&b, &a);
        assert_eq!(n1, n2);
    }
}
