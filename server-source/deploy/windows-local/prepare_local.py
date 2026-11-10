from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


root = Path("/run/akfes-local")
root.mkdir(parents=True, exist_ok=True)
private_path = root / "jwt-private.pem"
public_path = root / "jwt-public.pem"

if not private_path.exists() or not public_path.exists():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    private_path.write_bytes(
        private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    public_path.write_bytes(
        private_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    private_path.chmod(0o600)
    public_path.chmod(0o644)
