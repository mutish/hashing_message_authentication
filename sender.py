import hashlib
import os
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

NONCE_BYTES = 12

def _derive_key_from_password(password: str) -> bytes:
    """Derive a 256-bit AES key from a user-provided password using SHA-256."""
    return hashlib.sha256(password.encode('utf-8')).digest()

def generate_hash(message: str | bytes) -> bytes:
    """Compute SHA-256 hash of the message and return as raw bytes."""
    if isinstance(message, str):
        message = message.encode('utf-8')
    return hashlib.sha256(message).digest()

def encrypt_hash(message_digest: bytes, key: bytes) -> bytes:
    """Encrypt the hash using AES-256-GCM with a random nonce."""
    nonce = os.urandom(NONCE_BYTES)
    ciphertext = AESGCM(key).encrypt(nonce, message_digest, associated_data=None)
    # Return nonce + ciphertext (receiver will parse the same way)
    return nonce + ciphertext

def generate_secure_payload(message: str, key: str) -> dict:
    """Generate a message payload with encrypted hash for transmission.
    
    Args:
        message: Plaintext message to authenticate
        key: Shared secret key (string, will be derived to 256-bit key)
    
    Returns:
        dict with 'message' and 'encrypted_hash' (base64-encoded for transport)
    """
    if not message or not key:
        raise ValueError("Message and key cannot be empty")
    
    # Derive the encryption key from password
    derived_key = _derive_key_from_password(key)
    
    # Compute hash of the message
    msg_hash = generate_hash(message)
    
    # Encrypt the hash
    encrypted_hash_bytes = encrypt_hash(msg_hash, derived_key)
    
    # Encode to base64 for JSON transport
    encrypted_hash_b64 = base64.b64encode(encrypted_hash_bytes).decode('utf-8')
    
    return {
        "message": message,
        "encrypted_hash": encrypted_hash_b64
    }

# --- Example Usage (For demonstration and testing) ---
if __name__ == "__main__":
    print("--- Sender: AES-256-GCM Message Authentication Demo ---\n")
    
    test_message = "Transfer $10,000 to Account B"
    shared_secret = "super_secret_group_key_123"
    
    # Generate payload
    payload = generate_secure_payload(test_message, shared_secret)
    
    print(f"Original Message: {payload['message']}")
    print(f"Generated Hash (H(M)): {generate_hash(test_message).hex()}")
    print(f"Encrypted Hash (E(K, H(M))) [base64 for transport]:")
    print(f"  {payload['encrypted_hash']}\n")
    print(f"Final Payload (JSON):")
    import json
    print(json.dumps(payload, indent=2))
