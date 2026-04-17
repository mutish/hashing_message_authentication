import hashlib
import hmac
import os
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

NONCE_BYTES = 12

def _derive_key_from_password(password: str) -> bytes:
    """Derive a 256-bit AES key from a user-provided password using SHA-256."""
    return hashlib.sha256(password.encode('utf-8')).digest()

def decrypt_hash(encrypted_hash_bytes: bytes, key: bytes) -> bytes:
    """Decrypt the received encrypted hash using AES-256-GCM."""
    min_length = NONCE_BYTES + 32 + 16  # nonce + SHA-256 digest + GCM tag
    if len(encrypted_hash_bytes) < min_length:
        raise ValueError("Encrypted blob too short. Data may be corrupted.")
    
    nonce = encrypted_hash_bytes[:NONCE_BYTES]
    ciphertext = encrypted_hash_bytes[NONCE_BYTES:]
    
    # AESGCM(key) will natively raise ValueError if the key length is invalid
    return AESGCM(key).decrypt(nonce, ciphertext, associated_data=None)


def verify_message(message: str | bytes, received_encrypted_hash: bytes, key: bytes) -> bool:
    """Verify the authenticity and integrity of a received message."""
    if isinstance(message, str):
        message = message.encode("utf-8")
    
    try:
        decrypted_hash = decrypt_hash(received_encrypted_hash, key)
        computed_hash = hashlib.sha256(message).digest()
        
        # Constant-time comparison prevents timing attacks
        return hmac.compare_digest(computed_hash, decrypted_hash)
    except Exception:
        # Catches InvalidTag (tampering), ValueError (length/key issues), etc.
        return False


def verify_payload(payload: dict, key: str) -> tuple[bool, str]:
    """Verify a received payload and return authentication result.
    
    Args:
        payload: dict with 'message' (str) and 'encrypted_hash' (base64-encoded)
        key: Shared secret key (string, will be derived to 256-bit key)
    
    Returns:
        tuple: (authenticated: bool, message: str)
    """
    if not payload or 'message' not in payload or 'encrypted_hash' not in payload:
        return False, "Invalid payload format"
    
    try:
        message = payload['message']
        encrypted_hash_b64 = payload['encrypted_hash']
        
        # Decode base64 back to bytes
        encrypted_hash_bytes = base64.b64decode(encrypted_hash_b64)
        
        # Derive the decryption key from password
        derived_key = _derive_key_from_password(key)
        
        # Verify the message
        is_authentic = verify_message(message, encrypted_hash_bytes, derived_key)
        
        return is_authentic, message
    except Exception as e:
        return False, f"Verification error: {str(e)}"


# ---------------------------------------------------------------------------
# Utility: sender-side helper & tests
# ---------------------------------------------------------------------------

def _sender_encrypt_hash(message: str | bytes, key: bytes) -> bytes:
    """Helper to simulate sender-side H(M) -> E(K, H(M))."""
    if isinstance(message, str):
        message = message.encode("utf-8")
    
    digest = hashlib.sha256(message).digest()
    nonce = os.urandom(NONCE_BYTES)
    return nonce + AESGCM(key).encrypt(nonce, digest, associated_data=None)



if __name__ == "__main__":
    print("--- receiver.py Message Verification Demo ---")
    
    key = AESGCM.generate_key(bit_length=256)
    msg = b"Transfer $500 to account 9876543210"
    enc_hash = _sender_encrypt_hash(msg, key)
    
    # Test 1 - Happy path
    print(f"1. Authentic message:   {verify_message(msg, enc_hash, key)}")
    
    # Test 2 - Tampered message
    print(f"2. Tampered message:    {verify_message(b'Transfer $5000 to account 9876543210', enc_hash, key)}")
    
    # Test 3 - Wrong key
    wrong_key = AESGCM.generate_key(bit_length=256)
    print(f"3. Wrong key:           {verify_message(msg, enc_hash, wrong_key)}")
    
    # Test 4 - Corrupted hash blob
    corrupted_hash = bytearray(enc_hash)
    corrupted_hash[15] ^= 0xFF
    print(f"4. Corrupted hash blob: {verify_message(msg, bytes(corrupted_hash), key)}")