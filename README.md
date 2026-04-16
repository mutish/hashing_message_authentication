# Hashing and Message Authentication
A message authentication scheme where the hash of the message is encrypted using a symmetric key, appended to the plaintext message, and sent to the receiver. The receiver then decrypts the hash, re-hashes the received message, and compares the two to verify authenticity.

## Project Structure
- `app.py`: Flask application and API routing (Copilot generated).
- `sender.py`: Handles hashing and encryption.
- `receiver.py`: Handles decryption and hash comparison.
- `templates/`: Contains `sender.html` and `receiver.html` for the frontend.

## Setup Instructions

1. **Clone the repository.**
2. **Create a virtual environment:**
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
4. **Run the application:**
   ```bash
   python3 app.py


import hashlib
import hmac
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

NONCE_BYTES = 12

def decrypt_hash(encrypted_hash: bytes, key: bytes) -> bytes:
    """Decrypt the received encrypted hash using AES-256-GCM."""
    min_length = NONCE_BYTES + 32 + 16  # nonce + SHA-256 digest + GCM tag
    if len(encrypted_hash) < min_length:
        raise ValueError("Encrypted blob too short. Data may be corrupted.")
    
    nonce = encrypted_hash[:NONCE_BYTES]
    ciphertext = encrypted_hash[NONCE_BYTES:]
    
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