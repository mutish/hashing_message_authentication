import hashlib
import base64
from cryptography.fernet import Fernet


# Helper function ->This safely derives a valid symmetric key from any arbitrary user password/string.
def _derive_valid_key(key: str) -> bytes:
    
    return base64.urlsafe_b64encode(hashlib.sha256(key.encode('utf-8')).digest())

# Compute the hash of the message using SHA-256
def generate_hash(message: str) -> str:
    
    if not message:
        return ""
    
    # Encode message to bytes, hash it, and return the hexadecimal string
    return hashlib.sha256(message.encode('utf-8')).hexdigest()

# Encrypt the hash using the shared secret key
def encrypt_hash(hash_val: str, key: str) -> str:
  
    if not hash_val or not key:
        return ""

    # Derive a valid Fernet key from the provided secret
    valid_key = _derive_valid_key(key)
    fernet = Fernet(valid_key)
    
    # Encrypt the hash and return it as a string
    encrypted_bytes = fernet.encrypt(hash_val.encode('utf-8'))
    return encrypted_bytes.decode('utf-8')

# Construct the final payload to be sent to the receiver
def build_message_payload(message: str, key: str) -> dict:
   
    # Generate the hash
    msg_hash = generate_hash(message)
    
    # Encrypt the hash
    encrypted_hash = encrypt_hash(msg_hash, key)
    
    # Construct the final concatenated payload
    return {
        "message": message,
        "encrypted_hash": encrypted_hash
    }

# --- Example Usage (For demonstration and testing) ---
if __name__ == "__main__":
    # Sample message and shared secret key
    test_message = "Transfer $10,000 to Account B"
    shared_secret = "super_secret_group_key_123"

    # Build the payload
    payload = build_message_payload(test_message, shared_secret)

    # Display results for educational purposes
    print("--- Sender Core Logic Test ---")
    print(f"Original Message: {payload['message']}")
    print(f"Generated Hash (H(M)): {generate_hash(test_message)}")
    print(f"Encrypted Hash (E(K, H(M))): {payload['encrypted_hash']}")
    print(f"Final Payload: {payload}")
    print("--- End of Test ---")
