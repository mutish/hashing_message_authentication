from cryptography.fernet import Fernet
import hashlib
import base64


def _derive_valid_key(key: str) -> bytes:
    """Derive a valid Fernet key from any arbitrary user password/string."""
    return base64.urlsafe_b64encode(hashlib.sha256(key.encode('utf-8')).digest())


def decrypt_hash(encrypted_hash: str, key: str) -> str:
    """Decrypt the encrypted hash using the shared secret key."""
    if not encrypted_hash or not key:
        return ""

    try:
        valid_key = _derive_valid_key(key)
        fernet = Fernet(valid_key)
        decrypted_bytes = fernet.decrypt(encrypted_hash.encode('utf-8'))
        return decrypted_bytes.decode('utf-8')
    except Exception:
        return ""


def generate_hash(message: str) -> str:
    """Compute the hash of the message using SHA-256."""
    if not message:
        return ""
    return hashlib.sha256(message.encode('utf-8')).hexdigest()


def verify_payload(payload: dict, key: str) -> tuple:
    """
    Separates the payload, decrypts the hash, re-hashes the message, and compares.
    Returns a tuple of (is_authenticated, result_dict).
    """
    message = payload.get("message", "")
    encrypted_hash = payload.get("encrypted_hash", "")

    # Decrypt the received hash
    decrypted_hash = decrypt_hash(encrypted_hash, key)

    # Re-hash the received message
    recalculated_hash = generate_hash(message)

    # Compare the hashes
    is_authenticated = decrypted_hash == recalculated_hash and decrypted_hash != ""

    result = {
        "is_authentic": is_authenticated,
        "extracted_message": message,
        "decrypted_hash": decrypted_hash,
        "recalculated_hash": recalculated_hash
    }

    return is_authenticated, result