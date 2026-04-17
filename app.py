import os
import hashlib
import base64
from flask import Flask, request, jsonify, render_template
from sender import generate_secure_payload, generate_hash
from receiver import verify_payload

app = Flask(__name__)


@app.route('/')
def sender():
    return render_template('index.html')


@app.route('/receiver')
def receiver():
    """Redirect to main page (both sender and receiver on one page)"""
    return render_template('index.html')


@app.post('/api/send')
def send():
    """Generate a secure payload with encrypted hash.
    
    Expected JSON: {"message": str, "key": str}
    Returns: {"message": str, "encrypted_hash": str (base64), "message_hash": str (hex)}
    """
    data = request.get_json()
    if not data or 'message' not in data or 'key' not in data:
        return jsonify({'error': 'Missing required fields: message and key'}), 400
    
    try:
        # Generate secure payload (includes encrypted hash)
        payload = generate_secure_payload(data['message'], data['key'])
        
        # Also compute the hash in hex format for display
        msg_hash_hex = generate_hash(data['message']).hex()
        
        # Return response with all necessary data
        return jsonify({
            'message': payload['message'],
            'encrypted_hash': payload['encrypted_hash'],
            'message_hash': msg_hash_hex
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 400


@app.post('/api/hash')
def hash_message():
    """Compute SHA-256 hash of a message for display.
    
    Expected JSON: {"message": str}
    Returns: {"hash": str (hex)}
    """
    data = request.get_json()
    if not data or 'message' not in data:
        return jsonify({'error': 'Missing required field: message'}), 400
    
    try:
        msg_hash = generate_hash(data['message']).hex()
        return jsonify({'hash': msg_hash})
    except Exception as e:
        return jsonify({'error': str(e)}), 400


@app.post('/api/receive')
def receive():
    """Verify a received payload and return authentication result.
    
    Expected JSON: {"payload": {"message": str, "encrypted_hash": str}, "key": str}
    Returns: {"authenticated": bool, "message": str, "recalculated_hash": str, "decrypted_hash": str}
    """
    data = request.get_json()
    if not data or 'payload' not in data or 'key' not in data:
        return jsonify({'error': 'Missing required fields: payload and key'}), 400
    
    try:
        payload = data['payload']
        key = data['key']
        
        # Verify the payload
        authenticated, message = verify_payload(payload, key)
        
        # If authenticated, compute hashes for display
        recalculated_hash = generate_hash(message).hex()
        
        # Try to decrypt and show the decrypted hash (if available)
        decrypted_hash = ""
        if 'encrypted_hash' in payload:
            try:
                from receiver import decrypt_hash, _derive_key_from_password
                encrypted_bytes = base64.b64decode(payload['encrypted_hash'])
                derived_key = _derive_key_from_password(key)
                decrypted_hash_bytes = decrypt_hash(encrypted_bytes, derived_key)
                decrypted_hash = decrypted_hash_bytes.hex()
            except Exception:
                decrypted_hash = "Error decrypting"
        
        return jsonify({
            'authenticated': authenticated,
            'message': message,
            'recalculated_hash': recalculated_hash,
            'decrypted_hash': decrypted_hash
        })
    except Exception as e:
        return jsonify({'error': str(e), 'authenticated': False, 'message': ''}), 400


if __name__ == '__main__':
    app.run(debug=os.getenv('FLASK_DEBUG', 'False') == 'True')
